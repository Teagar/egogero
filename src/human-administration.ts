import { createHash, createHmac, randomBytes, randomUUID, timingSafeEqual } from 'node:crypto';

import { Prisma, type PrismaClient } from '@prisma/client';
import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';

import { isUuid, type AuthenticatedIdentity, type Authenticator, type Role } from './auth.js';

const INVITATION_TTL_MS = 24 * 60 * 60 * 1000;
const WEBHOOK_CLOCK_SKEW_MS = 5 * 60 * 1000;
const EMAIL_PATTERN = /^[^\s@]+@[^\s@]+$/;

export type AuthenticationEvidence = { amr: readonly string[]; acr: string | null };
export type RoleMfaPolicy = Readonly<Record<Role, { amr: readonly string[]; acr: readonly string[] }>>;

export type HumanAdministrationConfig = {
  publicApplicationOrigin: string;
  recoveryUrl: string;
  recoveryWebhookIssuers: ReadonlySet<string>;
  recoveryWebhookSecret: Buffer;
  mfaPolicy: RoleMfaPolicy;
};

type AuditInput = {
  eventType: string;
  outcome: 'success' | 'failure' | 'denied';
  requestCorrelationId: string;
  accountId?: string | null;
  membershipId?: string | null;
  condominioId?: string | null;
  actorId?: string | null;
  actorType?: 'human' | 'system' | 'anonymous';
  reasonCode?: string;
  metadata?: Record<string, boolean | number | string>;
};

export function normalizeProvisioningEmail(value: string) {
  const normalized = value.normalize('NFKC').trim().toLowerCase();
  return normalized.length <= 320 && EMAIL_PATTERN.test(normalized) ? normalized : null;
}

export function digestSecret(value: string | Buffer) {
  return createHash('sha256').update(value).digest();
}

function exactHttpsUrl(value: string, name: string) {
  let url: URL;
  try { url = new URL(value); } catch { throw new Error(`${name} must be an exact HTTPS URL`); }
  if (url.protocol !== 'https:' || url.username || url.password || url.hash || !url.hostname) {
    throw new Error(`${name} must be an exact HTTPS URL`);
  }
  return url.toString();
}

export function exactOidcIssuer(value: string, name = 'OIDC issuer') {
  let url: URL;
  try { url = new URL(value); } catch { throw new Error(`${name} must be an exact HTTPS URL`); }
  if (url.protocol !== 'https:' || url.username || url.password || url.search || url.hash || !url.hostname) {
    throw new Error(`${name} must be an exact HTTPS URL`);
  }
  return value;
}

function required(environment: NodeJS.ProcessEnv, name: string) {
  const value = environment[name];
  if (!value || value.trim() !== value) throw new Error(`${name} is required`);
  return value;
}

function parseMfaPolicy(value: string): RoleMfaPolicy {
  let parsed: unknown;
  try { parsed = JSON.parse(value); } catch { throw new Error('HUMAN_MFA_ROLE_POLICY must be valid JSON'); }
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
    throw new Error('HUMAN_MFA_ROLE_POLICY must define every role');
  }
  const roles = ['provedor', 'sindico', 'morador', 'portaria'] as const;
  if (Object.keys(parsed).length !== roles.length || Object.keys(parsed).some((role) => !roles.includes(role as Role))) {
    throw new Error('HUMAN_MFA_ROLE_POLICY must define exactly every role');
  }
  const result = {} as Record<Role, { amr: string[]; acr: string[] }>;
  for (const role of roles) {
    const entry = (parsed as Record<string, unknown>)[role];
    if (!entry || typeof entry !== 'object' || Array.isArray(entry)) {
      throw new Error('HUMAN_MFA_ROLE_POLICY must define every role');
    }
    const amr = (entry as Record<string, unknown>).amr;
    const acr = (entry as Record<string, unknown>).acr;
    if (!Array.isArray(amr) || amr.length === 0 || amr.length > 16
      || !amr.every((item) => typeof item === 'string' && item.length > 0 && item.length <= 100)
      || !Array.isArray(acr) || acr.length > 16
      || !acr.every((item) => typeof item === 'string' && item.length > 0 && item.length <= 255)) {
      throw new Error('HUMAN_MFA_ROLE_POLICY entries require non-empty amr and valid acr arrays');
    }
    const phishingResistant = new Set(['webauthn', 'fido', 'fido2', 'hwk']);
    const residentAllowed = new Set([...phishingResistant, 'otp', 'totp']);
    const allowed = role === 'morador' ? residentAllowed : phishingResistant;
    if (!amr.every((method) => allowed.has(method.toLowerCase()))) {
      throw new Error('HUMAN_MFA_ROLE_POLICY permits an unsafe method for the role');
    }
    result[role] = { amr: [...new Set(amr)], acr: [...new Set(acr)] };
  }
  return result;
}

export function humanAdministrationConfigFromEnvironment(
  environment: NodeJS.ProcessEnv
): HumanAdministrationConfig | undefined {
  if (environment.HUMAN_AUTH_ENABLED !== 'true') return undefined;
  const origin = exactHttpsUrl(required(environment, 'PUBLIC_APPLICATION_ORIGIN'), 'PUBLIC_APPLICATION_ORIGIN');
  if (new URL(origin).pathname !== '/' || new URL(origin).search) {
    throw new Error('PUBLIC_APPLICATION_ORIGIN must be an exact HTTPS origin');
  }
  const recoveryUrl = exactHttpsUrl(required(environment, 'OIDC_RECOVERY_URL'), 'OIDC_RECOVERY_URL');
  const issuers = required(environment, 'RECOVERY_WEBHOOK_ISSUERS').split(',').map((issuer) =>
    exactOidcIssuer(issuer.trim(), 'RECOVERY_WEBHOOK_ISSUERS')
  );
  if (issuers.length === 0 || new Set(issuers).size !== issuers.length) {
    throw new Error('RECOVERY_WEBHOOK_ISSUERS must be a unique exact issuer allowlist');
  }
  const rawSecret = required(environment, 'RECOVERY_WEBHOOK_SECRET');
  const recoveryWebhookSecret = Buffer.from(rawSecret, 'utf8');
  if (recoveryWebhookSecret.length < 32 || new Set(rawSecret).size < 12
    || /(change[-_ ]?me|placeholder|example|secret){2,}/i.test(rawSecret)) {
    throw new Error('RECOVERY_WEBHOOK_SECRET must be at least 32 bytes and have adequate entropy');
  }
  return {
    publicApplicationOrigin: new URL(origin).origin,
    recoveryUrl,
    recoveryWebhookIssuers: new Set(issuers),
    recoveryWebhookSecret,
    mfaPolicy: parseMfaPolicy(required(environment, 'HUMAN_MFA_ROLE_POLICY'))
  };
}

export function evidenceSatisfiesRole(policy: RoleMfaPolicy, role: Role, evidence: AuthenticationEvidence) {
  const requirement = policy[role];
  if (!requirement || evidence.amr.length === 0) return false;
  const normalized = new Set(evidence.amr.map((method) => method.toLowerCase()));
  const methodAccepted = requirement.amr.some((method) => normalized.has(method.toLowerCase()));
  const contextAccepted = requirement.acr.length === 0
    || (evidence.acr !== null && requirement.acr.includes(evidence.acr));
  return methodAccepted && contextAccepted;
}

export function verifyRecoveryWebhookSignature(
  config: Pick<HumanAdministrationConfig, 'recoveryWebhookIssuers' | 'recoveryWebhookSecret'>,
  input: { eventId: string; issuer: string; subject: string; timestamp: number; signature: string },
  now = Date.now()
) {
  const canonical = canonicalRecoveryWebhookEvent(input);
  const supplied = /^[a-f0-9]{64}$/i.test(input.signature) ? Buffer.from(input.signature, 'hex') : Buffer.alloc(0);
  const expected = createHmac('sha256', config.recoveryWebhookSecret).update(canonical).digest();
  const valid = supplied.length === expected.length && timingSafeEqual(supplied, expected)
    && Number.isSafeInteger(input.timestamp) && Math.abs(now - input.timestamp * 1000) <= WEBHOOK_CLOCK_SKEW_MS
    && input.eventId.length > 0 && input.eventId.length <= 255 && input.subject.length > 0 && input.subject.length <= 255
    && config.recoveryWebhookIssuers.has(input.issuer);
  expected.fill(0);
  supplied.fill(0);
  return valid;
}

function canonicalRecoveryWebhookEvent(input: { timestamp: number; eventId: string; issuer: string; subject: string }) {
  return `${input.timestamp}.${input.eventId}.${input.issuer}.${input.subject}`;
}

async function insertAudit(transaction: Prisma.TransactionClient, input: AuditInput) {
  const correlation = input.requestCorrelationId.length <= 128
    ? input.requestCorrelationId
    : digestSecret(input.requestCorrelationId).toString('hex');
  const actorType = input.actorType ?? (input.actorId ? 'human' : 'anonymous');
  await transaction.$executeRaw`
    INSERT INTO "AuthenticationAuditEvent" (
      id, "eventType", outcome, "accountId", "membershipId", "condominioId", "actorType",
      "actorId", "requestCorrelationId", "reasonCode", metadata
    ) VALUES (
      ${randomUUID()}::uuid, ${input.eventType}, ${input.outcome}::"AuthenticationOutcome",
      ${input.accountId ?? null}::uuid, ${input.membershipId ?? null}::uuid,
      ${input.condominioId ?? null}, ${actorType}::"AuthenticationActorType",
      ${input.actorId ?? null}, ${correlation}, ${input.reasonCode ?? null},
      ${JSON.stringify(input.metadata ?? {})}::jsonb
    )
  `;
}

type MembershipInput = {
  role: Role;
  condominioId: string | null;
  residentId: string | null;
};

function actorCanManage(actor: AuthenticatedIdentity, target: MembershipInput) {
  if (actor.principalType !== 'human') return false;
  if (actor.role === 'provedor' && actor.condominioIds === null) return true;
  return actor.role === 'sindico' && target.role !== 'provedor' && target.condominioId !== null
    && actor.condominioIds.includes(target.condominioId);
}

function validScope(input: MembershipInput) {
  return input.role === 'provedor'
    ? input.condominioId === null && input.residentId === null
    : input.role === 'morador'
      ? isUuid(input.condominioId) && isUuid(input.residentId)
      : isUuid(input.condominioId) && input.residentId === null;
}

export function createHumanAdministrationService(client: PrismaClient, config: HumanAdministrationConfig) {
  return {
    mfaPolicy: config.mfaPolicy,
    recoveryUrl: config.recoveryUrl,

    async createInvitation(input: MembershipInput & {
      email: string;
      displayName: string;
      actor: AuthenticatedIdentity;
      requestCorrelationId: string;
    }) {
      const expectedEmail = normalizeProvisioningEmail(input.email);
      const displayName = input.displayName.trim();
      if (!expectedEmail || displayName.length < 1 || displayName.length > 200
        || !validScope(input) || !actorCanManage(input.actor, input)) return null;
      const token = randomBytes(32).toString('base64url');
      const accountId = randomUUID();
      const membershipId = randomUUID();
      const invitationId = randomUUID();
      await client.$transaction(async (transaction) => {
        if (input.condominioId) {
          const live = await transaction.$queryRaw<Array<{ id: string }>>(Prisma.sql`
            SELECT condominium.id FROM "Condominio" condominium
            ${input.residentId ? Prisma.sql`JOIN "Morador" resident ON resident.id = ${input.residentId}
              AND resident."condominioId" = condominium.id AND resident."deletedAt" IS NULL` : Prisma.empty}
            WHERE condominium.id = ${input.condominioId} AND condominium."deletedAt" IS NULL
            FOR SHARE OF condominium
          `);
          if (!live[0]) throw new Error('invalid_scope');
        }
        await transaction.humanAccount.create({ data: { id: accountId, displayName, status: 'invited' } });
        await transaction.humanMembership.create({ data: {
          id: membershipId, accountId, role: input.role, condominioId: input.condominioId,
          residentId: input.residentId, status: 'invited'
        } });
        await transaction.humanProvisioningInvitation.create({ data: {
          id: invitationId, accountId, membershipId, expectedEmail,
          tokenDigest: digestSecret(token), expiresAt: new Date(Date.now() + INVITATION_TTL_MS),
          createdByAccountId: 'accountId' in input.actor ? input.actor.accountId : input.actor.id
        } });
        await insertAudit(transaction, {
          eventType: 'account_invitation_created', outcome: 'success', accountId, membershipId,
          condominioId: input.condominioId, actorId: input.actor.id,
          requestCorrelationId: input.requestCorrelationId
        });
      });
      return { id: invitationId, accountId, membershipId, token, expiresAt: new Date(Date.now() + INVITATION_TTL_MS) };
    },

    async listMemberships(actor: AuthenticatedIdentity, condominioId?: string) {
      const globallyScoped = actor.principalType === 'human' && actor.role === 'provedor' && actor.condominioIds === null;
      if (!globallyScoped && (actor.principalType !== 'human' || actor.role !== 'sindico')) return null;
      const scope = globallyScoped ? condominioId : actor.condominioIds[0];
      if (scope !== undefined && !isUuid(scope)) return null;
      return client.humanMembership.findMany({
        where: scope ? { condominioId: scope } : undefined,
        select: { id: true, accountId: true, role: true, condominioId: true, residentId: true, status: true, createdAt: true, disabledAt: true },
        orderBy: [{ createdAt: 'asc' }, { id: 'asc' }]
      });
    },

    async createMembership(input: MembershipInput & { accountId: string; actor: AuthenticatedIdentity; requestCorrelationId: string }) {
      if (!isUuid(input.accountId) || !validScope(input) || !actorCanManage(input.actor, input)) return null;
      return client.$transaction(async (transaction) => {
        const account = await transaction.humanAccount.findFirst({ where: { id: input.accountId, status: { not: 'disabled' } } });
        if (!account) return null;
        const membership = await transaction.humanMembership.create({ data: {
          accountId: input.accountId, role: input.role, condominioId: input.condominioId,
          residentId: input.residentId, status: 'active'
        } });
        await insertAudit(transaction, { eventType: 'membership_created', outcome: 'success',
          accountId: input.accountId, membershipId: membership.id, condominioId: input.condominioId,
          actorId: input.actor.id, requestCorrelationId: input.requestCorrelationId });
        return membership;
      });
    },

    async disableMembership(id: string, actor: AuthenticatedIdentity, requestCorrelationId: string) {
      if (!isUuid(id)) return false;
      return client.$transaction(async (transaction) => {
        const rows = await transaction.$queryRaw<Array<{ id: string; accountId: string; role: Role; condominioId: string | null; residentId: string | null }>>(Prisma.sql`
          SELECT id, "accountId", role, "condominioId", "residentId" FROM "HumanMembership"
          WHERE id = ${id}::uuid FOR UPDATE
        `);
        const membership = rows[0];
        if (!membership || !actorCanManage(actor, membership)) return false;
        await transaction.$executeRaw`UPDATE "HumanMembership" SET status = 'disabled', "disabledAt" = COALESCE("disabledAt", clock_timestamp()) WHERE id = ${id}::uuid`;
        const revoked = await transaction.$executeRaw`UPDATE "BrowserSession" SET "revokedAt" = clock_timestamp(), "revokeReason" = 'membership_disabled' WHERE "activeMembershipId" = ${id}::uuid AND "revokedAt" IS NULL`;
        await insertAudit(transaction, { eventType: 'membership_disabled', outcome: 'success', accountId: membership.accountId,
          membershipId: id, condominioId: membership.condominioId, actorId: actor.id, requestCorrelationId,
          metadata: { revokedSessions: revoked } });
        return true;
      });
    },

    async setAccountStatus(accountId: string, status: 'suspended' | 'disabled', actor: AuthenticatedIdentity, requestCorrelationId: string) {
      if (!isUuid(accountId) || actor.principalType !== 'human' || actor.role !== 'provedor' || actor.condominioIds !== null) return false;
      return client.$transaction(async (transaction) => {
        const updated = await transaction.$executeRaw`
          UPDATE "HumanAccount" SET status = ${status}::"HumanAccountStatus",
            "disabledAt" = CASE WHEN ${status} = 'disabled' THEN COALESCE("disabledAt", clock_timestamp()) ELSE NULL END,
            "sessionVersion" = "sessionVersion" + 1, "updatedAt" = clock_timestamp()
          WHERE id = ${accountId}::uuid AND status <> 'disabled'
        `;
        if (updated !== 1) return false;
        if (status === 'disabled') await transaction.$executeRaw`UPDATE "HumanMembership" SET status = 'disabled', "disabledAt" = COALESCE("disabledAt", clock_timestamp()) WHERE "accountId" = ${accountId}::uuid AND status <> 'disabled'`;
        const revoked = await transaction.$executeRaw`UPDATE "BrowserSession" SET "revokedAt" = clock_timestamp(), "revokeReason" = ${`account_${status}`} WHERE "accountId" = ${accountId}::uuid AND "revokedAt" IS NULL`;
        await insertAudit(transaction, { eventType: `account_${status}`, outcome: 'success', accountId,
          actorId: actor.id, requestCorrelationId, metadata: { revokedSessions: revoked } });
        return true;
      });
    },

    async processRecoveryWebhook(input: { eventId: string; issuer: string; subject: string; timestamp: number; signature: string; requestCorrelationId: string }) {
      const valid = verifyRecoveryWebhookSignature(config, input);
      if (!valid) {
        await client.$transaction((transaction) => insertAudit(transaction, { eventType: 'recovery_webhook_denied', outcome: 'denied',
          actorType: 'anonymous', requestCorrelationId: input.requestCorrelationId, reasonCode: 'invalid_webhook' }));
        return false;
      }
      return client.$transaction(async (transaction) => {
        const eventDigest = digestSecret(canonicalRecoveryWebhookEvent(input));
        const inserted = await transaction.$queryRaw<Array<{ id: string }>>(Prisma.sql`
          INSERT INTO "RecoveryWebhookEvent" (id, "eventId", "eventDigest", issuer, subject, "processedAt")
          VALUES (${randomUUID()}::uuid, ${input.eventId}, ${eventDigest}, ${input.issuer}, ${input.subject}, clock_timestamp())
          ON CONFLICT (issuer, "eventId") DO NOTHING RETURNING id
        `);
        if (!inserted[0]) return true;
        const identities = await transaction.$queryRaw<Array<{ accountId: string }>>(Prisma.sql`
          SELECT "accountId" FROM "ExternalIdentity" WHERE issuer = ${input.issuer} AND subject = ${input.subject} FOR UPDATE
        `);
        const accountId = identities[0]?.accountId;
        if (accountId) {
          await transaction.$executeRaw`UPDATE "HumanAccount" SET "sessionVersion" = "sessionVersion" + 1, "updatedAt" = clock_timestamp() WHERE id = ${accountId}::uuid`;
          await transaction.$executeRaw`UPDATE "BrowserSession" SET "revokedAt" = clock_timestamp(), "revokeReason" = 'provider_recovery_event' WHERE "accountId" = ${accountId}::uuid AND "revokedAt" IS NULL`;
          await transaction.$executeRaw`UPDATE "RecoveryWebhookEvent" SET "accountId" = ${accountId}::uuid WHERE id = ${inserted[0].id}::uuid`;
        }
        await insertAudit(transaction, { eventType: 'recovery_webhook_processed', outcome: 'success', accountId,
          actorType: 'system', requestCorrelationId: input.requestCorrelationId, metadata: { identityMatched: Boolean(accountId) } });
        return true;
      }, { timeout: 5_000 });
    }
  };
}

export type HumanAdministrationService = ReturnType<typeof createHumanAdministrationService>;

function bodyObject(request: FastifyRequest) {
  return request.body && typeof request.body === 'object' && !Array.isArray(request.body)
    ? request.body as Record<string, unknown> : null;
}

async function authenticated(authenticator: Authenticator, request: FastifyRequest, reply: FastifyReply) {
  const identity = await authenticator.authenticate(request);
  if (!identity) reply.status(401).send({ error: 'authentication_required' });
  return identity;
}

export function registerHumanAdministrationRoutes(app: FastifyInstance, authenticator: Authenticator, service?: HumanAdministrationService) {
  if (!service) return;
  app.post('/admin/human/invitations', async (request, reply) => {
    const actor = await authenticated(authenticator, request, reply); if (!actor) return;
    const body = bodyObject(request); if (!body) return reply.status(400).send({ error: 'invalid_request' });
    try {
      const result = await service.createInvitation({ email: String(body.email ?? ''), displayName: String(body.displayName ?? ''),
        role: body.role as Role, condominioId: typeof body.condominioId === 'string' ? body.condominioId : null,
        residentId: typeof body.residentId === 'string' ? body.residentId : null, actor, requestCorrelationId: request.id });
      return result ? reply.status(201).send(result) : reply.status(403).send({ error: 'forbidden' });
    } catch { return reply.status(400).send({ error: 'invalid_request' }); }
  });
  app.get('/admin/human/memberships', async (request, reply) => {
    const actor = await authenticated(authenticator, request, reply); if (!actor) return;
    const query = request.query as Record<string, unknown>;
    const result = await service.listMemberships(actor, typeof query?.condominioId === 'string' ? query.condominioId : undefined);
    return result ? reply.send(result) : reply.status(403).send({ error: 'forbidden' });
  });
  app.post('/admin/human/memberships', async (request, reply) => {
    const actor = await authenticated(authenticator, request, reply); if (!actor) return;
    const body = bodyObject(request); if (!body) return reply.status(400).send({ error: 'invalid_request' });
    try {
      const result = await service.createMembership({ accountId: String(body.accountId ?? ''), role: body.role as Role,
        condominioId: typeof body.condominioId === 'string' ? body.condominioId : null,
        residentId: typeof body.residentId === 'string' ? body.residentId : null, actor, requestCorrelationId: request.id });
      return result ? reply.status(201).send(result) : reply.status(403).send({ error: 'forbidden' });
    } catch { return reply.status(400).send({ error: 'invalid_request' }); }
  });
  app.delete('/admin/human/memberships/:id', async (request, reply) => {
    const actor = await authenticated(authenticator, request, reply); if (!actor) return;
    return await service.disableMembership(String((request.params as Record<string, unknown>).id ?? ''), actor, request.id)
      ? reply.status(204).send() : reply.status(404).send({ error: 'not_found' });
  });
  for (const status of ['suspended', 'disabled'] as const) {
    app.post(`/admin/human/accounts/:id/${status}`, async (request, reply) => {
      const actor = await authenticated(authenticator, request, reply); if (!actor) return;
      return await service.setAccountStatus(String((request.params as Record<string, unknown>).id ?? ''), status, actor, request.id)
        ? reply.status(204).send() : reply.status(404).send({ error: 'not_found' });
    });
  }
  app.post('/auth/recovery/webhook', async (request, reply) => {
    const body = bodyObject(request) ?? {};
    await service.processRecoveryWebhook({ eventId: String(body.eventId ?? ''), issuer: String(body.issuer ?? ''),
      subject: String(body.subject ?? ''), timestamp: Number(request.headers['x-recovery-timestamp']),
      signature: typeof request.headers['x-recovery-signature'] === 'string' ? request.headers['x-recovery-signature'] : '',
      requestCorrelationId: request.id });
    return reply.status(202).send({ accepted: true });
  });
}
