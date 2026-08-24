import {
  createCipheriv,
  createDecipheriv,
  createHash,
  randomBytes,
  randomUUID,
  timingSafeEqual
} from 'node:crypto';

import { Prisma, type PrismaClient } from '@prisma/client';
import type { FastifyRequest } from 'fastify';

import { AuthenticationError } from './auth.js';
import type { Authenticator, HumanSessionIdentity, Role } from './auth.js';

export type { HumanSessionIdentity } from './auth.js';

export const SESSION_COOKIE_NAME = '__Host-eg_session';
export const SESSION_TOKEN_PATTERN = /^[A-Za-z0-9_-]{43}$/;
export const SESSION_IDLE_TTL_MS = 30 * 60 * 1000;
export const SESSION_ABSOLUTE_TTL_MS = 12 * 60 * 60 * 1000;
export const SESSION_TOUCH_INTERVAL_MS = 5 * 60 * 1000;
export const SESSION_CREATION_LIMIT = 10;
export const SESSION_CREATION_WINDOW_MS = 15 * 60 * 1000;
export const CLEARED_SESSION_COOKIE = `${SESSION_COOKIE_NAME}=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0`;

const CSRF_PURPOSE = 'egogero-csrf-v1';
const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export type SessionRuntimeConfig = {
  currentCsrfKeyVersion: number;
  csrfKeys: ReadonlyMap<number, Buffer>;
};

export type IssuedBrowserSession = {
  sessionToken: string;
  csrfToken: string;
  identity: HumanSessionIdentity;
  absoluteExpiresAt: Date;
};

export type SessionRotationResult =
  | ({ status: 'rotated' } & IssuedBrowserSession)
  | { status: 'stale' | 'denied' };

export type SessionRevocationResult = 'revoked' | 'already-revoked' | 'unavailable';

export type SessionRequestContext = {
  requestCorrelationId: string;
  ipPrefix?: string | null;
  userAgent?: string | null;
};

export interface BrowserSessionStore {
  issueFromHandoff(input: SessionRequestContext & {
    handoffToken: string;
    oldSessionToken?: string;
  }): Promise<IssuedBrowserSession | null>;
  authenticate(sessionToken: string, requestCorrelationId: string): Promise<HumanSessionIdentity | null>;
  rotate(input: SessionRequestContext & {
    sessionToken: string;
    targetMembershipId?: string;
  }): Promise<SessionRotationResult>;
  revoke(input: SessionRequestContext & {
    sessionToken: string;
    reason?: string;
  }): Promise<SessionRevocationResult>;
  revokeAll(input: SessionRequestContext & { accountId: string }): Promise<number>;
  recordAmbiguousCredentials(input: SessionRequestContext): Promise<void>;
}

export interface BrowserSessionService {
  issueFromHandoff(input: Parameters<BrowserSessionStore['issueFromHandoff']>[0]): Promise<IssuedBrowserSession | null>;
  rotate(input: Parameters<BrowserSessionStore['rotate']>[0]): Promise<SessionRotationResult>;
  revoke(input: Parameters<BrowserSessionStore['revoke']>[0]): Promise<SessionRevocationResult>;
  revokeAll(input: Parameters<BrowserSessionStore['revokeAll']>[0]): Promise<number>;
  sessionCookie(sessionToken: string): string;
  clearSessionCookie(): string;
}

type MembershipRow = {
  id: string;
  accountId: string;
  role: Role;
  condominioId: string | null;
  residentId: string | null;
};

type SessionRow = MembershipRow & {
  sessionId: string;
  familyId: string;
  accountSessionVersion: number;
  currentSessionVersion: number;
  accountStatus: string;
  membershipStatus: string;
  condominiumDeletedAt: Date | null;
  residentDeletedAt: Date | null;
  residentCondominiumId: string | null;
  createdAt: Date;
  lastSeenAt: Date;
  idleExpiresAt: Date;
  absoluteExpiresAt: Date;
  authenticatedAt: Date;
  revokedAt: Date | null;
  csrfDigest: Buffer;
  csrfCiphertext: Buffer;
  csrfNonce: Buffer;
  csrfAuthTag: Buffer;
  csrfKeyVersion: number;
  ipPrefix: string | null;
  userAgentHash: Buffer | null;
  databaseNow: Date;
};

type AuditInput = {
  eventType: string;
  outcome: 'success' | 'failure' | 'denied';
  requestCorrelationId: string;
  reasonCode?: string;
  accountId?: string | null;
  externalIdentityId?: string | null;
  sessionId?: string | null;
  membershipId?: string | null;
  condominioId?: string | null;
  ipPrefix?: string | null;
  userAgentHash?: Buffer | null;
  metadata?: Record<string, boolean | number | string>;
};

function requireEnvironment(environment: NodeJS.ProcessEnv, name: string) {
  const value = environment[name];
  if (!value || value.trim() !== value) throw new Error(`${name} is required`);
  return value;
}

function parseCsrfKeys(environment: NodeJS.ProcessEnv) {
  let parsed: unknown;
  try {
    parsed = JSON.parse(requireEnvironment(environment, 'SESSION_CSRF_KEYS'));
  } catch (error) {
    if (error instanceof Error && error.message === 'SESSION_CSRF_KEYS is required') throw error;
    throw new Error('SESSION_CSRF_KEYS must be a JSON object of versioned base64url keys');
  }
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
    throw new Error('SESSION_CSRF_KEYS must be a JSON object of versioned base64url keys');
  }

  const keys = new Map<number, Buffer>();
  for (const [rawVersion, rawKey] of Object.entries(parsed)) {
    const version = Number(rawVersion);
    if (!Number.isSafeInteger(version) || version <= 0 || rawVersion !== String(version)
      || typeof rawKey !== 'string' || !/^[A-Za-z0-9_-]+$/.test(rawKey)) {
      throw new Error('SESSION_CSRF_KEYS contains an invalid version or key');
    }
    const key = Buffer.from(rawKey, 'base64url');
    if (key.length !== 32 || key.toString('base64url') !== rawKey || keys.has(version)) {
      throw new Error('SESSION_CSRF_KEYS contains an invalid version or key');
    }
    keys.set(version, key);
  }
  if (keys.size === 0) throw new Error('SESSION_CSRF_KEYS must contain at least one active key');
  return keys;
}

export function sessionConfigFromEnvironment(environment: NodeJS.ProcessEnv): SessionRuntimeConfig | undefined {
  if (environment.HUMAN_AUTH_ENABLED === undefined || environment.HUMAN_AUTH_ENABLED === 'false') return undefined;
  if (environment.HUMAN_AUTH_ENABLED !== 'true') throw new Error('HUMAN_AUTH_ENABLED must be true or false');

  const csrfKeys = parseCsrfKeys(environment);
  const rawCurrentVersion = requireEnvironment(environment, 'SESSION_CSRF_CURRENT_KEY_VERSION');
  const currentCsrfKeyVersion = Number(rawCurrentVersion);
  if (!Number.isSafeInteger(currentCsrfKeyVersion) || rawCurrentVersion !== String(currentCsrfKeyVersion)
    || !csrfKeys.has(currentCsrfKeyVersion)) {
    throw new Error('SESSION_CSRF_CURRENT_KEY_VERSION must identify an active key');
  }
  return { currentCsrfKeyVersion, csrfKeys };
}

export function generateSessionToken() {
  return randomBytes(32).toString('base64url');
}

export function hasBrowserSessionCookie(cookieHeader: string | readonly string[] | undefined) {
  const headers = typeof cookieHeader === 'string' ? [cookieHeader] : cookieHeader ?? [];
  return headers.some((header) => header.split(';').some((part) => part.trim().startsWith(`${SESSION_COOKIE_NAME}=`)));
}

export function parseBrowserSessionCookie(cookieHeader: string | readonly string[] | undefined) {
  const headers = typeof cookieHeader === 'string' ? [cookieHeader] : cookieHeader ?? [];
  const values: string[] = [];
  for (const header of headers) {
    for (const part of header.split(';')) {
      const separator = part.indexOf('=');
      if (separator < 0 || part.slice(0, separator).trim() !== SESSION_COOKIE_NAME) continue;
      values.push(part.slice(separator + 1).trim());
    }
  }
  return values.length === 1 && SESSION_TOKEN_PATTERN.test(values[0]!) ? values[0]! : null;
}

export function serializeBrowserSessionCookie(sessionToken: string) {
  if (!SESSION_TOKEN_PATTERN.test(sessionToken)) throw new Error('Invalid browser session token');
  return `${SESSION_COOKIE_NAME}=${sessionToken}; Path=/; HttpOnly; Secure; SameSite=Lax`;
}

function digest(value: string | Buffer) {
  return createHash('sha256').update(value).digest();
}

function userAgentDigest(value: string | null | undefined) {
  return value ? digest(Buffer.from(value, 'utf8')) : null;
}

function boundedCorrelationId(value: string) {
  if (!value) return 'missing-correlation-id';
  return value.length <= 128 ? value : digest(Buffer.from(value, 'utf8')).toString('hex');
}

// A length-prefixed encoding avoids ambiguous concatenation while binding all three required values exactly.
function csrfAad(sessionId: string, accountId: string) {
  const fields = [CSRF_PURPOSE, sessionId, accountId];
  return Buffer.concat(fields.flatMap((field) => {
    const bytes = Buffer.from(field, 'utf8');
    const length = Buffer.allocUnsafe(4);
    length.writeUInt32BE(bytes.length);
    return [length, bytes];
  }));
}

function encryptCsrf(config: SessionRuntimeConfig, sessionId: string, accountId: string, plaintext: Buffer) {
  const key = config.csrfKeys.get(config.currentCsrfKeyVersion);
  if (!key) throw new Error('Current session CSRF key is unavailable');
  const nonce = randomBytes(12);
  const cipher = createCipheriv('aes-256-gcm', key, nonce);
  cipher.setAAD(csrfAad(sessionId, accountId));
  return {
    ciphertext: Buffer.concat([cipher.update(plaintext), cipher.final()]),
    nonce,
    authTag: cipher.getAuthTag(),
    keyVersion: config.currentCsrfKeyVersion
  };
}

function decryptCsrf(config: SessionRuntimeConfig, session: SessionRow) {
  const key = config.csrfKeys.get(session.csrfKeyVersion);
  if (!key || session.csrfNonce.length !== 12 || session.csrfAuthTag.length !== 16 || session.csrfCiphertext.length !== 32) {
    return null;
  }
  let plaintext: Buffer | undefined;
  try {
    const decipher = createDecipheriv('aes-256-gcm', key, session.csrfNonce);
    decipher.setAAD(csrfAad(session.sessionId, session.accountId));
    decipher.setAuthTag(session.csrfAuthTag);
    plaintext = Buffer.concat([decipher.update(session.csrfCiphertext), decipher.final()]);
    const actualDigest = digest(plaintext);
    if (plaintext.length !== 32 || actualDigest.length !== session.csrfDigest.length
      || !timingSafeEqual(actualDigest, session.csrfDigest)) {
      plaintext.fill(0);
      return null;
    }
    return plaintext;
  } catch {
    plaintext?.fill(0);
    return null;
  }
}

function identityFor(sessionId: string, membership: MembershipRow): HumanSessionIdentity {
  if (membership.role === 'provedor') {
    return {
      principalType: 'human',
      authMethod: 'oidc-session',
      accountId: membership.accountId,
      sessionId,
      role: membership.role,
      id: membership.accountId,
      condominioIds: null
    };
  }
  return {
    principalType: 'human',
    authMethod: 'oidc-session',
    accountId: membership.accountId,
    sessionId,
    role: membership.role,
    id: membership.role === 'morador' ? membership.residentId! : membership.accountId,
    condominioIds: [membership.condominioId!]
  };
}

async function insertAudit(transaction: Prisma.TransactionClient, input: AuditInput) {
  const accountId = input.accountId ?? null;
  const actorType = accountId ? 'human' : 'anonymous';
  const actorId = accountId;
  const metadata = JSON.stringify(input.metadata ?? {});
  await transaction.$executeRaw`
    INSERT INTO "AuthenticationAuditEvent" (
      id, "eventType", outcome, "accountId", "externalIdentityId", "sessionId", "membershipId",
      "condominioId", "actorType", "actorId", "requestCorrelationId", "ipPrefix",
      "userAgentHash", "reasonCode", metadata
    ) VALUES (
      ${randomUUID()}::uuid, ${input.eventType}, ${input.outcome}::"AuthenticationOutcome",
      ${accountId}::uuid, ${input.externalIdentityId ?? null}::uuid, ${input.sessionId ?? null}::uuid,
      ${input.membershipId ?? null}::uuid, ${input.condominioId ?? null},
      ${actorType}::"AuthenticationActorType", ${actorId},
      ${boundedCorrelationId(input.requestCorrelationId)}, ${input.ipPrefix ?? null},
      ${input.userAgentHash ?? null}, ${input.reasonCode ?? null}, ${metadata}::jsonb
    )
  `;
}

function liveMembershipCondition(alias: string) {
  return Prisma.raw(`
    ${alias}.status = 'active'
    AND (
      (${alias}.role = 'provedor' AND ${alias}."condominioId" IS NULL AND ${alias}."residentId" IS NULL)
      OR (${alias}.role IN ('sindico', 'portaria') AND condominium.id IS NOT NULL AND condominium."deletedAt" IS NULL)
      OR (${alias}.role = 'morador' AND condominium.id IS NOT NULL AND condominium."deletedAt" IS NULL
        AND resident.id IS NOT NULL AND resident."deletedAt" IS NULL
        AND resident."condominioId" = ${alias}."condominioId")
    )
  `);
}

async function chooseMembership(transaction: Prisma.TransactionClient, accountId: string) {
  const rows = await transaction.$queryRaw<MembershipRow[]>(Prisma.sql`
    SELECT membership.id, membership."accountId", membership.role,
           membership."condominioId", membership."residentId"
    FROM "HumanMembership" membership
    LEFT JOIN "Condominio" condominium ON condominium.id = membership."condominioId"
    LEFT JOIN "Morador" resident ON resident.id = membership."residentId"
      AND resident."condominioId" = membership."condominioId"
    LEFT JOIN LATERAL (
      SELECT MAX(session."createdAt") AS "lastUsedAt"
      FROM "BrowserSession" session
      WHERE session."activeMembershipId" = membership.id
        AND session."accountId" = membership."accountId"
    ) usage ON true
    WHERE membership."accountId" = ${accountId}::uuid
      AND ${liveMembershipCondition('membership')}
    ORDER BY usage."lastUsedAt" DESC NULLS LAST, membership."createdAt" ASC, membership.id ASC
    LIMIT 1
    FOR SHARE OF membership
  `);
  return rows[0] ?? null;
}

async function loadTargetMembership(
  transaction: Prisma.TransactionClient,
  accountId: string,
  membershipId: string
) {
  const rows = await transaction.$queryRaw<MembershipRow[]>(Prisma.sql`
    SELECT membership.id, membership."accountId", membership.role,
           membership."condominioId", membership."residentId"
    FROM "HumanMembership" membership
    LEFT JOIN "Condominio" condominium ON condominium.id = membership."condominioId"
    LEFT JOIN "Morador" resident ON resident.id = membership."residentId"
      AND resident."condominioId" = membership."condominioId"
    WHERE membership.id = ${membershipId}::uuid
      AND membership."accountId" = ${accountId}::uuid
      AND ${liveMembershipCondition('membership')}
    FOR SHARE OF membership
  `);
  return rows[0] ?? null;
}

async function creationAllowed(transaction: Prisma.TransactionClient, accountId: string) {
  const rows = await transaction.$queryRaw<Array<{ allowed: boolean }>>(Prisma.sql`
    SELECT COUNT(*) < ${SESSION_CREATION_LIMIT} AS allowed
    FROM "BrowserSession"
    WHERE "accountId" = ${accountId}::uuid
      AND "createdAt" > clock_timestamp() - interval '15 minutes'
  `);
  return rows[0]?.allowed === true;
}

async function insertSession(
  transaction: Prisma.TransactionClient,
  config: SessionRuntimeConfig,
  input: {
    id: string;
    familyId: string;
    accountId: string;
    accountSessionVersion: number;
    membershipId: string;
    authenticatedAt: Date;
    absoluteExpiresAt?: Date;
    tokenDigest: Buffer;
    csrf: Buffer;
    ipPrefix: string | null;
    userAgentHash: Buffer | null;
  }
) {
  const encrypted = encryptCsrf(config, input.id, input.accountId, input.csrf);
  const rows = await transaction.$queryRaw<Array<{ createdAt: Date; absoluteExpiresAt: Date }>>(Prisma.sql`
    WITH db_clock AS MATERIALIZED (SELECT clock_timestamp() AS now)
    INSERT INTO "BrowserSession" (
      id, "familyId", "createdAt", "lastSeenAt", "idleExpiresAt", "absoluteExpiresAt",
      "authenticatedAt", "tokenDigest", "csrfDigest", "csrfCiphertext", "csrfNonce",
      "csrfAuthTag", "csrfKeyVersion", "accountId", "accountSessionVersion",
      "activeMembershipId", "ipPrefix", "userAgentHash"
    )
    SELECT ${input.id}::uuid, ${input.familyId}::uuid, now, now,
           LEAST(now + interval '30 minutes', COALESCE(${input.absoluteExpiresAt ?? null}::timestamptz, now + interval '12 hours')),
           COALESCE(${input.absoluteExpiresAt ?? null}::timestamptz, now + interval '12 hours'),
            LEAST(${input.authenticatedAt}, now), ${input.tokenDigest}, ${digest(input.csrf)},
           ${encrypted.ciphertext}, ${encrypted.nonce}, ${encrypted.authTag}, ${encrypted.keyVersion},
           ${input.accountId}::uuid, ${input.accountSessionVersion}, ${input.membershipId}::uuid,
           ${input.ipPrefix}, ${input.userAgentHash}
    FROM db_clock
    RETURNING "createdAt", "absoluteExpiresAt"
  `);
  return rows[0]!;
}

function validSessionToken(value: string) {
  return SESSION_TOKEN_PATTERN.test(value);
}

function sessionDenialReason(session: SessionRow) {
  const now = session.databaseNow.getTime();
  if (session.revokedAt) return 'session_revoked';
  if (session.absoluteExpiresAt.getTime() <= now) return 'session_absolute_expired';
  if (session.idleExpiresAt.getTime() <= now) return 'session_idle_expired';
  if (session.accountStatus !== 'active') return 'account_inactive';
  if (session.accountSessionVersion !== session.currentSessionVersion) return 'session_version_mismatch';
  if (session.membershipStatus !== 'active') return 'membership_inactive';
  if (session.role !== 'provedor' && session.condominiumDeletedAt !== null) return 'condominium_inactive';
  if (session.role === 'morador' && (
    session.residentDeletedAt !== null
    || session.residentCondominiumId !== session.condominioId
  )) return 'resident_inactive';
  return null;
}

async function loadSession(transaction: Prisma.TransactionClient, tokenDigest: Buffer, lock: boolean) {
  const lockSql = lock ? Prisma.raw('FOR UPDATE OF session') : Prisma.empty;
  const rows = await transaction.$queryRaw<SessionRow[]>(Prisma.sql`
    SELECT session.id AS "sessionId", session."familyId", session."accountId",
           session."accountSessionVersion", account."sessionVersion" AS "currentSessionVersion",
           account.status::text AS "accountStatus", membership.id,
           membership."accountId", membership.role, membership.status::text AS "membershipStatus",
           membership."condominioId", membership."residentId",
           condominium."deletedAt" AS "condominiumDeletedAt",
           resident."deletedAt" AS "residentDeletedAt",
           resident."condominioId" AS "residentCondominiumId",
           session."createdAt", session."lastSeenAt", session."idleExpiresAt",
           session."absoluteExpiresAt", session."authenticatedAt", session."revokedAt",
           session."csrfDigest", session."csrfCiphertext", session."csrfNonce",
           session."csrfAuthTag", session."csrfKeyVersion", session."ipPrefix",
           session."userAgentHash", clock_timestamp() AS "databaseNow"
    FROM "BrowserSession" session
    JOIN "HumanAccount" account ON account.id = session."accountId"
    JOIN "HumanMembership" membership ON membership.id = session."activeMembershipId"
      AND membership."accountId" = session."accountId"
    LEFT JOIN "Condominio" condominium ON condominium.id = membership."condominioId"
    LEFT JOIN "Morador" resident ON resident.id = membership."residentId"
      AND resident."condominioId" = membership."condominioId"
    WHERE session."tokenDigest" = ${tokenDigest}
    ${lockSql}
  `);
  return rows[0] ?? null;
}

export function createPrismaBrowserSessionStore(client: PrismaClient, config: SessionRuntimeConfig): BrowserSessionStore {
  async function auditDenied(
    transaction: Prisma.TransactionClient,
    request: SessionRequestContext,
    eventType: string,
    reasonCode: string,
    session?: SessionRow | null
  ) {
    await insertAudit(transaction, {
      eventType,
      outcome: 'denied',
      reasonCode,
      requestCorrelationId: request.requestCorrelationId,
      accountId: session?.accountId,
      sessionId: session?.sessionId,
      membershipId: session?.id,
      condominioId: session?.condominioId,
      ipPrefix: request.ipPrefix,
      userAgentHash: userAgentDigest(request.userAgent)
    });
  }

  async function createPersistedSession(
    transaction: Prisma.TransactionClient,
    input: Omit<Parameters<typeof insertSession>[2], 'tokenDigest'>,
    sessionToken: string
  ) {
    return insertSession(transaction, config, { ...input, tokenDigest: digest(sessionToken) });
  }

  return {
    async issueFromHandoff(input) {
      const request = input;
      if (!validSessionToken(input.handoffToken)
        || (input.oldSessionToken !== undefined && !validSessionToken(input.oldSessionToken))) {
        return client.$transaction(async (transaction) => {
          await auditDenied(transaction, request, 'session_issue_denied', 'invalid_handoff');
          return null;
        });
      }

      return client.$transaction(async (transaction) => {
        const handoffs = await transaction.$queryRaw<Array<{
          accountId: string;
          externalIdentityId: string;
          authenticatedAt: Date;
        }>>(Prisma.sql`
          UPDATE "OidcValidatedHandoff"
          SET "consumedAt" = clock_timestamp()
          WHERE "handleDigest" = ${digest(input.handoffToken)}
            AND "consumedAt" IS NULL
            AND "expiresAt" > clock_timestamp()
          RETURNING "accountId", "externalIdentityId", "authenticatedAt"
        `);
        const handoff = handoffs[0];
        if (!handoff) {
          await auditDenied(transaction, request, 'session_issue_denied', 'invalid_handoff');
          return null;
        }

        const accounts = await transaction.$queryRaw<Array<{
          id: string;
          sessionVersion: number;
          status: string;
          databaseNow: Date;
        }>>(Prisma.sql`
          SELECT id, "sessionVersion", status::text, clock_timestamp() AS "databaseNow"
          FROM "HumanAccount"
          WHERE id = ${handoff.accountId}::uuid
          FOR UPDATE
        `);
        const account = accounts[0];
        if (!account || account.status !== 'active') {
          await insertAudit(transaction, {
            eventType: 'session_issue_denied', outcome: 'denied', reasonCode: 'account_inactive',
            requestCorrelationId: input.requestCorrelationId, accountId: handoff.accountId,
            externalIdentityId: handoff.externalIdentityId, ipPrefix: input.ipPrefix,
            userAgentHash: userAgentDigest(input.userAgent)
          });
          return null;
        }
        const membership = await chooseMembership(transaction, account.id);
        if (!membership) {
          await insertAudit(transaction, {
            eventType: 'session_issue_denied', outcome: 'denied', reasonCode: 'no_active_membership',
            requestCorrelationId: input.requestCorrelationId, accountId: account.id,
            externalIdentityId: handoff.externalIdentityId, ipPrefix: input.ipPrefix,
            userAgentHash: userAgentDigest(input.userAgent)
          });
          return null;
        }
        if (!await creationAllowed(transaction, account.id)) {
          await insertAudit(transaction, {
            eventType: 'session_issue_denied', outcome: 'denied', reasonCode: 'session_creation_rate_limited',
            requestCorrelationId: input.requestCorrelationId, accountId: account.id,
            externalIdentityId: handoff.externalIdentityId, membershipId: membership.id,
            condominioId: membership.condominioId, ipPrefix: input.ipPrefix,
            userAgentHash: userAgentDigest(input.userAgent)
          });
          return null;
        }

        const sessionToken = generateSessionToken();
        const csrf = randomBytes(32);
        const sessionId = randomUUID();
        const stored = await createPersistedSession(transaction, {
          id: sessionId,
          familyId: randomUUID(),
          accountId: account.id,
          accountSessionVersion: account.sessionVersion,
          membershipId: membership.id,
          authenticatedAt: handoff.authenticatedAt,
          csrf,
          ipPrefix: input.ipPrefix ?? null,
          userAgentHash: userAgentDigest(input.userAgent)
        }, sessionToken);

        await insertAudit(transaction, {
          eventType: 'session_issued', outcome: 'success', requestCorrelationId: input.requestCorrelationId,
          accountId: account.id, externalIdentityId: handoff.externalIdentityId, sessionId,
          membershipId: membership.id, condominioId: membership.condominioId,
          ipPrefix: input.ipPrefix, userAgentHash: userAgentDigest(input.userAgent),
          metadata: { authenticationMethod: 'oidc' }
        });

        if (input.oldSessionToken) {
          const replaced = await transaction.$queryRaw<Array<{
            id: string;
            accountId: string;
            activeMembershipId: string;
            condominioId: string | null;
          }>>(Prisma.sql`
            UPDATE "BrowserSession" old_session
            SET "revokedAt" = clock_timestamp(), "revokeReason" = 'login_replaced'
            FROM "HumanMembership" membership
            WHERE old_session."tokenDigest" = ${digest(input.oldSessionToken)}
              AND old_session."revokedAt" IS NULL
              AND membership.id = old_session."activeMembershipId"
            RETURNING old_session.id, old_session."accountId", old_session."activeMembershipId", membership."condominioId"
          `);
          if (replaced[0]) {
            await insertAudit(transaction, {
              eventType: 'session_revoked', outcome: 'success', reasonCode: 'login_replaced',
              requestCorrelationId: input.requestCorrelationId, accountId: replaced[0].accountId,
              sessionId: replaced[0].id, membershipId: replaced[0].activeMembershipId,
              condominioId: replaced[0].condominioId, ipPrefix: input.ipPrefix,
              userAgentHash: userAgentDigest(input.userAgent)
            });
          }
        }

        const result = {
          sessionToken,
          csrfToken: csrf.toString('base64url'),
          identity: identityFor(sessionId, membership),
          absoluteExpiresAt: stored.absoluteExpiresAt
        };
        csrf.fill(0);
        return result;
      });
    },

    async authenticate(sessionToken, requestCorrelationId) {
      const request = { requestCorrelationId };
      if (!validSessionToken(sessionToken)) return null;
      return client.$transaction(async (transaction) => {
        const session = await loadSession(transaction, digest(sessionToken), false);
        if (!session) {
          await auditDenied(transaction, request, 'session_authentication_denied', 'invalid_session');
          return null;
        }
        const reason = sessionDenialReason(session);
        if (reason) {
          await auditDenied(transaction, request, 'session_authentication_denied', reason, session);
          return null;
        }
        if (session.lastSeenAt.getTime() <= session.databaseNow.getTime() - SESSION_TOUCH_INTERVAL_MS) {
          await transaction.$executeRaw`
            UPDATE "BrowserSession"
            SET "lastSeenAt" = clock_timestamp(),
                "idleExpiresAt" = LEAST(clock_timestamp() + interval '30 minutes', "absoluteExpiresAt")
            WHERE id = ${session.sessionId}::uuid
              AND "revokedAt" IS NULL
              AND "lastSeenAt" <= clock_timestamp() - interval '5 minutes'
              AND "idleExpiresAt" > clock_timestamp()
              AND "absoluteExpiresAt" > clock_timestamp()
          `;
        }
        return identityFor(session.sessionId, session);
      });
    },

    async rotate(input) {
      if (!validSessionToken(input.sessionToken)) return { status: 'denied' };
      return client.$transaction(async (transaction): Promise<SessionRotationResult> => {
        const tokenDigest = digest(input.sessionToken);
        const candidate = await loadSession(transaction, tokenDigest, false);
        if (candidate) {
          await transaction.$queryRaw(Prisma.sql`
            SELECT id FROM "HumanAccount" WHERE id = ${candidate.accountId}::uuid FOR UPDATE
          `);
        }
        const session = await loadSession(transaction, tokenDigest, true);
        if (!session) {
          await auditDenied(transaction, input, 'session_rotation_denied', 'invalid_session');
          return { status: 'denied' };
        }
        if (input.targetMembershipId && !UUID_PATTERN.test(input.targetMembershipId)) {
          await auditDenied(transaction, input, 'session_rotation_denied', 'target_membership_invalid', session);
          return { status: 'denied' };
        }
        if (session.revokedAt) {
          await auditDenied(transaction, input, 'session_rotation_denied', 'stale_session', session);
          return { status: 'stale' };
        }
        const reason = sessionDenialReason(session);
        if (reason) {
          await auditDenied(transaction, input, 'session_rotation_denied', reason, session);
          return { status: 'denied' };
        }
        const membership = input.targetMembershipId
          ? await loadTargetMembership(transaction, session.accountId, input.targetMembershipId)
          : await loadTargetMembership(transaction, session.accountId, session.id);
        if (!membership) {
          await auditDenied(transaction, input, 'session_rotation_denied', 'target_membership_inactive', session);
          return { status: 'denied' };
        }
        if (!await creationAllowed(transaction, session.accountId)) {
          await auditDenied(transaction, input, 'session_rotation_denied', 'session_creation_rate_limited', session);
          return { status: 'denied' };
        }
        const csrf = decryptCsrf(config, session);
        if (!csrf) {
          await auditDenied(transaction, input, 'session_rotation_denied', 'csrf_integrity_failed', session);
          return { status: 'denied' };
        }

        const revoked = await transaction.$executeRaw`
          UPDATE "BrowserSession"
          SET "revokedAt" = clock_timestamp(), "revokeReason" = 'rotated'
          WHERE id = ${session.sessionId}::uuid AND "revokedAt" IS NULL
        `;
        if (revoked !== 1) {
          csrf.fill(0);
          await auditDenied(transaction, input, 'session_rotation_denied', 'stale_session', session);
          return { status: 'stale' };
        }

        const sessionToken = generateSessionToken();
        const sessionId = randomUUID();
        const stored = await createPersistedSession(transaction, {
          id: sessionId,
          familyId: session.familyId,
          accountId: session.accountId,
          accountSessionVersion: session.accountSessionVersion,
          membershipId: membership.id,
          authenticatedAt: session.authenticatedAt,
          absoluteExpiresAt: session.absoluteExpiresAt,
          csrf,
          ipPrefix: input.ipPrefix ?? session.ipPrefix,
          userAgentHash: input.userAgent === undefined ? session.userAgentHash : userAgentDigest(input.userAgent)
        }, sessionToken);
        await insertAudit(transaction, {
          eventType: 'session_rotated', outcome: 'success', requestCorrelationId: input.requestCorrelationId,
          accountId: session.accountId, sessionId, membershipId: membership.id,
          condominioId: membership.condominioId, ipPrefix: input.ipPrefix ?? session.ipPrefix,
          userAgentHash: input.userAgent === undefined ? session.userAgentHash : userAgentDigest(input.userAgent),
          metadata: { membershipChanged: membership.id !== session.id }
        });
        const result: SessionRotationResult = {
          status: 'rotated', sessionToken, csrfToken: csrf.toString('base64url'),
          identity: identityFor(sessionId, membership), absoluteExpiresAt: stored.absoluteExpiresAt
        };
        csrf.fill(0);
        return result;
      });
    },

    async revoke(input) {
      if (!validSessionToken(input.sessionToken)) return 'unavailable';
      return client.$transaction(async (transaction): Promise<SessionRevocationResult> => {
        const session = await loadSession(transaction, digest(input.sessionToken), true);
        if (!session) {
          await auditDenied(transaction, input, 'session_revocation_denied', 'invalid_session');
          return 'unavailable';
        }
        if (session.revokedAt) return 'already-revoked';
        const reason = input.reason && /^[a-z][a-z0-9_]{0,99}$/.test(input.reason)
          ? input.reason
          : 'user_logout';
        await transaction.$executeRaw`
          UPDATE "BrowserSession"
          SET "revokedAt" = clock_timestamp(), "revokeReason" = ${reason}
          WHERE id = ${session.sessionId}::uuid AND "revokedAt" IS NULL
        `;
        await insertAudit(transaction, {
          eventType: 'session_revoked', outcome: 'success', reasonCode: reason,
          requestCorrelationId: input.requestCorrelationId, accountId: session.accountId,
          sessionId: session.sessionId, membershipId: session.id,
          condominioId: session.condominioId, ipPrefix: input.ipPrefix,
          userAgentHash: userAgentDigest(input.userAgent)
        });
        return 'revoked';
      });
    },

    async revokeAll(input) {
      return client.$transaction(async (transaction) => {
        if (!UUID_PATTERN.test(input.accountId)) {
          await auditDenied(transaction, input, 'session_revoke_all_denied', 'account_not_found');
          return 0;
        }
        const accounts = await transaction.$queryRaw<Array<{ id: string }>>(Prisma.sql`
          UPDATE "HumanAccount"
          SET "sessionVersion" = "sessionVersion" + 1, "updatedAt" = clock_timestamp()
          WHERE id = ${input.accountId}::uuid
          RETURNING id
        `);
        if (!accounts[0]) {
          await auditDenied(transaction, input, 'session_revoke_all_denied', 'account_not_found');
          return 0;
        }
        const revoked = await transaction.$executeRaw`
          UPDATE "BrowserSession"
          SET "revokedAt" = clock_timestamp(), "revokeReason" = 'all_sessions_revoked'
          WHERE "accountId" = ${input.accountId}::uuid AND "revokedAt" IS NULL
        `;
        await insertAudit(transaction, {
          eventType: 'session_revoke_all', outcome: 'success', reasonCode: 'all_sessions_revoked',
          requestCorrelationId: input.requestCorrelationId, accountId: input.accountId,
          ipPrefix: input.ipPrefix, userAgentHash: userAgentDigest(input.userAgent),
          metadata: { revokedSessions: revoked }
        });
        return revoked;
      });
    },

    async recordAmbiguousCredentials(input) {
      await client.$transaction((transaction) => insertAudit(transaction, {
        eventType: 'ambiguous_credentials',
        outcome: 'denied',
        reasonCode: 'ambiguous_credentials',
        requestCorrelationId: input.requestCorrelationId,
        ipPrefix: input.ipPrefix,
        userAgentHash: userAgentDigest(input.userAgent)
      }));
    }
  };
}

export function createBrowserSessionService(store: BrowserSessionStore): BrowserSessionService {
  return {
    issueFromHandoff: (input) => store.issueFromHandoff(input),
    rotate: (input) => store.rotate(input),
    revoke: (input) => store.revoke(input),
    revokeAll: (input) => store.revokeAll(input),
    sessionCookie: serializeBrowserSessionCookie,
    clearSessionCookie: () => CLEARED_SESSION_COOKIE
  };
}

export function createBrowserSessionAuthenticator(store: BrowserSessionStore): Authenticator {
  return {
    async authenticate(request: FastifyRequest) {
      const token = parseBrowserSessionCookie(request.headers.cookie);
      if (!token) {
        if (!hasBrowserSessionCookie(request.headers.cookie)) return null;
        throw new AuthenticationError(401, 'authentication_required', {
          'cache-control': 'no-store',
          'set-cookie': CLEARED_SESSION_COOKIE
        });
      }
      const identity = await store.authenticate(token, request.id);
      if (!identity) {
        throw new AuthenticationError(401, 'authentication_required', {
          'cache-control': 'no-store',
          'set-cookie': CLEARED_SESSION_COOKIE
        });
      }
      if (!['GET', 'HEAD', 'OPTIONS'].includes(request.method)) {
        throw new AuthenticationError(403, 'csrf_required', { 'cache-control': 'no-store' });
      }
      return identity;
    }
  };
}

export function createCredentialRouter(
  store: BrowserSessionStore,
  deviceAuthenticator: Authenticator,
  developmentAuthenticator?: Authenticator
): Authenticator {
  const browserAuthenticator = createBrowserSessionAuthenticator(store);
  return {
    async authenticate(request) {
      const hasSession = hasBrowserSessionCookie(request.headers.cookie);
      const hasDeviceBearer = typeof request.headers.authorization === 'string'
        && /^Bearer egdev_/.test(request.headers.authorization);
      if (hasSession && hasDeviceBearer) {
        await store.recordAmbiguousCredentials({
          requestCorrelationId: request.id,
          userAgent: typeof request.headers['user-agent'] === 'string' ? request.headers['user-agent'] : null
        });
        throw new AuthenticationError(400, 'ambiguous_credentials', { 'cache-control': 'no-store' });
      }
      if (hasSession) return browserAuthenticator.authenticate(request);
      if (hasDeviceBearer) return deviceAuthenticator.authenticate(request);
      const deviceIdentity = await deviceAuthenticator.authenticate(request);
      return deviceIdentity ?? await developmentAuthenticator?.authenticate(request) ?? null;
    }
  };
}
