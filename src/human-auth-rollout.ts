import { createHash } from 'node:crypto';

import { Prisma, type PrismaClient } from '@prisma/client';
import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';

import { isUuid, type AuthenticatedIdentity, type Authenticator } from './auth.js';

export const HUMAN_AUTH_COHORT_ALGORITHM = 'sha256-tenant-v1';
export const HUMAN_AUTH_COHORT_PERCENTAGES = [10, 50, 100] as const;
export const HUMAN_AUTH_ROLLOUT_STATES = ['disabled', 'internal-provider', 'pilot', 'enabled'] as const;

export type HumanAuthRolloutState = (typeof HUMAN_AUTH_ROLLOUT_STATES)[number];
type StoredState = 'disabled' | 'internal_provider' | 'pilot' | 'enabled';
type PolicyRow = {
  scope: string;
  condominioId: string | null;
  state: StoredState;
  cohortPercentage: number | null;
  cohortAlgorithm: string | null;
  version: number;
  updatedAt: Date;
};

export type HumanAuthGateDecision = { allowed: boolean; reason: string; policyVersion?: number };

function storedState(state: HumanAuthRolloutState): StoredState {
  return state === 'internal-provider' ? 'internal_provider' : state;
}

function publicState(state: StoredState): HumanAuthRolloutState {
  return state === 'internal_provider' ? 'internal-provider' : state;
}

export function humanAuthTenantCohort(condominioId: string) {
  const digest = createHash('sha256')
    .update(`${HUMAN_AUTH_COHORT_ALGORITHM}\0${condominioId}`, 'utf8')
    .digest();
  return digest.readUInt32BE(0) % 100 + 1;
}

function policyAllows(policy: PolicyRow | undefined, tenantId: string | null, provider: boolean): HumanAuthGateDecision {
  if (!policy) return { allowed: false, reason: 'policy_missing' };
  if (policy.state === 'disabled') return { allowed: false, reason: 'rollout_disabled', policyVersion: policy.version };
  if (policy.state === 'internal_provider') {
    return { allowed: provider, reason: provider ? 'internal_provider' : 'rollout_disabled', policyVersion: policy.version };
  }
  if (provider) return { allowed: true, reason: 'provider_scope', policyVersion: policy.version };
  if (policy.state === 'enabled') return { allowed: true, reason: 'enabled', policyVersion: policy.version };
  if (!tenantId || policy.cohortAlgorithm !== HUMAN_AUTH_COHORT_ALGORITHM
    || !HUMAN_AUTH_COHORT_PERCENTAGES.includes(policy.cohortPercentage as 10 | 50 | 100)) {
    return { allowed: false, reason: 'policy_inconsistent', policyVersion: policy.version };
  }
  const allowed = humanAuthTenantCohort(tenantId) <= policy.cohortPercentage!;
  return { allowed, reason: allowed ? 'pilot_cohort' : 'outside_pilot_cohort', policyVersion: policy.version };
}

function effectiveDecision(
  policies: ReadonlyMap<string, PolicyRow>,
  tenantId: string | null,
  provider: boolean
) {
  const global = policies.get('global');
  const globalDecision = policyAllows(global, tenantId, provider);
  if (!globalDecision.allowed || provider || global?.state === 'internal_provider') return globalDecision;
  if (!tenantId) return { allowed: false, reason: 'tenant_context_required', policyVersion: global?.version };
  return policyAllows(policies.get(`tenant:${tenantId}`), tenantId, false);
}

async function lockedPolicies(transaction: Prisma.TransactionClient, tenantId: string | null) {
  const scopes = tenantId ? ['global', `tenant:${tenantId}`] : ['global'];
  return transaction.$queryRaw<PolicyRow[]>(Prisma.sql`
    SELECT scope, "condominioId", state::text, "cohortPercentage", "cohortAlgorithm", version, "updatedAt"
    FROM "HumanAuthRolloutPolicy"
    WHERE scope IN (${Prisma.join(scopes)})
    ORDER BY scope
    FOR SHARE
  `);
}

async function evaluate(
  transaction: Prisma.TransactionClient,
  tenantId: string | null,
  provider: boolean
): Promise<HumanAuthGateDecision> {
  const policies = await lockedPolicies(transaction, tenantId);
  return effectiveDecision(new Map(policies.map((policy) => [policy.scope, policy])), tenantId, provider);
}

export interface HumanAuthRolloutGate {
  preflightGlobal(): Promise<HumanAuthGateDecision>;
  preflightInvitation(tokenDigest: Buffer): Promise<HumanAuthGateDecision>;
  gateScope(transaction: Prisma.TransactionClient, tenantId: string | null, provider: boolean): Promise<HumanAuthGateDecision>;
  gateIdentity(transaction: Prisma.TransactionClient, accountId: string): Promise<HumanAuthGateDecision>;
  gateMembership(transaction: Prisma.TransactionClient, membershipId: string, accountId: string): Promise<HumanAuthGateDecision>;
}

export const TEST_ONLY_ALLOW_ALL_HUMAN_AUTH_ROLLOUT: HumanAuthRolloutGate = Object.freeze({
  async preflightGlobal() { return { allowed: true, reason: 'test_only_bypass' }; },
  async preflightInvitation() { return { allowed: true, reason: 'test_only_bypass' }; },
  async gateScope() { return { allowed: true, reason: 'test_only_bypass' }; },
  async gateIdentity() { return { allowed: true, reason: 'test_only_bypass' }; },
  async gateMembership() { return { allowed: true, reason: 'test_only_bypass' }; }
});

export function createHumanAuthRolloutService(client: PrismaClient) {
  const gate: HumanAuthRolloutGate = {
    async preflightGlobal() {
      return client.$transaction(async (transaction) => {
        const policies = await lockedPolicies(transaction, null);
        const policy = policies[0];
        if (!policy) return { allowed: false, reason: 'policy_missing' };
        if (policy.state === 'disabled') return { allowed: false, reason: 'rollout_disabled', policyVersion: policy.version };
        return { allowed: true, reason: 'identity_pending', policyVersion: policy.version };
      });
    },
    gateScope: evaluate,
    async preflightInvitation(tokenDigest) {
      return client.$transaction(async (transaction) => {
        const rows = await transaction.$queryRaw<Array<{ condominioId: string | null; role: string }>>(Prisma.sql`
          SELECT membership."condominioId", membership.role::text
          FROM "HumanProvisioningInvitation" invitation
          JOIN "HumanMembership" membership ON membership.id = invitation."membershipId"
            AND membership."accountId" = invitation."accountId"
          WHERE invitation."tokenDigest" = ${tokenDigest}
            AND invitation."consumedAt" IS NULL AND invitation."disabledAt" IS NULL
            AND invitation."expiresAt" > clock_timestamp()
          FOR SHARE OF invitation, membership
        `);
        const target = rows[0];
        if (!target) return { allowed: false, reason: 'invitation_unavailable' };
        return evaluate(transaction, target.condominioId, target.role === 'provedor');
      });
    },
    async gateIdentity(transaction, accountId) {
      const memberships = await transaction.$queryRaw<Array<{ id: string; condominioId: string | null; role: string }>>(Prisma.sql`
        SELECT id, "condominioId", role::text FROM "HumanMembership"
        WHERE "accountId" = ${accountId}::uuid AND status = 'active'
        ORDER BY CASE WHEN role = 'provedor' THEN 0 ELSE 1 END, "createdAt", id
        FOR SHARE
      `);
      for (const membership of memberships) {
        const decision = await evaluate(transaction, membership.condominioId, membership.role === 'provedor');
        if (decision.allowed) return decision;
      }
      return { allowed: false, reason: memberships.length ? 'rollout_disabled' : 'no_active_membership' };
    },
    async gateMembership(transaction, membershipId, accountId) {
      const rows = await transaction.$queryRaw<Array<{ condominioId: string | null; role: string }>>(Prisma.sql`
        SELECT "condominioId", role::text FROM "HumanMembership"
        WHERE id = ${membershipId}::uuid AND "accountId" = ${accountId}::uuid AND status = 'active'
        FOR SHARE
      `);
      const membership = rows[0];
      return membership
        ? evaluate(transaction, membership.condominioId, membership.role === 'provedor')
        : { allowed: false, reason: 'membership_inactive' };
    }
  };

  return {
    ...gate,
    async verifyGlobalPolicy() {
      const rows = await client.$queryRaw<Array<{ valid: boolean }>>`
        SELECT scope = 'global' AND "condominioId" IS NULL AND version > 0
          AND "updatedAt" <= clock_timestamp()
          AND ("updatedByAccountId" IS NULL OR EXISTS (
            SELECT 1 FROM "HumanAccount" account WHERE account.id = "updatedByAccountId"
          ))
          AND ((state = 'pilot' AND "cohortPercentage" IN (10, 50, 100)
            AND "cohortAlgorithm" = ${HUMAN_AUTH_COHORT_ALGORITHM})
            OR (state <> 'pilot' AND "cohortPercentage" IS NULL AND "cohortAlgorithm" IS NULL)) AS valid
        FROM "HumanAuthRolloutPolicy" WHERE scope = 'global'
      `;
      if (rows.length !== 1 || !rows[0]?.valid) throw new Error('Human authentication rollout policy is unavailable');
    },
    async getPolicies() {
      const rows = await client.$queryRaw<PolicyRow[]>`
        SELECT scope, "condominioId", state::text, "cohortPercentage", "cohortAlgorithm", version, "updatedAt"
        FROM "HumanAuthRolloutPolicy" ORDER BY scope
      `;
      return rows.map((row) => ({ ...row, state: publicState(row.state) }));
    },
    async setPolicy(input: {
      condominioId: string | null;
      state: HumanAuthRolloutState;
      cohortPercentage: number | null;
      actorAccountId: string;
      requestCorrelationId: string;
      authorization: { kind: 'browser'; sessionId: string } | { kind: 'deployment'; token: string };
    }) {
      const scope = input.condominioId ? `tenant:${input.condominioId}` : 'global';
      const state = storedState(input.state);
      return client.$transaction(async (transaction) => {
        // Global-first ordering also prevents global and tenant rollbacks from deadlocking on sessions.
        await transaction.$executeRaw`SELECT pg_advisory_xact_lock(hashtextextended('global', 170030))`;
        if (scope !== 'global') {
          // Serializes first creation because a row lock cannot lock a missing tenant policy.
          await transaction.$executeRaw`SELECT pg_advisory_xact_lock(hashtextextended(${scope}, 170030))`;
        }
        const browserSessionId = input.authorization.kind === 'browser' ? input.authorization.sessionId : null;
        const deploymentTokenDigest = input.authorization.kind === 'deployment'
          ? createHash('sha256').update(input.authorization.token, 'utf8').digest() : null;
        const rows = await transaction.$queryRaw<Array<{ result_scope: string; result_state: StoredState;
          resultCohortPercentage: number | null; result_version: number; resultRevokedSessions: number }>>(Prisma.sql`
          SELECT * FROM set_human_auth_rollout_policy(
            ${scope}, ${state}::"HumanAuthRolloutState", ${input.cohortPercentage}::integer,
            ${input.actorAccountId}::uuid, ${input.requestCorrelationId},
            ${browserSessionId}::uuid, ${deploymentTokenDigest}::bytea
          )
        `);
        const result = rows[0];
        return result ? { scope: result.result_scope, state: publicState(result.result_state),
          cohortPercentage: result.resultCohortPercentage, version: result.result_version,
          revokedSessions: result.resultRevokedSessions } : null;
      }, {
        // Rollback may update a large active-session set; queue briefly, then allow one bounded atomic scan/update.
        maxWait: 5_000,
        timeout: 30_000
      });
    }
  };
}

export type HumanAuthRolloutService = ReturnType<typeof createHumanAuthRolloutService>;

function providerActor(identity: AuthenticatedIdentity | null): identity is AuthenticatedIdentity & { accountId: string; sessionId: string } {
  return Boolean(identity && identity.principalType === 'human' && identity.authMethod === 'oidc-session'
    && identity.role === 'provedor' && identity.condominioIds === null);
}

async function authenticateProvider(authenticator: Authenticator, request: FastifyRequest, reply: FastifyReply) {
  const identity = await authenticator.authenticate(request);
  if (!identity) reply.status(401).send({ error: 'authentication_required' });
  else if (!providerActor(identity)) reply.status(403).send({ error: 'forbidden' });
  return providerActor(identity) ? identity : null;
}

export function registerHumanAuthRolloutRoutes(
  app: FastifyInstance,
  authenticator: Authenticator,
  service?: HumanAuthRolloutService
) {
  if (!service) return;
  app.get('/admin/human-auth/rollout', async (request, reply) => {
    if (!await authenticateProvider(authenticator, request, reply)) return;
    return service.getPolicies();
  });
  app.put('/admin/human-auth/rollout', async (request, reply) => {
    const actor = await authenticateProvider(authenticator, request, reply);
    if (!actor) return;
    const body = request.body && typeof request.body === 'object' && !Array.isArray(request.body)
      ? request.body as Record<string, unknown> : null;
    if (!body || Object.keys(body).some((key) => !['condominioId', 'state', 'cohortPercentage'].includes(key))) {
      return reply.status(400).send({ error: 'invalid_request' });
    }
    const condominioId = body.condominioId === null ? null : body.condominioId;
    const state = body.state;
    const cohortPercentage = body.cohortPercentage === undefined ? null : body.cohortPercentage;
    if ((condominioId !== null && !isUuid(condominioId))
      || typeof state !== 'string' || !HUMAN_AUTH_ROLLOUT_STATES.includes(state as HumanAuthRolloutState)
      || (condominioId !== null && state === 'internal-provider')
      || (state === 'pilot'
        ? !HUMAN_AUTH_COHORT_PERCENTAGES.includes(cohortPercentage as 10 | 50 | 100)
        : cohortPercentage !== null)) {
      return reply.status(400).send({ error: 'invalid_request' });
    }
    const result = await service.setPolicy({ condominioId, state: state as HumanAuthRolloutState,
      cohortPercentage: cohortPercentage as number | null, actorAccountId: actor.accountId,
      requestCorrelationId: request.id, authorization: { kind: 'browser', sessionId: actor.sessionId } });
    return result ? reply.send(result) : reply.status(403).send({ error: 'reauthentication_required' });
  });
}
