import { createHash, randomUUID } from 'node:crypto';

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

async function revokeIneligibleSessions(
  transaction: Prisma.TransactionClient,
  changedTenantId: string | null
) {
  return transaction.$executeRaw(Prisma.sql`
    WITH effective AS MATERIALIZED (
      SELECT session.id,
        membership.role = 'provedor' AS provider,
        global_policy.state::text AS global_state,
        global_policy."cohortPercentage" AS global_percentage,
        global_policy."cohortAlgorithm" AS global_algorithm,
        tenant_policy.state::text AS tenant_state,
        tenant_policy."cohortPercentage" AS tenant_percentage,
        tenant_policy."cohortAlgorithm" AS tenant_algorithm,
        CASE WHEN membership."condominioId" IS NULL THEN NULL ELSE
          (get_byte(sha256(convert_to(${HUMAN_AUTH_COHORT_ALGORITHM}, 'UTF8') || decode('00', 'hex')
            || convert_to(membership."condominioId", 'UTF8')), 0)::bigint * 16777216
          + get_byte(sha256(convert_to(${HUMAN_AUTH_COHORT_ALGORITHM}, 'UTF8') || decode('00', 'hex')
            || convert_to(membership."condominioId", 'UTF8')), 1)::bigint * 65536
          + get_byte(sha256(convert_to(${HUMAN_AUTH_COHORT_ALGORITHM}, 'UTF8') || decode('00', 'hex')
            || convert_to(membership."condominioId", 'UTF8')), 2)::bigint * 256
          + get_byte(sha256(convert_to(${HUMAN_AUTH_COHORT_ALGORITHM}, 'UTF8') || decode('00', 'hex')
            || convert_to(membership."condominioId", 'UTF8')), 3)::bigint) % 100 + 1
        END AS cohort
      FROM "BrowserSession" session
      JOIN "HumanMembership" membership ON membership.id = session."activeMembershipId"
        AND membership."accountId" = session."accountId"
      LEFT JOIN "HumanAuthRolloutPolicy" global_policy ON global_policy.scope = 'global'
      LEFT JOIN "HumanAuthRolloutPolicy" tenant_policy
        ON tenant_policy.scope = 'tenant:' || membership."condominioId"
      WHERE session."revokedAt" IS NULL
        ${changedTenantId ? Prisma.sql`AND membership."condominioId" = ${changedTenantId}` : Prisma.empty}
    )
    UPDATE "BrowserSession" session
    SET "revokedAt" = clock_timestamp(), "revokeReason" = 'human_auth_policy_change'
    FROM effective
    WHERE session.id = effective.id
      AND (
        (effective.provider AND effective.global_state IN ('internal_provider', 'pilot', 'enabled'))
        OR (NOT effective.provider
          AND (effective.global_state = 'enabled' OR (
            effective.global_state = 'pilot'
            AND effective.global_algorithm = ${HUMAN_AUTH_COHORT_ALGORITHM}
            AND effective.global_percentage IN (10, 50, 100)
            AND effective.cohort <= effective.global_percentage
          ))
          AND (effective.tenant_state = 'enabled' OR (
            effective.tenant_state = 'pilot'
            AND effective.tenant_algorithm = ${HUMAN_AUTH_COHORT_ALGORITHM}
            AND effective.tenant_percentage IN (10, 50, 100)
            AND effective.cohort <= effective.tenant_percentage
          ))
        )
      ) IS NOT TRUE
  `);
}

function potentiallyRestrictive(previous: PolicyRow | undefined, state: StoredState, cohortPercentage: number | null) {
  if (!previous) return state !== 'enabled';
  if (state === 'disabled') return previous.state !== 'disabled';
  if (state === 'internal_provider') return !['disabled', 'internal_provider'].includes(previous.state);
  if (state === 'pilot') {
    return previous.state === 'enabled'
      || previous.state === 'pilot' && (previous.cohortPercentage ?? 0) > (cohortPercentage ?? 0);
  }
  return false;
}

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
        SELECT state IN ('disabled', 'internal_provider', 'pilot', 'enabled')
          AND version > 0
          AND ((state = 'pilot' AND "cohortPercentage" IN (10, 50, 100)
            AND "cohortAlgorithm" = ${HUMAN_AUTH_COHORT_ALGORITHM})
            OR (state <> 'pilot' AND "cohortPercentage" IS NULL AND "cohortAlgorithm" IS NULL)) AS valid
        FROM "HumanAuthRolloutPolicy" WHERE scope = 'global' AND "condominioId" IS NULL
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
      authorization: { kind: 'browser'; authenticatedAt: Date } | { kind: 'deployment'; token: string };
    }) {
      const scope = input.condominioId ? `tenant:${input.condominioId}` : 'global';
      const state = storedState(input.state);
      return client.$transaction(async (transaction) => {
        if (input.authorization.kind === 'browser') {
          const recent = await transaction.$queryRaw<Array<{ recent: boolean }>>`
            SELECT ${input.authorization.authenticatedAt}::timestamptz >= clock_timestamp() - interval '10 minutes'
              AND ${input.authorization.authenticatedAt}::timestamptz <= clock_timestamp() AS recent
          `;
          if (!recent[0]?.recent) return null;
        } else {
          const tokenDigest = createHash('sha256').update(input.authorization.token, 'utf8').digest();
          const consumed = await transaction.$queryRaw<Array<{ id: string }>>(Prisma.sql`
            UPDATE "HumanAuthDeploymentAuthorization"
            SET "usedAt" = clock_timestamp(), "requestCorrelationId" = ${input.requestCorrelationId}
            WHERE "tokenDigest" = ${tokenDigest} AND "usedAt" IS NULL
              AND "expiresAt" > clock_timestamp() AND "actorAccountId" = ${input.actorAccountId}::uuid
              AND scope = ${scope} AND state = ${state}::"HumanAuthRolloutState"
              AND "cohortPercentage" IS NOT DISTINCT FROM ${input.cohortPercentage}
            RETURNING id
          `);
          if (!consumed[0]) return null;
        }
        // Global-first ordering also prevents global and tenant rollbacks from deadlocking on sessions.
        await transaction.$executeRaw`SELECT pg_advisory_xact_lock(hashtextextended('global', 170030))`;
        if (scope !== 'global') {
          // Serializes first creation because a row lock cannot lock a missing tenant policy.
          await transaction.$executeRaw`SELECT pg_advisory_xact_lock(hashtextextended(${scope}, 170030))`;
        }
        const actors = await transaction.$queryRaw<Array<{ id: string }>>`
          SELECT account.id
          FROM "HumanAccount" account
          JOIN "HumanMembership" membership ON membership."accountId" = account.id
            AND membership.role = 'provedor' AND membership.status = 'active'
          WHERE account.id = ${input.actorAccountId}::uuid AND account.status = 'active'
            AND EXISTS (SELECT 1 FROM "ExternalIdentity" identity WHERE identity."accountId" = account.id)
          FOR SHARE OF account, membership
        `;
        if (!actors[0]) return null;
        const existing = await transaction.$queryRaw<PolicyRow[]>(Prisma.sql`
          SELECT scope, "condominioId", state::text, "cohortPercentage", "cohortAlgorithm", version, "updatedAt"
          FROM "HumanAuthRolloutPolicy" WHERE scope = ${scope} FOR UPDATE
        `);
        if (input.condominioId && existing.length === 0) {
          const live = await transaction.$queryRaw<Array<{ id: string }>>`
            SELECT id FROM "Condominio" WHERE id = ${input.condominioId} AND "deletedAt" IS NULL FOR SHARE
          `;
          if (!live[0]) return null;
        }
        const previous = existing[0];
        const cohortAlgorithm = state === 'pilot' ? HUMAN_AUTH_COHORT_ALGORITHM : null;
        const version = (previous?.version ?? 0) + 1;
        const restrictiveTransition = potentiallyRestrictive(previous, state, input.cohortPercentage);
        await transaction.$executeRaw(Prisma.sql`
          INSERT INTO "HumanAuthRolloutPolicy" (
            scope, "condominioId", state, "cohortPercentage", "cohortAlgorithm", version, "updatedAt", "updatedByAccountId"
          ) VALUES (
            ${scope}, ${input.condominioId}, ${state}::"HumanAuthRolloutState", ${input.cohortPercentage},
            ${cohortAlgorithm}, ${version}, clock_timestamp(), ${input.actorAccountId}::uuid
          ) ON CONFLICT (scope) DO UPDATE SET state = EXCLUDED.state,
            "cohortPercentage" = EXCLUDED."cohortPercentage", "cohortAlgorithm" = EXCLUDED."cohortAlgorithm",
            version = EXCLUDED.version, "updatedAt" = EXCLUDED."updatedAt",
            "updatedByAccountId" = EXCLUDED."updatedByAccountId"
        `);
        const revokedSessions = await revokeIneligibleSessions(transaction, input.condominioId);
        const rollback = restrictiveTransition || revokedSessions > 0;
        await transaction.$executeRaw`
          INSERT INTO "HumanAuthRolloutHistory" (
            id, scope, "condominioId", "previousState", "previousCohortPercentage", state,
            "cohortPercentage", "cohortAlgorithm", "policyVersion", "actorAccountId",
            "requestCorrelationId", rollback, "revokedSessions"
          ) VALUES (
            ${randomUUID()}::uuid, ${scope}, ${input.condominioId}, ${previous?.state ?? null}::"HumanAuthRolloutState",
            ${previous?.cohortPercentage ?? null}, ${state}::"HumanAuthRolloutState", ${input.cohortPercentage},
            ${cohortAlgorithm}, ${version}, ${input.actorAccountId}::uuid, ${input.requestCorrelationId},
            ${rollback}, ${revokedSessions}
          )
        `;
        return { scope, state: input.state, cohortPercentage: input.cohortPercentage, version, revokedSessions };
      }, {
        // Rollback may update a large active-session set; queue briefly, then allow one bounded atomic scan/update.
        maxWait: 5_000,
        timeout: 30_000
      });
    }
  };
}

export type HumanAuthRolloutService = ReturnType<typeof createHumanAuthRolloutService>;

function providerActor(identity: AuthenticatedIdentity | null): identity is AuthenticatedIdentity & { accountId: string } {
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
    const authenticatedAt = request.browserSessionSnapshot?.authenticatedAt;
    if (!authenticatedAt || authenticatedAt.getTime() < Date.now() - 10 * 60_000) {
      return reply.status(403).send({ error: 'reauthentication_required' });
    }
    const result = await service.setPolicy({ condominioId, state: state as HumanAuthRolloutState,
      cohortPercentage: cohortPercentage as number | null, actorAccountId: actor.accountId,
      requestCorrelationId: request.id, authorization: { kind: 'browser', authenticatedAt } });
    return result ? reply.send(result) : reply.status(404).send({ error: 'not_found' });
  });
}
