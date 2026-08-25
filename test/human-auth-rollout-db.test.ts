import assert from 'node:assert/strict';
import { createHash, randomBytes, randomUUID } from 'node:crypto';
import test from 'node:test';

import { Prisma, PrismaClient } from '@prisma/client';
import Fastify from 'fastify';
import pg from 'pg';

import { authorize } from '../src/auth.js';
import { createHumanAuthRolloutService, humanAuthTenantCohort } from '../src/human-auth-rollout.js';
import {
  createBrowserSessionAuthenticator,
  createPrismaBrowserSessionStore,
  generateSessionToken,
  SESSION_COOKIE_NAME
} from '../src/sessions.js';

const run = process.env.RUN_DATABASE_TESTS === 'true' && Boolean(process.env.DATABASE_URL);

function tenantInCohort(minimum: number, maximum: number) {
  while (true) {
    const id = randomUUID();
    const cohort = humanAuthTenantCohort(id);
    if (cohort >= minimum && cohort <= maximum) return id;
  }
}

function deferred() {
  let resolve!: () => void;
  const promise = new Promise<void>((done) => { resolve = done; });
  return { promise, resolve };
}

async function waitForLockWait(client: pg.Client, queryFragment: string) {
  for (let attempt = 0; attempt < 1_000; attempt += 1) {
    const result = await client.query<{ waiting: boolean }>(`
      SELECT EXISTS (
        SELECT 1 FROM pg_stat_activity
        WHERE pid <> pg_backend_pid() AND datname = current_database()
          AND wait_event_type = 'Lock' AND position($1 in query) > 0
      ) AS waiting
    `, [queryFragment]);
    if (result.rows[0]?.waiting) return;
    await new Promise<void>((resolve) => setImmediate(resolve));
  }
  throw new Error(`database operation did not block at ${queryFragment}`);
}

test('PostgreSQL rollout serializes changes, fails closed, isolates tenants, and rolls sessions back atomically',
  { skip: !run }, async () => {
    const prisma = new PrismaClient();
    const second = new PrismaClient();
    const service = createHumanAuthRolloutService(prisma);
    const secondService = createHumanAuthRolloutService(second);
    const actorAccountId = randomUUID();
    const tenantA = tenantInCohort(51, 100);
    const tenantB = tenantInCohort(1, 10);
    const accountA = randomUUID();
    const accountB = randomUUID();
    const membershipA = randomUUID();
    const membershipB = randomUUID();
    const providerMembershipId = randomUUID();
    const sessionA = randomUUID();
    const sessionB = randomUUID();
    let racingSession: string | undefined;
    const invitedAccount = randomUUID();
    const invitedMembership = randomUUID();
    const invitationId = randomUUID();
    const invitationDigest = randomBytes(32);
    const racingTransactionId = randomUUID();
    const racingHandoffToken = generateSessionToken();
    const highAccount = randomUUID();
    const highMembership = randomUUID();
    const lockObserver = new pg.Client({ connectionString: process.env.DATABASE_URL });
    const rollbackBarrier = new pg.Client({ connectionString: process.env.DATABASE_URL });
    const sessionStore = createPrismaBrowserSessionStore(prisma, {
      currentCsrfKeyVersion: 1,
      csrfKeys: new Map([[1, randomBytes(32)]]),
      publicApplicationOrigin: 'https://app.example.test'
    }, {
      rolloutGate: service,
      rateLimiter: {
        async check() { return { allowed: true, retryAfterSeconds: 0, repeatedExcess: false }; },
        async reserveFailure() { return { allowed: true, retryAfterSeconds: 0, repeatedExcess: false,
          reservationId: randomUUID() }; },
        async finalizeFailure() {}
      }
    });
    try {
      await Promise.all([lockObserver.connect(), rollbackBarrier.connect()]);
      const parityIds = [tenantA, tenantB, randomUUID(), randomUUID()];
      const sqlCohorts = await prisma.$queryRaw<Array<{ id: string; cohort: bigint }>>(Prisma.sql`
        SELECT id, (
          get_byte(sha256(convert_to('sha256-tenant-v1', 'UTF8') || decode('00', 'hex')
            || convert_to(id, 'UTF8')), 0)::bigint * 16777216
          + get_byte(sha256(convert_to('sha256-tenant-v1', 'UTF8') || decode('00', 'hex')
            || convert_to(id, 'UTF8')), 1)::bigint * 65536
          + get_byte(sha256(convert_to('sha256-tenant-v1', 'UTF8') || decode('00', 'hex')
            || convert_to(id, 'UTF8')), 2)::bigint * 256
          + get_byte(sha256(convert_to('sha256-tenant-v1', 'UTF8') || decode('00', 'hex')
            || convert_to(id, 'UTF8')), 3)::bigint
        ) % 100 + 1 AS cohort
        FROM (VALUES ${Prisma.join(parityIds.map((id) => Prisma.sql`(${id})`))}) sample(id)
      `);
      assert.deepEqual(sqlCohorts.map(({ id, cohort }) => [id, Number(cohort)]),
        parityIds.map((id) => [id, humanAuthTenantCohort(id)]));
      await prisma.condominio.createMany({ data: [tenantA, tenantB].map((id) => ({ id, nome: id,
        responsavel: 'PC30', tipo: 'residencial', timezone: 'UTC' })) });
      await prisma.humanAccount.createMany({ data: [actorAccountId, accountA, accountB].map((id) => ({ id,
        displayName: id, status: 'active' })) });
      await prisma.humanMembership.createMany({ data: [
        { id: providerMembershipId, accountId: actorAccountId, role: 'provedor', status: 'active' },
        { id: membershipA, accountId: accountA, condominioId: tenantA, role: 'sindico', status: 'active' },
        { id: membershipB, accountId: accountB, condominioId: tenantB, role: 'sindico', status: 'active' }
      ] });
      await prisma.externalIdentity.create({ data: { accountId: actorAccountId,
        issuer: 'https://identity.example.test', subject: `rollout-${actorAccountId}` } });
      const accountIdentity = await prisma.externalIdentity.create({ data: { accountId: accountA,
        issuer: 'https://identity.example.test', subject: `rollout-${accountA}` } });
      await service.setPolicy({ condominioId: null, state: 'internal-provider', cohortPercentage: null,
        actorAccountId, requestCorrelationId: 'internal-provider' });
      assert.equal((await prisma.$transaction((tx) => service.gateMembership(
        tx, providerMembershipId, actorAccountId
      ))).allowed, true);
      assert.equal((await prisma.$transaction((tx) => service.gateMembership(
        tx, membershipA, accountA
      ))).allowed, false);
      await service.setPolicy({ condominioId: null, state: 'enabled', cohortPercentage: null,
        actorAccountId, requestCorrelationId: 'global-enable' });
      const changes = await Promise.all([
        service.setPolicy({ condominioId: tenantA, state: 'pilot', cohortPercentage: 10,
          actorAccountId, requestCorrelationId: 'pilot-10' }),
        secondService.setPolicy({ condominioId: tenantA, state: 'enabled', cohortPercentage: null,
          actorAccountId, requestCorrelationId: 'enable' })
      ]);
      assert.deepEqual(changes.map((change) => change?.version).sort(), [1, 2]);
      await service.setPolicy({ condominioId: tenantB, state: 'enabled', cohortPercentage: null,
        actorAccountId, requestCorrelationId: 'tenant-b-enable' });
      await service.setPolicy({ condominioId: tenantA, state: 'enabled', cohortPercentage: null,
        actorAccountId, requestCorrelationId: 'tenant-a-concurrent-result' });

      await prisma.humanAccount.create({ data: { id: invitedAccount, displayName: 'Invited' } });
      await prisma.humanMembership.create({ data: { id: invitedMembership, accountId: invitedAccount,
        condominioId: tenantA, role: 'portaria' } });
      await prisma.humanProvisioningInvitation.create({ data: { id: invitationId, accountId: invitedAccount,
        membershipId: invitedMembership, expectedEmail: 'invited@example.test', tokenDigest: invitationDigest,
        expiresAt: new Date(Date.now() + 60_000), createdByAccountId: actorAccountId } });
      assert.equal((await service.preflightInvitation(invitationDigest)).allowed, true);

      const now = new Date();
      const locker = new pg.Client({ connectionString: process.env.DATABASE_URL });
      await locker.connect();
      await prisma.oidcLoginTransaction.create({ data: { id: racingTransactionId,
        expiresAt: new Date(Date.now() + 60_000), stateDigest: randomBytes(32), nonceDigest: randomBytes(32),
        pkceVerifierCiphertext: randomBytes(43), pkceVerifierNonce: randomBytes(12),
        pkceVerifierAuthTag: randomBytes(16), pkceKeyVersion: 1, issuer: 'https://identity.example.test',
        clientId: 'rollout-race', redirectUri: 'https://app.example.test/auth/callback', returnTo: '/' } });
      await prisma.oidcValidatedHandoff.create({ data: { loginTransactionId: racingTransactionId,
        expiresAt: new Date(Date.now() + 60_000), handleDigest: createHash('sha256').update(racingHandoffToken).digest(),
        accountId: accountA, externalIdentityId: accountIdentity.id, authenticatedAt: now } });
      await locker.query(`CREATE FUNCTION pc30_block_session_issue() RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN PERFORM pg_advisory_xact_lock(300030); RETURN NEW; END; $$`);
      await locker.query(`CREATE TRIGGER pc30_block_session_issue BEFORE INSERT ON "BrowserSession"
        FOR EACH ROW EXECUTE FUNCTION pc30_block_session_issue()`);
      await locker.query('BEGIN');
      await locker.query('SELECT pg_advisory_xact_lock(300030)');
      const issuing = sessionStore.issueFromHandoff({ handoffToken: racingHandoffToken,
        requestCorrelationId: 'rollout-issuance-race' });
      await new Promise((resolve) => setTimeout(resolve, 50));
      let rollbackFinished = false;
      const racingRollback = service.setPolicy({ condominioId: tenantA, state: 'disabled', cohortPercentage: null,
        actorAccountId, requestCorrelationId: 'racing-rollback' }).finally(() => { rollbackFinished = true; });
      await new Promise((resolve) => setTimeout(resolve, 30));
      assert.equal(rollbackFinished, false);
      await locker.query('COMMIT');
      const issued = await issuing;
      assert.ok(issued);
      racingSession = issued.identity.sessionId;
      assert.equal((await racingRollback)?.revokedSessions, 1);
      assert.ok((await prisma.browserSession.findUniqueOrThrow({ where: { id: racingSession } })).revokedAt);
      await locker.query('DROP TRIGGER pc30_block_session_issue ON "BrowserSession"');
      await locker.query('DROP FUNCTION pc30_block_session_issue()');
      await locker.end();

      let businessHandlerCalls = 0;
      const businessApp = Fastify();
      businessApp.get('/business/:tenantId', {
        preHandler: authorize(createBrowserSessionAuthenticator(sessionStore), 'moradores:manage', (request) =>
          String((request.params as Record<string, unknown>).tenantId)
        )
      }, async () => { businessHandlerCalls += 1; return { ok: true }; });
      const deniedAfterRollback = await businessApp.inject({ method: 'GET', url: `/business/${tenantA}`,
        headers: { cookie: `${SESSION_COOKIE_NAME}=${issued.sessionToken}` } });
      assert.equal(deniedAfterRollback.statusCode, 401);
      assert.equal(businessHandlerCalls, 0);
      await businessApp.close();
      assert.equal((await service.preflightInvitation(invitationDigest)).allowed, false);
      await service.setPolicy({ condominioId: tenantA, state: 'enabled', cohortPercentage: null,
        actorAccountId, requestCorrelationId: 'tenant-a-reenable' });

      async function createKnownSession(label: string) {
        const token = generateSessionToken();
        const id = randomUUID();
        const createdAt = new Date();
        await prisma.browserSession.create({ data: { id, familyId: randomUUID(), createdAt,
          lastSeenAt: createdAt, idleExpiresAt: new Date(createdAt.getTime() + 60_000),
          absoluteExpiresAt: new Date(createdAt.getTime() + 120_000), authenticatedAt: createdAt,
          tokenDigest: createHash('sha256').update(token).digest(), csrfDigest: randomBytes(32),
          csrfCiphertext: randomBytes(32), csrfNonce: randomBytes(12), csrfAuthTag: randomBytes(16),
          csrfKeyVersion: 1, accountId: accountB, accountSessionVersion: 0, activeMembershipId: membershipB } });
        return { id, token, label };
      }

      const gateEntered = deferred();
      const releaseGate = deferred();
      const handlerEntered = deferred();
      const releaseHandler = deferred();
      const gateFirstSession = await createKnownSession('gate-first');
      const heldGateStore = createPrismaBrowserSessionStore(prisma, {
        currentCsrfKeyVersion: 1, csrfKeys: new Map([[1, randomBytes(32)]]),
        publicApplicationOrigin: 'https://app.example.test'
      }, { rolloutGate: {
        ...service,
        async gateMembership(transaction, membershipId, accountId) {
          const decision = await service.gateMembership(transaction, membershipId, accountId);
          gateEntered.resolve();
          await releaseGate.promise;
          return decision;
        }
      } });
      let gateFirstHandlerCalls = 0;
      const gateFirstApp = Fastify();
      gateFirstApp.get('/business/:tenantId', {
        preHandler: authorize(createBrowserSessionAuthenticator(heldGateStore), 'moradores:manage', (request) =>
          String((request.params as Record<string, unknown>).tenantId)
        )
      }, async () => {
        gateFirstHandlerCalls += 1;
        handlerEntered.resolve();
        await releaseHandler.promise;
        return { ok: true };
      });
      const gateFirstRequest = gateFirstApp.inject({ method: 'GET', url: `/business/${tenantB}`,
        headers: { cookie: `${SESSION_COOKIE_NAME}=${gateFirstSession.token}` } });
      await gateEntered.promise;
      const gateFirstRollback = service.setPolicy({ condominioId: tenantB, state: 'disabled', cohortPercentage: null,
        actorAccountId, requestCorrelationId: 'gate-first-rollback' });
      await waitForLockWait(lockObserver, 'FROM "HumanAuthRolloutPolicy"');
      releaseGate.resolve();
      await Promise.all([handlerEntered.promise, gateFirstRollback]);
      assert.ok((await prisma.browserSession.findUniqueOrThrow({ where: { id: gateFirstSession.id } })).revokedAt);
      releaseHandler.resolve();
      assert.equal((await gateFirstRequest).statusCode, 200);
      assert.equal(gateFirstHandlerCalls, 1);
      await gateFirstApp.close();

      await service.setPolicy({ condominioId: tenantB, state: 'enabled', cohortPercentage: null,
        actorAccountId, requestCorrelationId: 'before-rollback-first' });
      const rollbackFirstSession = await createKnownSession('rollback-first');
      await rollbackBarrier.query(`CREATE FUNCTION pc30_block_policy_update() RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN PERFORM pg_advisory_xact_lock(300031); RETURN NEW; END; $$`);
      await rollbackBarrier.query(`CREATE TRIGGER pc30_block_policy_update BEFORE UPDATE
        ON "HumanAuthRolloutPolicy" FOR EACH ROW EXECUTE FUNCTION pc30_block_policy_update()`);
      await rollbackBarrier.query('BEGIN');
      await rollbackBarrier.query('SELECT pg_advisory_xact_lock(300031)');
      const rollbackFirst = service.setPolicy({ condominioId: tenantB, state: 'disabled', cohortPercentage: null,
        actorAccountId, requestCorrelationId: 'rollback-first' });
      await waitForLockWait(lockObserver, 'INSERT INTO "HumanAuthRolloutPolicy"');
      let rollbackFirstHandlerCalls = 0;
      const rollbackFirstApp = Fastify();
      rollbackFirstApp.get('/business/:tenantId', {
        preHandler: authorize(createBrowserSessionAuthenticator(sessionStore), 'moradores:manage', (request) =>
          String((request.params as Record<string, unknown>).tenantId)
        )
      }, async () => { rollbackFirstHandlerCalls += 1; return { ok: true }; });
      const rollbackFirstRequest = rollbackFirstApp.inject({ method: 'GET', url: `/business/${tenantB}`,
        headers: { cookie: `${SESSION_COOKIE_NAME}=${rollbackFirstSession.token}` } });
      await waitForLockWait(lockObserver, 'FROM "HumanAuthRolloutPolicy"');
      await rollbackBarrier.query('COMMIT');
      await rollbackFirst;
      assert.equal((await rollbackFirstRequest).statusCode, 401);
      assert.equal(rollbackFirstHandlerCalls, 0);
      await rollbackFirstApp.close();
      await rollbackBarrier.query('DROP TRIGGER pc30_block_policy_update ON "HumanAuthRolloutPolicy"');
      await rollbackBarrier.query('DROP FUNCTION pc30_block_policy_update()');
      await service.setPolicy({ condominioId: tenantB, state: 'enabled', cohortPercentage: null,
        actorAccountId, requestCorrelationId: 'after-linearization-tests' });

      const providerSession = randomUUID();
      const sessions = [
        { id: sessionA, accountId: accountA, membershipId: membershipA },
        { id: sessionB, accountId: accountB, membershipId: membershipB },
        { id: providerSession, accountId: actorAccountId, membershipId: providerMembershipId }
      ];
      for (const session of sessions) {
        await prisma.browserSession.create({ data: { id: session.id, familyId: randomUUID(), createdAt: now,
          lastSeenAt: now, idleExpiresAt: new Date(now.getTime() + 60_000),
          absoluteExpiresAt: new Date(now.getTime() + 120_000), authenticatedAt: now,
          tokenDigest: randomBytes(32), csrfDigest: randomBytes(32), csrfCiphertext: randomBytes(32),
          csrfNonce: randomBytes(12), csrfAuthTag: randomBytes(16), csrfKeyVersion: 1,
          accountId: session.accountId, accountSessionVersion: 0, activeMembershipId: session.membershipId } });
      }
      assert.equal((await service.setPolicy({ condominioId: tenantA, state: 'pilot', cohortPercentage: 100,
        actorAccountId, requestCorrelationId: 'tenant-pilot-100' }))?.revokedSessions, 0);
      assert.equal((await service.setPolicy({ condominioId: tenantA, state: 'pilot', cohortPercentage: 50,
        actorAccountId, requestCorrelationId: 'tenant-pilot-50' }))?.revokedSessions, 1);
      assert.ok((await prisma.browserSession.findUniqueOrThrow({ where: { id: sessionA } })).revokedAt);
      assert.equal((await prisma.browserSession.findUniqueOrThrow({ where: { id: sessionB } })).revokedAt, null);
      assert.equal((await prisma.browserSession.findUniqueOrThrow({ where: { id: providerSession } })).revokedAt, null);

      await service.setPolicy({ condominioId: tenantA, state: 'enabled', cohortPercentage: null,
        actorAccountId, requestCorrelationId: 'tenant-before-global-pilot' });
      const globalExcludedSession = randomUUID();
      await prisma.browserSession.create({ data: { id: globalExcludedSession, familyId: randomUUID(), createdAt: now,
        lastSeenAt: now, idleExpiresAt: new Date(now.getTime() + 60_000),
        absoluteExpiresAt: new Date(now.getTime() + 120_000), authenticatedAt: now,
        tokenDigest: randomBytes(32), csrfDigest: randomBytes(32), csrfCiphertext: randomBytes(32),
        csrfNonce: randomBytes(12), csrfAuthTag: randomBytes(16), csrfKeyVersion: 1,
        accountId: accountA, accountSessionVersion: 0, activeMembershipId: membershipA } });
      assert.equal((await service.setPolicy({ condominioId: null, state: 'pilot', cohortPercentage: 10,
        actorAccountId, requestCorrelationId: 'global-enabled-to-pilot' }))?.revokedSessions, 1);
      assert.ok((await prisma.browserSession.findUniqueOrThrow({ where: { id: globalExcludedSession } })).revokedAt);
      assert.equal((await prisma.browserSession.findUniqueOrThrow({ where: { id: sessionB } })).revokedAt, null);
      assert.equal((await prisma.browserSession.findUniqueOrThrow({ where: { id: providerSession } })).revokedAt, null);
      assert.equal((await prisma.$transaction((tx) => service.gateMembership(tx, membershipA, accountA))).allowed, false);
      assert.equal((await prisma.$transaction((tx) => service.gateMembership(tx, membershipB, accountB))).allowed, true);
      assert.ok(await prisma.humanAuthRolloutHistory.count({ where: { scope: `tenant:${tenantA}` } }) >= 8);

      await prisma.humanAccount.create({ data: { id: highAccount, displayName: 'High cardinality', status: 'active' } });
      await prisma.humanMembership.create({ data: { id: highMembership, accountId: highAccount,
        condominioId: tenantB, role: 'portaria', status: 'active' } });
      await prisma.$executeRaw`
        WITH db_clock AS MATERIALIZED (SELECT clock_timestamp() AS now)
        INSERT INTO "BrowserSession" (
          id, "familyId", "createdAt", "lastSeenAt", "idleExpiresAt", "absoluteExpiresAt",
          "authenticatedAt", "tokenDigest", "csrfDigest", "csrfCiphertext", "csrfNonce",
          "csrfAuthTag", "csrfKeyVersion", "accountId", "accountSessionVersion", "activeMembershipId"
        )
        SELECT ('10000000-0000-4000-8000-' || lpad(value::text, 12, '0'))::uuid,
          ('20000000-0000-4000-8000-' || lpad(value::text, 12, '0'))::uuid,
          now, now, now + interval '30 minutes', now + interval '12 hours', now,
          sha256(convert_to('pc30-high-token-' || value, 'UTF8')),
          decode(repeat('01', 32), 'hex'), decode(repeat('02', 32), 'hex'),
          decode(repeat('03', 12), 'hex'), decode(repeat('04', 16), 'hex'), 1,
          ${highAccount}::uuid, 0, ${highMembership}::uuid
        FROM generate_series(1, 33000) value CROSS JOIN db_clock
      `;
      const highRollback = await service.setPolicy({ condominioId: tenantB, state: 'disabled', cohortPercentage: null,
        actorAccountId, requestCorrelationId: 'high-cardinality-rollback' });
      assert.equal(highRollback?.revokedSessions, 33_001);
      assert.equal(await prisma.browserSession.count({ where: { accountId: highAccount, revokedAt: { not: null } } }), 33_000);
      await assert.rejects(prisma.$executeRaw`UPDATE "HumanAuthRolloutHistory" SET rollback = false
        WHERE scope = ${`tenant:${tenantA}`}`);
    } finally {
      await prisma.browserSession.deleteMany({ where: { accountId: {
        in: [actorAccountId, accountA, accountB, highAccount]
      } } });
      await prisma.oidcValidatedHandoff.deleteMany({ where: { loginTransactionId: racingTransactionId } });
      await prisma.oidcLoginTransaction.deleteMany({ where: { id: racingTransactionId } });
      await prisma.humanProvisioningInvitation.deleteMany({ where: { id: invitationId } });
      await prisma.humanAuthRolloutHistory.deleteMany({ where: { actorAccountId } }).catch(() => undefined);
      // Immutable history intentionally prevents normal cleanup; isolate this test with unique rows and remove through owner SQL.
      await rollbackBarrier.query('ROLLBACK').catch(() => undefined);
      const owner = new pg.Client({ connectionString: process.env.DATABASE_URL });
      await owner.connect();
      await owner.query('DROP TRIGGER IF EXISTS pc30_block_session_issue ON "BrowserSession"');
      await owner.query('DROP FUNCTION IF EXISTS pc30_block_session_issue()');
      await owner.query('DROP TRIGGER IF EXISTS pc30_block_policy_update ON "HumanAuthRolloutPolicy"');
      await owner.query('DROP FUNCTION IF EXISTS pc30_block_policy_update()');
      await owner.query('DROP TRIGGER "HumanAuthRolloutHistory_reject_update_delete" ON "HumanAuthRolloutHistory"');
      await owner.query('DELETE FROM "HumanAuthRolloutHistory" WHERE "actorAccountId" = $1', [actorAccountId]);
      await owner.query(`CREATE TRIGGER "HumanAuthRolloutHistory_reject_update_delete" BEFORE UPDATE OR DELETE
        ON "HumanAuthRolloutHistory" FOR EACH ROW EXECUTE FUNCTION reject_human_auth_rollout_history_mutation()`);
      await owner.end();
      await Promise.all([lockObserver.end().catch(() => undefined), rollbackBarrier.end().catch(() => undefined)]);
      await prisma.humanAuthRolloutPolicy.deleteMany({ where: { condominioId: { in: [tenantA, tenantB] } } });
      await prisma.externalIdentity.deleteMany({ where: { accountId: { in: [actorAccountId, accountA] } } });
      await prisma.humanMembership.deleteMany({ where: { accountId: {
        in: [actorAccountId, accountA, accountB, invitedAccount, highAccount]
      } } });
      await prisma.humanAccount.deleteMany({ where: { id: {
        in: [actorAccountId, accountA, accountB, invitedAccount, highAccount]
      } } });
      await prisma.condominio.deleteMany({ where: { id: { in: [tenantA, tenantB] } } });
      await Promise.all([prisma.$disconnect(), second.$disconnect()]);
    }
  });
