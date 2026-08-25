import assert from 'node:assert/strict';
import { randomBytes, randomUUID } from 'node:crypto';
import test from 'node:test';

import { PrismaClient } from '@prisma/client';
import pg from 'pg';

import { createHumanAuthRolloutService } from '../src/human-auth-rollout.js';

const run = process.env.RUN_DATABASE_TESTS === 'true' && Boolean(process.env.DATABASE_URL);

test('PostgreSQL rollout serializes changes, fails closed, isolates tenants, and rolls sessions back atomically',
  { skip: !run }, async () => {
    const prisma = new PrismaClient();
    const second = new PrismaClient();
    const service = createHumanAuthRolloutService(prisma);
    const secondService = createHumanAuthRolloutService(second);
    const actorAccountId = randomUUID();
    const tenantA = randomUUID();
    const tenantB = randomUUID();
    const accountA = randomUUID();
    const accountB = randomUUID();
    const membershipA = randomUUID();
    const membershipB = randomUUID();
    const providerMembershipId = randomUUID();
    const sessionA = randomUUID();
    const sessionB = randomUUID();
    const racingSession = randomUUID();
    const invitedAccount = randomUUID();
    const invitedMembership = randomUUID();
    const invitationId = randomUUID();
    const invitationDigest = randomBytes(32);
    try {
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
      await locker.query('BEGIN');
      await locker.query(`SELECT scope FROM "HumanAuthRolloutPolicy"
        WHERE scope IN ('global', $1) ORDER BY scope FOR SHARE`, [`tenant:${tenantA}`]);
      await locker.query(`INSERT INTO "BrowserSession" (id, "familyId", "createdAt", "lastSeenAt",
        "idleExpiresAt", "absoluteExpiresAt", "authenticatedAt", "tokenDigest", "csrfDigest",
        "csrfCiphertext", "csrfNonce", "csrfAuthTag", "csrfKeyVersion", "accountId",
        "accountSessionVersion", "activeMembershipId")
        VALUES ($1, $2, $3, $3, $4, $5, $3, $6, $7, $8, $9, $10, 1, $11, 0, $12)`,
      [racingSession, randomUUID(), now, new Date(now.getTime() + 60_000),
        new Date(now.getTime() + 120_000), randomBytes(32), randomBytes(32), randomBytes(32),
        randomBytes(12), randomBytes(16),
        accountA, membershipA]);
      const racingRollback = service.setPolicy({ condominioId: tenantA, state: 'disabled', cohortPercentage: null,
        actorAccountId, requestCorrelationId: 'racing-rollback' });
      await new Promise((resolve) => setTimeout(resolve, 30));
      await locker.query('COMMIT');
      await locker.end();
      assert.equal((await racingRollback)?.revokedSessions, 1);
      assert.ok((await prisma.browserSession.findUniqueOrThrow({ where: { id: racingSession } })).revokedAt);
      assert.equal((await service.preflightInvitation(invitationDigest)).allowed, false);
      await service.setPolicy({ condominioId: tenantA, state: 'enabled', cohortPercentage: null,
        actorAccountId, requestCorrelationId: 'tenant-a-reenable' });

      const sessions = [
        { id: sessionA, accountId: accountA, membershipId: membershipA },
        { id: sessionB, accountId: accountB, membershipId: membershipB }
      ];
      for (const session of sessions) {
        await prisma.browserSession.create({ data: { id: session.id, familyId: randomUUID(), createdAt: now,
          lastSeenAt: now, idleExpiresAt: new Date(now.getTime() + 60_000),
          absoluteExpiresAt: new Date(now.getTime() + 120_000), authenticatedAt: now,
          tokenDigest: randomBytes(32), csrfDigest: randomBytes(32), csrfCiphertext: randomBytes(32),
          csrfNonce: randomBytes(12), csrfAuthTag: randomBytes(16), csrfKeyVersion: 1,
          accountId: session.accountId, accountSessionVersion: 0, activeMembershipId: session.membershipId } });
      }
      const rollback = await service.setPolicy({ condominioId: tenantA, state: 'disabled', cohortPercentage: null,
        actorAccountId, requestCorrelationId: 'tenant-a-rollback' });
      assert.equal(rollback?.revokedSessions, 1);
      assert.ok((await prisma.browserSession.findUniqueOrThrow({ where: { id: sessionA } })).revokedAt);
      assert.equal((await prisma.browserSession.findUniqueOrThrow({ where: { id: sessionB } })).revokedAt, null);
      assert.equal((await prisma.$transaction((tx) => service.gateMembership(tx, membershipA, accountA))).allowed, false);
      assert.equal((await prisma.$transaction((tx) => service.gateMembership(tx, membershipB, accountB))).allowed, true);
      assert.equal(await prisma.humanAuthRolloutHistory.count({ where: { scope: `tenant:${tenantA}` } }), 5);
      await assert.rejects(prisma.$executeRaw`UPDATE "HumanAuthRolloutHistory" SET rollback = false
        WHERE scope = ${`tenant:${tenantA}`}`);
    } finally {
      await prisma.browserSession.deleteMany({ where: { id: { in: [sessionA, sessionB, racingSession] } } });
      await prisma.humanProvisioningInvitation.deleteMany({ where: { id: invitationId } });
      await prisma.humanAuthRolloutHistory.deleteMany({ where: { actorAccountId } }).catch(() => undefined);
      // Immutable history intentionally prevents normal cleanup; isolate this test with unique rows and remove through owner SQL.
      const owner = new pg.Client({ connectionString: process.env.DATABASE_URL });
      await owner.connect();
      await owner.query('DROP TRIGGER "HumanAuthRolloutHistory_reject_update_delete" ON "HumanAuthRolloutHistory"');
      await owner.query('DELETE FROM "HumanAuthRolloutHistory" WHERE "actorAccountId" = $1', [actorAccountId]);
      await owner.query(`CREATE TRIGGER "HumanAuthRolloutHistory_reject_update_delete" BEFORE UPDATE OR DELETE
        ON "HumanAuthRolloutHistory" FOR EACH ROW EXECUTE FUNCTION reject_human_auth_rollout_history_mutation()`);
      await owner.end();
      await prisma.humanAuthRolloutPolicy.deleteMany({ where: { condominioId: { in: [tenantA, tenantB] } } });
      await prisma.externalIdentity.deleteMany({ where: { accountId: actorAccountId } });
      await prisma.humanMembership.deleteMany({ where: { accountId: { in: [actorAccountId, accountA, accountB, invitedAccount] } } });
      await prisma.humanAccount.deleteMany({ where: { id: { in: [actorAccountId, accountA, accountB, invitedAccount] } } });
      await prisma.condominio.deleteMany({ where: { id: { in: [tenantA, tenantB] } } });
      await Promise.all([prisma.$disconnect(), second.$disconnect()]);
    }
  });
