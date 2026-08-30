import assert from 'node:assert/strict';
import { randomBytes, randomUUID } from 'node:crypto';
import test from 'node:test';

import { PrismaClient } from '@prisma/client';
import type { AuthAlertSink } from '../src/auth-observability.js';

import {
  alertOverdueRecoveryRevocations,
  claimRecoveryRevocations,
  createPostgresRecoveryRevocationAdapter,
  processRecoveryClaim,
  runRecoveryBatch,
  type RecoveryRevocationAdapter,
  type RecoveryWorkerConfig
} from '../src/jobs/process-recovery-revocations.js';

const run = process.env.RUN_DATABASE_TESTS === 'true' && Boolean(process.env.DATABASE_URL);
const config: RecoveryWorkerConfig = {
  batchSize: 20,
  leaseMs: 500,
  pollMs: 25,
  maxAttempts: 3,
  adapterTimeoutMs: 50,
  baseBackoffMs: 10,
  maxBackoffMs: 40
};

test('recovery workers retry nack and timeout, fence stale leases, expire work, alert at five seconds, and revoke exactly once', { skip: !run }, async () => {
  const prisma = new PrismaClient();
  const issuer = 'https://recovery-worker.example.test';
  const accountIds: string[] = [];
  const eventIds: string[] = [];
  const alerts: Array<{ type: string; details: Readonly<Record<string, unknown>> }> = [];
  const alertSink: AuthAlertSink = { emit(type, details) { alerts.push({ type, details }); } };
  const postgres = createPostgresRecoveryRevocationAdapter();

  async function fixture(label: string, withSession = true) {
    const accountId = randomUUID();
    const membershipId = randomUUID();
    const eventId = randomUUID();
    accountIds.push(accountId);
    eventIds.push(eventId);
    await prisma.humanAccount.create({ data: { id: accountId, displayName: `Worker ${label}`, status: 'active' } });
    await prisma.humanMembership.create({ data: { id: membershipId, accountId, role: 'provedor', status: 'active' } });
    if (withSession) {
      const now = new Date();
      await prisma.browserSession.create({ data: {
        familyId: randomUUID(), createdAt: now, lastSeenAt: now, idleExpiresAt: new Date(now.getTime() + 60_000),
        absoluteExpiresAt: new Date(now.getTime() + 120_000), authenticatedAt: now,
        authenticationMethods: ['webauthn'], tokenDigest: randomBytes(32), csrfDigest: randomBytes(32),
        csrfCiphertext: randomBytes(32), csrfNonce: randomBytes(12), csrfAuthTag: randomBytes(16), csrfKeyVersion: 1,
        accountId, accountSessionVersion: 0, activeMembershipId: membershipId
      } });
    }
    const event = await prisma.recoveryWebhookEvent.create({ data: {
      eventId, eventDigest: randomBytes(32), issuer, subjectDigest: randomBytes(32), keyVersion: 1,
      accountId, expiresAt: new Date(Date.now() + 60_000)
    } });
    return { accountId, eventId, id: event.id };
  }

  try {
    const concurrent = await Promise.all([fixture('concurrent-a'), fixture('concurrent-b')]);
    await Promise.all([
      runRecoveryBatch({ client: prisma, adapter: postgres, alerts: alertSink, workerId: 'worker-a', config: { ...config, batchSize: 1 } }),
      runRecoveryBatch({ client: prisma, adapter: postgres, alerts: alertSink, workerId: 'worker-b', config: { ...config, batchSize: 1 } })
    ]);
    for (const item of concurrent) {
      assert.equal((await prisma.recoveryWebhookEvent.findUniqueOrThrow({ where: { id: item.id } })).status, 'acknowledged');
      assert.equal((await prisma.humanAccount.findUniqueOrThrow({ where: { id: item.accountId } })).sessionVersion, 1);
      assert.equal(await prisma.browserSession.count({ where: { accountId: item.accountId, revokedAt: null } }), 0);
    }
    assert.deepEqual(await claimRecoveryRevocations(prisma, { workerId: 'duplicate', batchSize: 20, leaseMs: 500, maxAttempts: 3 }), []);

    const nack = await fixture('nack');
    let nackCalls = 0;
    const nackThenAck: RecoveryRevocationAdapter = {
      supportsIdempotency: true,
      async revoke(input) {
        nackCalls += 1;
        return nackCalls === 1 ? { acknowledged: false, revokedSessions: 0 } : postgres.revoke(input);
      }
    };
    await runRecoveryBatch({ client: prisma, adapter: nackThenAck, alerts: alertSink, workerId: 'nack-1', config, random: () => 0.5 });
    assert.equal((await prisma.recoveryWebhookEvent.findUniqueOrThrow({ where: { id: nack.id } })).status, 'retry');
    await prisma.recoveryWebhookEvent.update({ where: { id: nack.id }, data: { nextAttemptAt: new Date(0) } });
    await runRecoveryBatch({ client: prisma, adapter: nackThenAck, alerts: alertSink, workerId: 'nack-2', config, random: () => 0.5 });
    assert.equal((await prisma.humanAccount.findUniqueOrThrow({ where: { id: nack.accountId } })).sessionVersion, 1);

    const timeout = await fixture('timeout');
    await runRecoveryBatch({
      client: prisma, alerts: alertSink, workerId: 'timeout', config,
      adapter: { supportsIdempotency: true, async revoke() { return new Promise(() => {}); } }
    });
    const timedOut = await prisma.recoveryWebhookEvent.findUniqueOrThrow({ where: { id: timeout.id } });
    assert.equal(timedOut.status, 'retry');
    assert.equal(timedOut.lastError, 'adapter_timeout');
    assert.equal((await prisma.humanAccount.findUniqueOrThrow({ where: { id: timeout.accountId } })).sessionVersion, 0);
    await prisma.recoveryWebhookEvent.update({ where: { id: timeout.id }, data: { nextAttemptAt: new Date(Date.now() + 60_000) } });

    const stale = await fixture('stale');
    const oldClaim = (await claimRecoveryRevocations(prisma, { workerId: 'crashed', batchSize: 1, leaseMs: 500, maxAttempts: 3 }))[0]!;
    assert.equal(oldClaim.id, stale.id);
    await prisma.recoveryWebhookEvent.update({ where: { id: stale.id }, data: { leaseExpiresAt: new Date(0) } });
    const recovered = (await claimRecoveryRevocations(prisma, { workerId: 'restart', batchSize: 1, leaseMs: 500, maxAttempts: 3 }))[0]!;
    assert.notEqual(recovered.leaseToken, oldClaim.leaseToken);
    assert.deepEqual(await processRecoveryClaim(prisma, postgres, oldClaim, config), { outcome: 'lost_lease' });
    assert.equal((await processRecoveryClaim(prisma, postgres, recovered, config)).outcome, 'acknowledged');

    const expired = await fixture('expired', false);
    await prisma.recoveryWebhookEvent.update({ where: { id: expired.id }, data: {
      createdAt: new Date(Date.now() - 60_000), expiresAt: new Date(Date.now() - 1_000), sloAlertedAt: new Date()
    } });
    await claimRecoveryRevocations(prisma, { workerId: 'expiry-sweep', batchSize: 20, leaseMs: 500, maxAttempts: 3 });
    assert.equal((await prisma.recoveryWebhookEvent.findUniqueOrThrow({ where: { id: expired.id } })).status, 'expired');

    const overdue = await fixture('slo', false);
    await prisma.recoveryWebhookEvent.update({ where: { id: overdue.id }, data: { createdAt: new Date(Date.now() - 5_100) } });
    assert.equal(await alertOverdueRecoveryRevocations(prisma, alertSink), 1);
    assert.equal(await alertOverdueRecoveryRevocations(prisma, alertSink), 0);
    const breach = alerts.find(({ type }) => type === 'recovery_revocation_slo_breach');
    assert.ok(breach);
    assert.deepEqual(breach.details, { severity: 'critical', thresholdSeconds: 5, affectedEvents: 1, terminalEvents: 0 });

    const serialized = JSON.stringify(await prisma.recoveryWebhookEvent.findMany({ where: { eventId: { in: eventIds } } }));
    assert.equal(serialized.includes('recovery-subject'), false);
    assert.equal(serialized.includes('signature'), false);
  } finally {
    await prisma.recoveryWebhookEvent.deleteMany({ where: { eventId: { in: eventIds } } });
    await prisma.browserSession.deleteMany({ where: { accountId: { in: accountIds } } });
    await prisma.humanMembership.deleteMany({ where: { accountId: { in: accountIds } } });
    await prisma.humanAccount.deleteMany({ where: { id: { in: accountIds } } });
    await prisma.$disconnect();
  }
});
