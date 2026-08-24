import assert from 'node:assert/strict';
import { createCipheriv, createHash } from 'node:crypto';
import test from 'node:test';

import { PrismaClient, type DeliveryChannel } from '@prisma/client';

import {
  claimDeliveries,
  completeDelivery,
  PermanentDeliveryError,
  runDeliveryBatch,
  verifyDeliverySecret,
  type DeliveryProvider,
  type DeliveryWorkerConfig
} from '../src/jobs/deliver-invitations.js';

const runDatabaseTests = process.env.RUN_DATABASE_TESTS === 'true';
const secret = 'delivery-worker-cache-secret-minimum-32-bytes';
const uuid = (n: number) => `81000000-0000-4000-8000-${String(n).padStart(12, '0')}`;
const config: DeliveryWorkerConfig = {
  batchSize: 20,
  concurrency: 4,
  leaseMs: 5_000,
  pollMs: 50,
  maxAttempts: 3,
  providerTimeoutMs: 30_000,
  baseBackoffMs: 100,
  maxBackoffMs: 1_000
};

function protect(id: string, invitationId: string, channel: DeliveryChannel, to: string) {
  const key = createHash('sha256').update(secret).digest();
  const iv = Buffer.alloc(12, Number(id.slice(-2)) || 1);
  const cipher = createCipheriv('aes-256-gcm', key, iv);
  cipher.setAAD(Buffer.from(`delivery:${id}:${invitationId}:${channel}:v1`));
  const plaintext = JSON.stringify({
    intentId: id,
    invitationId,
    to,
    ...(channel === 'email' ? { subject: 'Invitation' } : {}),
    body: 'Secret token 123456'
  });
  return {
    payloadCiphertext: Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]),
    payloadIv: iv,
    payloadAuthTag: cipher.getAuthTag()
  };
}

test('PostgreSQL workers claim safely, retry, recover crashes, reject stale leases, and release locks before I/O', { skip: !runDatabaseTests }, async () => {
  const prisma = new PrismaClient();
  const condominioId = uuid(1);
  const invitationIds = Array.from({ length: 15 }, (_, index) => uuid(10 + index));
  const intentIds = Array.from({ length: 15 }, (_, index) => uuid(100 + index));
  const calls = new Map<string, number>();
  const previousSecurityKey = await prisma.securityKey.findUnique({ where: { name: 'idempotency-cache-v1' } });
  const previousDeliveryPolicy = await prisma.securityKey.findUnique({ where: { name: 'delivery-worker-policy-v1' } });
  const provider: DeliveryProvider = {
    supportsIdempotency: true,
    async send({ idempotencyKey, payload }) {
      calls.set(idempotencyKey, (calls.get(idempotencyKey) ?? 0) + 1);
      if (payload.to === 'transient@example.test' && calls.get(idempotencyKey) === 1) throw new Error('sensitive provider detail');
      if (payload.to === 'permanent@example.test') throw new PermanentDeliveryError('rejected address');
    }
  };

  try {
    await prisma.condominio.create({
      data: { id: condominioId, nome: 'Worker test', responsavel: 'Owner', tipo: 'residencial', timezone: 'UTC' }
    });
    await prisma.convite.createMany({
      data: invitationIds.map((id) => ({ id, condominioId, expiresAt: new Date(Date.now() + 60_000) }))
    });
    const fingerprint = createHash('sha256').update(`idempotency-cache:${secret}`).digest('hex');
    await prisma.securityKey.upsert({
      where: { name: 'idempotency-cache-v1' },
      create: { name: 'idempotency-cache-v1', fingerprint },
      update: { fingerprint }
    });
    const recipients = [
      'first@example.test', 'second@example.test', 'transient@example.test',
      'permanent@example.test', 'crash@example.test', 'stale@example.test', 'slow@example.test',
      'heartbeat@example.test', 'queued@example.test', 'final-crash@example.test', 'exhausted@example.test',
      'lease-holder@example.test', 'lost-lease@example.test', 'timeout@example.test', 'shutdown@example.test'
    ];
    for (let index = 0; index < intentIds.length; index++) {
      const channel: DeliveryChannel = index === 1 ? 'sms' : 'email';
      const encrypted = protect(intentIds[index]!, invitationIds[index]!, channel, recipients[index]!);
      await prisma.deliveryIntent.create({
        data: {
          id: intentIds[index]!, conviteId: invitationIds[index]!, condominioId,
          channel, keyVersion: 1, ...encrypted,
          nextAttemptAt: index < 4 ? new Date() : new Date(Date.now() + 60_000)
        }
      });
    }

    await assert.rejects(
      verifyDeliverySecret(prisma, 'wrong-delivery-worker-secret-at-least-32-bytes'),
      /does not match/
    );
    assert.equal(await prisma.deliveryIntent.count({ where: { condominioId, attempts: { gt: 0 } } }), 0);

    await Promise.all([
      runDeliveryBatch({ client: prisma, provider, secret, workerId: 'worker-a', config, random: () => 0.5 }),
      runDeliveryBatch({ client: prisma, provider, secret, workerId: 'worker-b', config, random: () => 0.5 })
    ]);
    await assert.rejects(
      runDeliveryBatch({
        client: prisma, provider, secret, workerId: 'mismatched-policy',
        config: { ...config, maxAttempts: config.maxAttempts + 1 }
      }),
      /attempt policy does not match/
    );
    assert.equal(calls.get(intentIds[0]!), 1);
    assert.equal(calls.get(intentIds[1]!), 1);
    assert.equal((await prisma.deliveryIntent.findUniqueOrThrow({ where: { id: intentIds[2] } })).status, 'retry');
    const permanent = await prisma.deliveryIntent.findUniqueOrThrow({ where: { id: intentIds[3] } });
    assert.equal(permanent.status, 'dead_letter');
    assert.equal(permanent.lastError, 'provider_permanent');

    await prisma.deliveryIntent.update({ where: { id: intentIds[2] }, data: { nextAttemptAt: new Date(0) } });
    await runDeliveryBatch({ client: prisma, provider, secret, workerId: 'worker-retry', config, random: () => 0.5 });
    assert.equal((await prisma.deliveryIntent.findUniqueOrThrow({ where: { id: intentIds[2] } })).status, 'delivered');
    assert.equal(calls.get(intentIds[2]!), 2);

    await prisma.deliveryIntent.update({ where: { id: intentIds[4] }, data: { nextAttemptAt: new Date(0) } });
    const crashed = await claimDeliveries(prisma, { workerId: 'crashed', batchSize: 1, leaseMs: 5_000, maxAttempts: 3 });
    assert.equal(crashed[0]?.id, intentIds[4]);
    await prisma.deliveryIntent.update({ where: { id: intentIds[4] }, data: { leaseExpiresAt: new Date(0) } });
    await runDeliveryBatch({ client: prisma, provider, secret, workerId: 'recovery', config, random: () => 0.5 });
    assert.equal(calls.get(intentIds[4]!), 1);

    await prisma.deliveryIntent.update({ where: { id: intentIds[5] }, data: { nextAttemptAt: new Date(0) } });
    const oldClaim = (await claimDeliveries(prisma, { workerId: 'reused-owner', batchSize: 1, leaseMs: 5_000, maxAttempts: 3 }))[0]!;
    await prisma.deliveryIntent.update({ where: { id: intentIds[5] }, data: { leaseExpiresAt: new Date(0) } });
    const newClaim = (await claimDeliveries(prisma, { workerId: 'reused-owner', batchSize: 1, leaseMs: 5_000, maxAttempts: 3 }))[0]!;
    assert.notEqual(oldClaim.leaseToken, newClaim.leaseToken);
    assert.equal(await completeDelivery(prisma, oldClaim), false);
    assert.equal(await completeDelivery(prisma, newClaim), true);

    await prisma.deliveryIntent.update({ where: { id: intentIds[6] }, data: { nextAttemptAt: new Date(0) } });
    let release!: () => void;
    let entered!: () => void;
    const blocked = new Promise<void>((resolve) => { release = resolve; });
    const providerEntered = new Promise<void>((resolve) => { entered = resolve; });
    const slowRun = runDeliveryBatch({
      client: prisma,
      secret,
      workerId: 'slow-worker',
      config,
      provider: { supportsIdempotency: true, async send() { entered(); await blocked; } }
    });
    await providerEntered;
    await Promise.race([
      prisma.deliveryIntent.update({ where: { id: intentIds[6] }, data: { nextAttemptAt: new Date() } }),
      new Promise((_, reject) => setTimeout(() => reject(new Error('row lock remained open during provider I/O')), 500))
    ]);
    release();
    await slowRun;

    await prisma.deliveryIntent.updateMany({
      where: { id: { in: [intentIds[7]!, intentIds[8]!] } },
      data: { nextAttemptAt: new Date(0) }
    });
    let releaseHeartbeat!: () => void;
    let heartbeatEntered!: () => void;
    const heartbeatBlocked = new Promise<void>((resolve) => { releaseHeartbeat = resolve; });
    const heartbeatProviderEntered = new Promise<void>((resolve) => { heartbeatEntered = resolve; });
    const heartbeatCalls: string[] = [];
    const heartbeatConfig = { ...config, batchSize: 2, concurrency: 1, leaseMs: 1_000 };
    const heartbeatRun = runDeliveryBatch({
      client: prisma,
      secret,
      workerId: 'heartbeat-worker',
      config: heartbeatConfig,
      provider: {
        supportsIdempotency: true,
        async send({ idempotencyKey }) {
          heartbeatCalls.push(idempotencyKey);
          if (heartbeatCalls.length === 1) {
            heartbeatEntered();
            await heartbeatBlocked;
          }
        }
      }
    });
    await heartbeatProviderEntered;
    await new Promise((resolve) => setTimeout(resolve, 1_100));
    assert.deepEqual(
      await claimDeliveries(prisma, { workerId: 'competing-worker', batchSize: 1, leaseMs: 1_000, maxAttempts: 3 }),
      [],
      'active and queued provider calls renew their leases and cannot be claimed by another replica'
    );
    releaseHeartbeat();
    await heartbeatRun;
    assert.equal((await prisma.deliveryIntent.findUniqueOrThrow({ where: { id: intentIds[7] } })).status, 'delivered');
    assert.equal((await prisma.deliveryIntent.findUniqueOrThrow({ where: { id: intentIds[8] } })).status, 'delivered');
    assert.deepEqual(heartbeatCalls.sort(), [intentIds[7]!, intentIds[8]!].sort());

    await prisma.deliveryIntent.update({
      where: { id: intentIds[9] },
      data: { status: 'retry', attempts: config.maxAttempts - 1, lastError: 'provider_transient', nextAttemptAt: new Date(0) }
    });
    const finalAttemptCrash = (await claimDeliveries(prisma, {
      workerId: 'final-attempt-crash', batchSize: 1, leaseMs: 1_000, maxAttempts: config.maxAttempts
    }))[0]!;
    assert.equal(finalAttemptCrash.attempts, config.maxAttempts - 1, 'claiming does not consume an attempt before provider outcome');
    await prisma.deliveryIntent.update({ where: { id: intentIds[9] }, data: { leaseExpiresAt: new Date(0) } });
    const recoveredFinalAttempt = (await claimDeliveries(prisma, {
      workerId: 'final-attempt-recovery', batchSize: 1, leaseMs: 1_000, maxAttempts: config.maxAttempts
    }))[0]!;
    assert.equal(recoveredFinalAttempt.id, intentIds[9]);
    assert.equal(recoveredFinalAttempt.attempts, config.maxAttempts - 1);
    assert.equal(await completeDelivery(prisma, recoveredFinalAttempt), true);

    await prisma.deliveryIntent.update({
      where: { id: intentIds[10] },
      data: {
        status: 'processing', attempts: config.maxAttempts, leaseOwner: 'crashed-final-attempt',
        leaseToken: uuid(900), leaseExpiresAt: new Date(0), nextAttemptAt: new Date(0)
      }
    });
    assert.deepEqual(
      await claimDeliveries(prisma, { workerId: 'exhaustion-sweeper', batchSize: 1, leaseMs: 1_000, maxAttempts: 3 }),
      []
    );
    const exhausted = await prisma.deliveryIntent.findUniqueOrThrow({ where: { id: intentIds[10] } });
    assert.equal(exhausted.status, 'dead_letter');
    assert.equal(exhausted.lastError, 'attempts_exhausted');
    assert.equal(calls.get(intentIds[10]!), undefined);

    await prisma.deliveryIntent.updateMany({
      where: { id: { in: [intentIds[11]!, intentIds[12]!] } },
      data: { nextAttemptAt: new Date(0) }
    });
    let releaseLostLease!: () => void;
    let lostLeaseEntered!: () => void;
    const lostLeaseBlocked = new Promise<void>((resolve) => { releaseLostLease = resolve; });
    const lostLeaseProviderEntered = new Promise<void>((resolve) => { lostLeaseEntered = resolve; });
    const lostLeaseCalls: string[] = [];
    const lostLeaseRun = runDeliveryBatch({
      client: prisma,
      secret,
      workerId: 'lease-loss-worker',
      config: heartbeatConfig,
      provider: {
        supportsIdempotency: true,
        async send({ idempotencyKey }) {
          lostLeaseCalls.push(idempotencyKey);
          if (lostLeaseCalls.length === 1) {
            lostLeaseEntered();
            await lostLeaseBlocked;
          }
        }
      }
    });
    await lostLeaseProviderEntered;
    await prisma.deliveryIntent.update({ where: { id: intentIds[12] }, data: { leaseToken: uuid(901) } });
    await new Promise((resolve) => setTimeout(resolve, 400));
    releaseLostLease();
    await lostLeaseRun;
    assert.deepEqual(lostLeaseCalls, [intentIds[11]], 'a queued claim known to have lost its fence is never sent');
    await prisma.deliveryIntent.update({
      where: { id: intentIds[12] },
      data: {
        status: 'dead_letter', attempts: 1, lastError: 'provider_transient',
        leaseOwner: null, leaseToken: null, leaseExpiresAt: null
      }
    });

    await prisma.deliveryIntent.update({ where: { id: intentIds[13] }, data: { nextAttemptAt: new Date(0) } });
    await runDeliveryBatch({
      client: prisma,
      secret,
      workerId: 'timeout-worker',
      config: { ...config, batchSize: 1, concurrency: 1, providerTimeoutMs: 1_000 },
      provider: { supportsIdempotency: true, async send() { await new Promise(() => {}); } }
    });
    const timedOut = await prisma.deliveryIntent.findUniqueOrThrow({ where: { id: intentIds[13] } });
    assert.equal(timedOut.status, 'retry');
    assert.equal(timedOut.lastError, 'provider_timeout');

    await prisma.deliveryIntent.update({ where: { id: intentIds[14] }, data: { nextAttemptAt: new Date(0) } });
    const shutdown = new AbortController();
    shutdown.abort();
    let shutdownProviderCalls = 0;
    const shutdownResult = await runDeliveryBatch({
      client: prisma,
      secret,
      workerId: 'shutdown-worker',
      config: { ...config, batchSize: 1, concurrency: 1 },
      shutdownSignal: shutdown.signal,
      provider: {
        supportsIdempotency: true,
        async send() { shutdownProviderCalls++; }
      }
    });
    assert.equal(shutdownResult.deferred, 1);
    assert.equal(shutdownProviderCalls, 0);
    assert.equal((await prisma.deliveryIntent.findUniqueOrThrow({ where: { id: intentIds[14] } })).status, 'processing');

    const serialized = JSON.stringify(await prisma.deliveryIntent.findMany({ where: { condominioId } }));
    for (const sensitive of ['first@example.test', 'Secret token 123456', 'sensitive provider detail']) {
      assert.equal(serialized.includes(sensitive), false);
    }
  } finally {
    await prisma.deliveryIntent.deleteMany({ where: { condominioId } });
    await prisma.convite.deleteMany({ where: { condominioId } });
    await prisma.condominio.deleteMany({ where: { id: condominioId } });
    if (previousSecurityKey) {
      await prisma.securityKey.upsert({
        where: { name: previousSecurityKey.name },
        create: previousSecurityKey,
        update: { fingerprint: previousSecurityKey.fingerprint }
      });
    } else {
      await prisma.securityKey.deleteMany({ where: { name: 'idempotency-cache-v1' } });
    }
    if (previousDeliveryPolicy) {
      await prisma.securityKey.upsert({
        where: { name: previousDeliveryPolicy.name },
        create: previousDeliveryPolicy,
        update: { fingerprint: previousDeliveryPolicy.fingerprint }
      });
    } else {
      await prisma.securityKey.deleteMany({ where: { name: 'delivery-worker-policy-v1' } });
    }
    await prisma.$disconnect();
  }
});
