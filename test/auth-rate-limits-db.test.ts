import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import test from 'node:test';

import { PrismaClient } from '@prisma/client';

import { createPrismaAuthRateLimiter } from '../src/auth-rate-limits.js';

const runDatabaseTests = process.env.RUN_DATABASE_TESTS === 'true' && Boolean(process.env.DATABASE_URL);

test('PostgreSQL auth limits hold exact thresholds across independent stores and apply backoff', { skip: !runDatabaseTests }, async () => {
  const firstClient = new PrismaClient();
  const secondClient = new PrismaClient();
  const first = createPrismaAuthRateLimiter(firstClient);
  const second = createPrismaAuthRateLimiter(secondClient);
  const ip = `192.0.${Math.floor(Math.random() * 200)}.0/24-${randomUUID()}`;
  const account = randomUUID();
  try {
    const login = await Promise.all(Array.from({ length: 12 }, (_, index) =>
      (index % 2 ? first : second).check('login_ip', ip)
    ));
    assert.equal(login.filter((decision) => decision.allowed).length, 5);
    assert.ok(login.filter((decision) => !decision.allowed).every((decision) => decision.retryAfterSeconds > 0));

    const sessions = await Promise.all(Array.from({ length: 14 }, (_, index) =>
      (index % 2 ? first : second).check('session_creation_account', account)
    ));
    assert.equal(sessions.filter((decision) => decision.allowed).length, 10);
    const blocked = await first.check('session_creation_account', account, false);
    assert.equal(blocked.allowed, false);
    assert.ok(blocked.retryAfterSeconds >= 15 * 60);

    await firstClient.authenticationRateLimit.update({
      where: { action_subject: { action: 'login_ip', subject: ip } },
      data: { windowStartedAt: new Date(Date.now() - 11 * 60_000), blockedUntil: null }
    });
    assert.equal((await second.check('login_ip', ip)).allowed, true, 'an expired window must reset');
  } finally {
    await firstClient.authenticationRateLimit.deleteMany({ where: { subject: { in: [ip, account] } } });
    await Promise.all([firstClient.$disconnect(), secondClient.$disconnect()]);
  }
});

test('rate-limit cleanup is bounded by the updatedAt index', { skip: !runDatabaseTests }, async () => {
  const client = new PrismaClient();
  const limiter = createPrismaAuthRateLimiter(client);
  const subject = randomUUID();
  try {
    await limiter.check('recovery_ip', subject);
    await client.authenticationRateLimit.updateMany({
      where: { subject },
      data: { updatedAt: new Date(Date.now() - 25 * 60 * 60_000) }
    });
    assert.equal(await limiter.cleanup!(), 1);
    const indexes = await client.$queryRaw<Array<{ indexname: string }>>`
      SELECT indexname FROM pg_indexes WHERE tablename = 'AuthenticationRateLimit'
    `;
    assert.ok(indexes.some((index) => index.indexname === 'AuthenticationRateLimit_updatedAt_idx'));
  } finally {
    await client.authenticationRateLimit.deleteMany({ where: { subject } });
    await client.$disconnect();
  }
});
