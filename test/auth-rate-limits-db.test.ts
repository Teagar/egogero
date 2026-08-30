import assert from 'node:assert/strict';
import { createHash, randomBytes, randomUUID } from 'node:crypto';
import test from 'node:test';

import { PrismaClient } from '@prisma/client';

import { createPrismaAuthRateLimiter } from '../src/auth-rate-limits.js';
import { createApp } from '../src/app.js';
import { createAuthTestCollectors } from '../src/auth-observability.js';
import { createBrowserSessionService, generateSessionToken, SESSION_COOKIE_NAME } from '../src/sessions.js';
import type { BrowserSessionStore } from '../src/sessions.js';

const runDatabaseTests = process.env.RUN_DATABASE_TESTS === 'true' && Boolean(process.env.DATABASE_URL);

test('limiter checks use the supplied interactive transaction client', async () => {
  let transactionQueries = 0;
  const root = {
    async $queryRaw() { throw new Error('root client must not be used'); }
  } as unknown as PrismaClient;
  const transaction = {
    async $queryRaw() {
      transactionQueries += 1;
      return [{ allowed: true, retryAfterSeconds: 0, deniedCount: 0 }];
    }
  } as unknown as Parameters<Parameters<PrismaClient['$transaction']>[0]>[0];
  const decision = await createPrismaAuthRateLimiter(root).check(
    'session_creation_account', randomUUID(), true, transaction
  );
  assert.equal(decision.allowed, true);
  assert.equal(transactionQueries, 1);
});

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
    const reservationIndexes = await client.$queryRaw<Array<{ indexname: string }>>`
      SELECT indexname FROM pg_indexes WHERE tablename = 'AuthenticationRateLimitReservation'
    `;
    assert.ok(reservationIndexes.some((index) => index.indexname === 'AuthenticationRateLimitReservation_expiresAt_idx'));
  } finally {
    await client.authenticationRateLimit.deleteMany({ where: { subject } });
    await client.$disconnect();
  }
});

test('callback exchange reservations are exact across stores and successful callbacks release their budget', { skip: !runDatabaseTests }, async () => {
  const firstClient = new PrismaClient();
  const secondClient = new PrismaClient();
  const first = createPrismaAuthRateLimiter(firstClient);
  const second = createPrismaAuthRateLimiter(secondClient);
  const concurrentSubject = `2001:db8:${randomUUID()}::/64`;
  const successSubject = `198.51.100.0/24-${randomUUID()}`;
  const failureSubject = `203.0.113.0/24-${randomUUID()}`;
  try {
    const concurrent = await Promise.all(Array.from({ length: 16 }, (_, index) =>
      (index % 2 ? first : second).reserve('callback_failure_ip', concurrentSubject)
    ));
    assert.equal(concurrent.filter((decision) => decision.allowed).length, 10);
    await Promise.all(concurrent.flatMap((decision, index) => decision.reservationId
      ? [(index % 2 ? first : second).finalize(decision.reservationId, 'release')]
      : []));
    assert.deepEqual(await firstClient.authenticationRateLimit.findUniqueOrThrow({
      where: { action_subject: { action: 'callback_failure_ip', subject: concurrentSubject } },
      select: { count: true, reservedCount: true }
    }), { count: 0, reservedCount: 0 });

    for (let index = 0; index < 25; index += 1) {
      const reservation = await (index % 2 ? first : second).reserve('callback_failure_ip', successSubject);
      assert.equal(reservation.allowed, true, 'successful callbacks must not consume the failure budget');
      await (index % 2 ? second : first).finalize(reservation.reservationId!, 'release');
    }
    assert.deepEqual(await firstClient.authenticationRateLimit.findUniqueOrThrow({
      where: { action_subject: { action: 'callback_failure_ip', subject: successSubject } },
      select: { count: true, reservedCount: true }
    }), { count: 0, reservedCount: 0 });

    for (let index = 0; index < 10; index += 1) {
      const reservation = await (index % 2 ? first : second).reserve('callback_failure_ip', failureSubject);
      assert.equal(reservation.allowed, true);
      await (index % 2 ? second : first).finalize(reservation.reservationId!, 'consume');
    }
    assert.equal((await first.reserve('callback_failure_ip', failureSubject)).allowed, false);
    assert.deepEqual(await firstClient.authenticationRateLimit.findUniqueOrThrow({
      where: { action_subject: { action: 'callback_failure_ip', subject: failureSubject } },
      select: { count: true, reservedCount: true }
    }), { count: 10, reservedCount: 0 });
  } finally {
    await firstClient.authenticationRateLimit.deleteMany({
      where: { subject: { in: [concurrentSubject, successSubject, failureSubject] } }
    });
    await Promise.all([firstClient.$disconnect(), secondClient.$disconnect()]);
  }
});

test('administrative invitation limits serialize both dimensions across services without denied OIDC mutation', { skip: !runDatabaseTests }, async () => {
  const firstClient = new PrismaClient();
  const secondClient = new PrismaClient();
  const telemetry = createAuthTestCollectors();
  const token = randomBytes(32).toString('base64url');
  const tokenDigest = createHash('sha256').update(token).digest('hex');
  let loginTransactions = 0;
  const browserStore = {
    publicApplicationOrigin: 'https://app.example.test',
    async issueFromHandoff() { return null; },
    async authenticate() { return null; },
    async inspect() { return null; },
    async isRevoked() { return false; },
    async rotate() { return { status: 'denied' as const }; },
    async revoke() { return 'unavailable' as const; },
    async revokeAll() { return 'unavailable' as const; },
    async recordAmbiguousCredentials() {}
  } satisfies BrowserSessionStore;
  const oidcService = {
    failurePath: '/auth/error',
    async startLogin() {
      loginTransactions += 1;
      return new URL('https://identity.example.test/authorize');
    },
    async completeCallback() { throw new Error('unused'); }
  };
  const firstApp = createApp({
    oidcService, browserSessionStore: browserStore,
    authRateLimiter: createPrismaAuthRateLimiter(firstClient, telemetry.metricSink, telemetry.alertSink),
    testOnlyBypassHumanAuthRollout: true
  });
  const secondApp = createApp({
    oidcService, browserSessionStore: browserStore,
    authRateLimiter: createPrismaAuthRateLimiter(secondClient, telemetry.metricSink, telemetry.alertSink),
    testOnlyBypassHumanAuthRollout: true
  });
  const request = (index: number) => (index % 2 ? firstApp : secondApp).inject({
    method: 'POST', url: '/auth/invitations/accept',
    headers: { origin: browserStore.publicApplicationOrigin, 'content-type': 'application/json' },
    payload: { token }
  });
  try {
    await firstClient.authenticationRateLimit.deleteMany({
      where: { action: { in: ['invitation_acceptance_ip', 'invitation_acceptance_digest'] } }
    });
    const responses = await Promise.all(Array.from({ length: 12 }, (_, index) => request(index)));
    assert.equal(responses.filter((response) => response.statusCode === 200).length, 5);
    assert.equal(responses.filter((response) => response.statusCode === 429).length, 7);
    assert.ok(responses.filter((response) => response.statusCode === 429).every((response) =>
      response.json().error === 'authentication_temporarily_unavailable' && Number(response.headers['retry-after']) > 0
    ));
    assert.equal(loginTransactions, 5, 'denied attempts must not create an OIDC transaction');

    const buckets = await firstClient.authenticationRateLimit.findMany({
      where: { action: { in: ['invitation_acceptance_ip', 'invitation_acceptance_digest'] } },
      select: { action: true, subject: true, count: true, deniedCount: true, reservedCount: true }
    });
    assert.deepEqual(buckets.sort((left, right) => left.action.localeCompare(right.action)), [
      { action: 'invitation_acceptance_digest', subject: tokenDigest, count: 5, deniedCount: 5, reservedCount: 0 },
      { action: 'invitation_acceptance_ip', subject: '127.0.0.0/24', count: 10, deniedCount: 2, reservedCount: 0 }
    ]);
    assert.ok(buckets.every((bucket) => !bucket.subject.includes(token)));
    assert.ok(telemetry.alerts.filter((alert) => alert.type === 'rate_limit_repeated_excess').length >= 2);

    await firstClient.authenticationRateLimit.updateMany({
      where: { action: { in: ['invitation_acceptance_ip', 'invitation_acceptance_digest'] } },
      data: { windowStartedAt: new Date(Date.now() - 3_600_001), blockedUntil: null }
    });
    const afterBoundary = await request(0);
    assert.equal(afterBoundary.statusCode, 200, 'the first attempt strictly after the one-hour window is allowed');
    assert.equal(loginTransactions, 6);
  } finally {
    await Promise.all([firstApp.close(), secondApp.close()]);
    await firstClient.authenticationRateLimit.deleteMany({
      where: { action: { in: ['invitation_acceptance_ip', 'invitation_acceptance_digest'] } }
    });
    await Promise.all([firstClient.$disconnect(), secondClient.$disconnect()]);
  }
});

test('reservation finalization and cleanup are exactly once under races', { skip: !runDatabaseTests }, async () => {
  const firstClient = new PrismaClient();
  const secondClient = new PrismaClient();
  const subject = randomUUID();
  const first = createPrismaAuthRateLimiter(firstClient);
  const second = createPrismaAuthRateLimiter(secondClient);
  try {
    const reservation = await first.reserve('invitation_acceptance_digest', subject);
    assert.equal(reservation.allowed, true);
    await Promise.all(Array.from({ length: 12 }, (_, index) =>
      (index % 2 ? first : second).finalize(reservation.reservationId!, 'consume')
    ));
    assert.deepEqual(await firstClient.authenticationRateLimit.findUniqueOrThrow({
      where: { action_subject: { action: 'invitation_acceptance_digest', subject } },
      select: { count: true, reservedCount: true }
    }), { count: 1, reservedCount: 0 });

    const expiring = await second.reserve('invitation_acceptance_digest', subject);
    assert.equal(expiring.allowed, true);
    await firstClient.authenticationRateLimitReservation.update({
      where: { id: expiring.reservationId! }, data: { expiresAt: new Date(Date.now() - 1) }
    });
    assert.equal(await first.cleanup!(), 0);
    assert.equal(await firstClient.authenticationRateLimitReservation.count({ where: { subject } }), 0);
    assert.equal((await firstClient.authenticationRateLimit.findUniqueOrThrow({
      where: { action_subject: { action: 'invitation_acceptance_digest', subject } }
    })).reservedCount, 0);
  } finally {
    await firstClient.authenticationRateLimit.deleteMany({ where: { subject } });
    await Promise.all([firstClient.$disconnect(), secondClient.$disconnect()]);
  }
});

test('GET /auth/session shares its exact failure threshold across application instances', { skip: !runDatabaseTests }, async () => {
  const firstClient = new PrismaClient();
  const secondClient = new PrismaClient();
  const subject = '127.0.0.0/24';
  const auditCorrelationPrefix = `test-invalid-session-${randomUUID()}`;
  let auditSequence = 0;
  const store = {
    publicApplicationOrigin: 'https://app.example.test',
    async issueFromHandoff() { return null; },
    async authenticate() { return null; },
    async inspect() {
      await firstClient.authenticationAuditEvent.create({
        data: {
          eventType: 'session_authentication_denied',
          outcome: 'denied',
          actorType: 'anonymous',
          requestCorrelationId: `${auditCorrelationPrefix}-${auditSequence += 1}`,
          reasonCode: 'invalid_session'
        }
      });
      return null;
    },
    async isRevoked() { return false; },
    async rotate() { return { status: 'denied' as const }; },
    async revoke() { return 'unavailable' as const; },
    async revokeAll() { return 'unavailable' as const; },
    async recordAmbiguousCredentials() {}
  } satisfies BrowserSessionStore;
  const firstApp = createApp({
    browserSessionStore: store,
    browserSessionService: createBrowserSessionService(store),
    authRateLimiter: createPrismaAuthRateLimiter(firstClient),
    testOnlyBypassHumanAuthRollout: true
  });
  const secondApp = createApp({
    browserSessionStore: store,
    browserSessionService: createBrowserSessionService(store),
    authRateLimiter: createPrismaAuthRateLimiter(secondClient),
    testOnlyBypassHumanAuthRollout: true
  });
  try {
    await firstClient.authenticationRateLimit.deleteMany({
      where: { action: 'authentication_failure_ip', subject }
    });
    const nonexistentToken = generateSessionToken();
    const responses = await Promise.all(Array.from({ length: 70 }, (_, index) => {
      return (index % 2 ? firstApp : secondApp).inject({
        method: 'GET', url: '/auth/session', headers: { cookie: `${SESSION_COOKIE_NAME}=${nonexistentToken}` }
      });
    }));
    assert.ok(responses.every((response) => [401, 429].includes(response.statusCode)),
      JSON.stringify(responses.map((response) => ({ status: response.statusCode, body: response.body }))));
    assert.equal(responses.filter((response) => response.statusCode === 401).length, 60);
    assert.equal(responses.filter((response) => response.statusCode === 429).length, 10);
    assert.ok(responses.every((response) => ['authentication_required', 'authentication_temporarily_unavailable']
      .includes(response.json().error)));
    assert.ok(responses.filter((response) => response.statusCode === 429)
      .every((response) => Number(response.headers['retry-after']) > 0));
    assert.equal(await firstClient.authenticationAuditEvent.count({
      where: { requestCorrelationId: { startsWith: auditCorrelationPrefix } }
    }), 60,
      'requests denied by the reservation must not reach audit-producing session lookup');
  } finally {
    await Promise.all([firstApp.close(), secondApp.close()]);
    await firstClient.authenticationRateLimit.deleteMany({
      where: { action: 'authentication_failure_ip', subject }
    });
    await Promise.all([firstClient.$disconnect(), secondClient.$disconnect()]);
  }
});

test('PostgreSQL forbids simultaneous recovery and reauthentication intents in both handoff stages', { skip: !runDatabaseTests }, async () => {
  const client = new PrismaClient();
  const accountId = randomUUID();
  const identityId = randomUUID();
  const validTransactionId = randomUUID();
  const familyId = randomUUID();
  const transactionData = (id: string) => ({
    id,
    expiresAt: new Date(Date.now() + 600_000),
    stateDigest: randomBytes(32),
    nonceDigest: randomBytes(32),
    pkceVerifierCiphertext: randomBytes(43),
    pkceVerifierNonce: randomBytes(12),
    pkceVerifierAuthTag: randomBytes(16),
    pkceKeyVersion: 1,
    issuer: 'https://identity.example.test',
    clientId: 'intent-constraint-test',
    redirectUri: 'https://app.example.test/auth/callback',
    returnTo: '/'
  });
  try {
    await assert.rejects(client.oidcLoginTransaction.create({
      data: {
        ...transactionData(randomUUID()), recoveryIntent: true,
        reauthenticationIntent: true, reauthenticationFamilyId: familyId
      }
    }), /check constraint|intents_exclusive/i);
    await client.humanAccount.create({ data: { id: accountId, displayName: 'Intent constraint', status: 'active' } });
    await client.externalIdentity.create({
      data: { id: identityId, accountId, issuer: 'https://identity.example.test', subject: `intent-${accountId}` }
    });
    await client.oidcLoginTransaction.create({
      data: { ...transactionData(validTransactionId), recoveryIntent: true }
    });
    await assert.rejects(client.oidcValidatedHandoff.create({
      data: {
        id: randomUUID(), expiresAt: new Date(Date.now() + 300_000), handleDigest: randomBytes(32),
        loginTransactionId: validTransactionId, accountId, externalIdentityId: identityId,
        authenticatedAt: new Date(), recoveryIntent: true,
        reauthenticationIntent: true, reauthenticationFamilyId: familyId
      }
    }), /check constraint|intents_exclusive/i);
  } finally {
    await client.oidcValidatedHandoff.deleteMany({ where: { loginTransactionId: validTransactionId } });
    await client.oidcLoginTransaction.deleteMany({ where: { id: validTransactionId } });
    await client.externalIdentity.deleteMany({ where: { accountId } });
    await client.humanAccount.deleteMany({ where: { id: accountId } });
    await client.$disconnect();
  }
});
