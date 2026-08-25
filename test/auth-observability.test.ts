import assert from 'node:assert/strict';
import test from 'node:test';
import { randomUUID } from 'node:crypto';

import {
  createAuthTestCollectors,
  createStructuredAuthTelemetry,
  evaluateAuthAggregates,
  redactAuthData,
  registerAuthTelemetryLifecycle,
  safeAuthAlerts,
  safeAuthMetrics,
  type StructuredAuthTelemetryRecord
} from '../src/auth-observability.js';
import { normalizeIpPrefix, trustedProxyFromEnvironment } from '../src/client-ip.js';
import { createApp } from '../src/app.js';
import type { AuthRateLimiter } from '../src/auth-rate-limits.js';
import type { PrismaClient } from '@prisma/client';
import { createHumanAdministrationService } from '../src/human-administration.js';
import { createPrismaBrowserSessionStore, generateSessionToken } from '../src/sessions.js';
import { TEST_ONLY_ALLOW_ALL_HUMAN_AUTH_ROLLOUT } from '../src/human-auth-rollout.js';

test('IP minimization handles IPv4, mapped IPv4, and canonical IPv6 prefixes', () => {
  assert.equal(normalizeIpPrefix('192.0.2.129'), '192.0.2.0/24');
  assert.equal(normalizeIpPrefix('::ffff:192.0.2.129'), '192.0.2.0/24');
  assert.equal(normalizeIpPrefix('::ffff:c000:0281'), '192.0.2.0/24');
  assert.equal(normalizeIpPrefix('0:0:0:0:0:ffff:c000:281'), '192.0.2.0/24');
  assert.equal(normalizeIpPrefix('2001:0db8:abcd:1234:5678::1'), '2001:db8:abcd:1234::/64');
  assert.equal(normalizeIpPrefix('not-an-ip'), null);
  assert.equal(normalizeIpPrefix('999.0.0.1'), null);
});

test('proxy allowlists fail closed on malformed or broad semantic config', () => {
  assert.equal(trustedProxyFromEnvironment(undefined), false);
  assert.equal(trustedProxyFromEnvironment('127.0.0.1,10.0.0.0/8'), '127.0.0.1,10.0.0.0/8');
  for (const invalid of [
    ' true', 'true', '127.0.0.1, evil', '10.0.0.0/33', '::1/129', '0.0.0.0/0', '::/0', ''
  ]) {
    if (invalid === '') assert.equal(trustedProxyFromEnvironment(invalid), false);
    else assert.throws(() => trustedProxyFromEnvironment(invalid), /TRUST_PROXY/);
  }
});

test('Fastify only derives minimized forwarded IP through an explicitly trusted proxy', async () => {
  async function observed(trustProxy: false | string, forwarded: string) {
    let subject = '';
    const limiter: AuthRateLimiter = {
      async check(_action, value) {
        subject = value;
        return { allowed: false, retryAfterSeconds: 1, repeatedExcess: false };
      },
      async reserveFailure() { return { allowed: true, retryAfterSeconds: 0, repeatedExcess: false, reservationId: randomUUID() }; },
      async finalizeFailure() {}
    };
    const app = createApp({
      trustProxy,
      authRateLimiter: limiter,
      oidcService: {
        failurePath: '/auth/error',
        async startLogin() { throw new Error('must be rate limited first'); },
        async completeCallback() { throw new Error('unused'); }
      },
      testOnlyBypassHumanAuthRollout: true
    });
    const response = await app.inject({ method: 'GET', url: '/auth/login', headers: { 'x-forwarded-for': forwarded } });
    await app.close();
    assert.equal(response.statusCode, 429);
    return subject;
  }
  assert.equal(await observed(false, '198.51.100.77'), '127.0.0.0/24');
  assert.equal(await observed('127.0.0.1', '198.51.100.77'), '198.51.100.0/24');
  assert.equal(await observed('127.0.0.1', 'malformed, 198.51.100.77'), 'unknown');
});

test('recovery initiation is generic, marks recovery intent, and returns Retry-After on denial', async () => {
  let recovery = false;
  let attempts = 0;
  const app = createApp({
    authRateLimiter: {
      async check(action) {
        assert.equal(action, 'recovery_ip');
        attempts += 1;
        return { allowed: attempts <= 3, retryAfterSeconds: 60, repeatedExcess: attempts > 5 };
      },
      async reserveFailure() { return { allowed: true, retryAfterSeconds: 0, repeatedExcess: false, reservationId: randomUUID() }; },
      async finalizeFailure() {}
    },
    oidcService: {
      failurePath: '/auth/error',
      async startLogin(input) {
        recovery = input.recovery === true;
        return new URL('https://identity.example.test/authorize');
      },
      async completeCallback() { throw new Error('unused'); }
    },
    testOnlyBypassHumanAuthRollout: true,
    humanAdministrationService: createHumanAdministrationService({} as PrismaClient, {
      publicApplicationOrigin: 'https://app.example.test',
      recoveryUrl: 'https://identity.example.test/authorize',
      recoveryWebhookIssuers: new Set(['https://identity.example.test']),
      recoveryWebhookSecret: Buffer.alloc(32),
      mfaPolicy: {
        provedor: { amr: ['webauthn'], acr: [] },
        sindico: { amr: ['webauthn'], acr: [] },
        morador: { amr: ['webauthn'], acr: [] },
        portaria: { amr: ['webauthn'], acr: [] }
      }
    })
  });
  for (let index = 0; index < 3; index += 1) {
    const response = await app.inject({ method: 'GET', url: '/auth/recovery' });
    assert.equal(response.statusCode, 302);
    assert.equal(response.headers.location, 'https://identity.example.test/authorize');
  }
  assert.equal(recovery, true);
  const denied = await app.inject({ method: 'GET', url: '/auth/recovery' });
  assert.equal(denied.statusCode, 429);
  assert.equal(denied.headers['retry-after'], '60');
  assert.deepEqual(denied.json(), { error: 'authentication_temporarily_unavailable' });
  await app.close();
});

test('redaction recursively removes auth credentials and wrappers isolate sink failures', async () => {
  const canary = 'CANARY-RAW-AUTH-SECRET';
  const redacted = redactAuthData({
    safe: 'bounded',
    headers: { authorization: `Bearer ${canary}`, cookie: `session=${canary}` },
    nested: { sessionToken: canary, code: canary, ciphertext: canary, nonce: canary, authTag: canary },
    bytes: Buffer.from(canary)
  });
  assert.equal(JSON.stringify(redacted).includes(canary), false);

  const metrics = safeAuthMetrics({ increment() { throw new Error(canary); }, observe() { return Promise.reject(new Error(canary)); } });
  const alerts = safeAuthAlerts({ emit() { throw new Error(canary); } });
  assert.doesNotThrow(() => metrics.increment('auth_database_writes_total', { operation: 'session', outcome: 'success' }));
  assert.doesNotThrow(() => metrics.observe('auth_session_lookup_seconds', 0.01, { operation: 'inspect', outcome: 'hit' }));
  assert.doesNotThrow(() => alerts.emit('crypto_integrity_failure', { sessionToken: canary }));
  await new Promise((resolve) => setImmediate(resolve));
});

test('aggregate observer emits callback and session SLO alerts with bounded details', () => {
  const collectors = createAuthTestCollectors();
  evaluateAuthAggregates({
    callbackSuccess: 994,
    callbackFailure: 6,
    sessionLookupSeconds: Array.from({ length: 100 }, (_, index) => index < 94 ? 0.005 : 0.025)
  }, collectors.alertSink);
  assert.deepEqual(collectors.alerts.map((alert) => alert.type), [
    'oidc_callback_success_slo',
    'session_lookup_latency_slo'
  ]);
  assert.ok(collectors.alerts.every((alert) => !JSON.stringify(alert.details).match(/account|sessionId|ip|token/i)));
});

test('structured telemetry periodically evaluates bounded aggregates and stops with Fastify', async () => {
  const records: StructuredAuthTelemetryRecord[] = [];
  const telemetry = createStructuredAuthTelemetry((record) => records.push(record));
  const app = createApp();
  const timer = registerAuthTelemetryLifecycle(app, telemetry, 10);
  assert.equal(timer.hasRef(), false);
  for (let index = 0; index < 100; index += 1) {
    telemetry.metrics.increment('auth_oidc_callback_total', { outcome: 'failure', reason: 'validation' });
    telemetry.metrics.observe('auth_session_lookup_seconds', 0.025, { operation: 'inspect', outcome: 'miss' });
  }
  await new Promise((resolve) => setTimeout(resolve, 25));
  assert.ok(records.some((record) => record.event === 'auth_metrics'
    && record.counters.auth_oidc_callback_total === 100));
  assert.deepEqual(records.filter((record) => record.event === 'auth_alert').map((record) => record.type).sort(), [
    'oidc_callback_success_slo',
    'session_lookup_latency_slo'
  ]);
  await app.close();
  const afterClose = records.length;
  await new Promise((resolve) => setTimeout(resolve, 25));
  assert.equal(records.length, afterClose);
});

test('human authentication routes fail construction without the distributed limiter', async () => {
  const oidcService = {
    failurePath: '/auth/error',
    async startLogin() { return new URL('https://identity.example.test/authorize'); },
    async completeCallback() { throw new Error('unused'); }
  };
  assert.throws(() => createApp({ oidcService }), /require an AuthRateLimiter/);
  assert.throws(() => createApp({ oidcService, authRateLimiter: {
    async check() { return { allowed: true, retryAfterSeconds: 0, repeatedExcess: false }; },
    async reserveFailure() { return { allowed: true, retryAfterSeconds: 0, repeatedExcess: false,
      reservationId: randomUUID() }; },
    async finalizeFailure() {}
  } }), /require a HumanAuthRolloutService/);
  const deviceOnlyApp = createApp();
  await deviceOnlyApp.close();
});

test('session lookup metrics distinguish database failure from a credential miss', async () => {
  const collectors = createAuthTestCollectors();
  const rateLimiter: AuthRateLimiter = {
    async check() { return { allowed: true, retryAfterSeconds: 0, repeatedExcess: false }; },
    async reserveFailure() { return { allowed: true, retryAfterSeconds: 0, repeatedExcess: false, reservationId: randomUUID() }; },
    async finalizeFailure() {}
  };
  const failingClient = {
    async $transaction() { throw new Error('database unavailable'); }
  } as unknown as PrismaClient;
  const store = createPrismaBrowserSessionStore(failingClient, {
    currentCsrfKeyVersion: 1,
    csrfKeys: new Map([[1, Buffer.alloc(32, 1)]]),
    publicApplicationOrigin: 'https://app.example.test'
  }, { rateLimiter, metrics: collectors.metricSink, rolloutGate: TEST_ONLY_ALLOW_ALL_HUMAN_AUTH_ROLLOUT });
  assert.equal(await store.authenticate('malformed', 'miss'), null);
  await assert.rejects(store.authenticate(generateSessionToken(), 'failure'), /database unavailable/);
  const outcomes = collectors.metrics
    .filter((metric) => metric.name === 'auth_session_lookup_total')
    .map((metric) => metric.labels.outcome);
  assert.deepEqual(outcomes, ['miss', 'failure']);
});
