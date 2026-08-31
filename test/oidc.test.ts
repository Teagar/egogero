import assert from 'node:assert/strict';
import { createHash, randomBytes, randomUUID } from 'node:crypto';
import test from 'node:test';

import { exportJWK, generateKeyPair, SignJWT } from 'jose';
import { PrismaClient } from '@prisma/client';

import { createApp } from '../src/app.js';
import {
  createOidcService as createProductionOidcService,
  OidcCallbackError,
  oidcConfigFromEnvironment
} from '../src/oidc.js';
import type { OidcLoginStore, OidcRuntimeConfig } from '../src/oidc.js';
import { createBrowserSessionService, generateSessionToken, SESSION_COOKIE_NAME } from '../src/sessions.js';
import type { BrowserSessionStore } from '../src/sessions.js';
import { createAuthTestCollectors } from '../src/auth-observability.js';
import { AuthRateLimitError } from '../src/oidc.js';
import type { AuthRateLimiter } from '../src/auth-rate-limits.js';
import { createPrismaAuthRateLimiter } from '../src/auth-rate-limits.js';
import { TEST_ONLY_ALLOW_ALL_HUMAN_AUTH_ROLLOUT } from '../src/human-auth-rollout.js';

type StoredTransaction = Parameters<OidcLoginStore['createTransaction']>[0] & { createdAt: Date; consumed: boolean };
const runDatabaseTests = process.env.RUN_DATABASE_TESTS === 'true' && Boolean(process.env.DATABASE_URL);
const pkceTestKeys = new Map([
  [1, createHash('sha256').update('oidc-test-pkce-key-one').digest()],
  [2, createHash('sha256').update('oidc-test-pkce-key-two').digest()],
  [3, createHash('sha256').update('oidc-test-pkce-key-three').digest()]
]);

const permissiveAuthRateLimiter = {
  async check() { return { allowed: true, retryAfterSeconds: 0, repeatedExcess: false }; },
  async reserve() { return { allowed: true, retryAfterSeconds: 0, repeatedExcess: false, reservationId: randomUUID() }; },
  async finalize() {}
} satisfies AuthRateLimiter;

function createOidcService(
  config: Parameters<typeof createProductionOidcService>[0],
  store: Parameters<typeof createProductionOidcService>[1],
  fetchImplementation: Parameters<typeof createProductionOidcService>[2],
  dependencies: Omit<Parameters<typeof createProductionOidcService>[3], 'rolloutGate'> = {}
) {
  return createProductionOidcService(config, store, fetchImplementation, {
    ...dependencies,
    rolloutGate: TEST_ONLY_ALLOW_ALL_HUMAN_AUTH_ROLLOUT
  });
}

function configuration(overrides: Partial<OidcRuntimeConfig> = {}): OidcRuntimeConfig {
  return {
    issuer: 'https://identity.example.test',
    authorizationEndpoint: 'https://identity.example.test/authorize',
    tokenEndpoint: 'https://identity.example.test/token',
    jwksUri: 'https://identity.example.test/jwks',
    clientId: 'egogero client!*',
    clientSecret: 'oidc client secret with !*() and thirty-two bytes',
    redirectUri: 'https://app.example.test/auth/callback',
    idTokenSigningAlgorithm: 'RS256',
    failurePath: '/auth/error',
    returnToPrefixes: ['/'],
    currentPkceKeyVersion: 2,
    pkceKeys: new Map([[1, pkceTestKeys.get(1)!], [2, pkceTestKeys.get(2)!]]),
    ...overrides
  };
}

function memoryStore() {
  const transactions = new Map<string, StoredTransaction>();
  const audits: Array<Parameters<OidcLoginStore['appendAudit']>[0]> = [];
  const handoffs = new Map<string, import('../src/oidc.js').ValidatedOidcIdentity>();
  let handoff: Parameters<OidcLoginStore['completeIdentity']>[0] | undefined;

  const store: OidcLoginStore = {
    async createTransaction(input) {
      transactions.set(input.stateDigest.toString('hex'), { ...input, createdAt: new Date(), consumed: false });
      audits.push(input.audit);
    },
    async consumeTransaction(stateDigest) {
      const transaction = transactions.get(stateDigest.toString('hex'));
      if (!transaction || transaction.consumed || transaction.expiresAt.getTime() <= Date.now()) return null;
      transaction.consumed = true;
      return transaction;
    },
    async completeIdentity(input) {
      handoff = input;
      audits.push(input.audit);
      const identity = {
        accountId: '5b64b4a4-575d-43aa-a9ed-d8bc3b22913d',
        externalIdentityId: '3efbed86-aa77-40f3-9121-5dc92f7a4938',
        issuer: input.issuer,
        subject: input.subject,
        authenticatedAt: input.authenticatedAt
      };
      handoffs.set(input.handoffDigest.toString('hex'), identity);
      return identity;
    },
    async consumeHandoff(handleDigest) {
      const key = handleDigest.toString('hex');
      const identity = handoffs.get(key) ?? null;
      handoffs.delete(key);
      return identity;
    },
    async appendAudit(input) {
      audits.push(input);
    }
  };
  return { store, transactions, audits, get handoff() { return handoff; } };
}

async function mockProvider(config: OidcRuntimeConfig) {
  const signing = await generateKeyPair('RS256', { extractable: true });
  const attacker = await generateKeyPair('RS256', { extractable: true });
  const rotated = await generateKeyPair('RS256', { extractable: true });
  const publicJwk = await exportJWK(signing.publicKey);
  Object.assign(publicJwk, { alg: 'RS256', kid: 'provider-key', use: 'sig' });
  const rotatedJwk = await exportJWK(rotated.publicKey);
  Object.assign(rotatedJwk, { alg: 'RS256', kid: 'rotated-key', use: 'sig' });

  let expectedNonce = '';
  let expectedChallenge = '';
  let tokenCalls = 0;
  let mode: 'valid' | 'audience' | 'azp' | 'expired' | 'future' | 'issuer' | 'missing_sub'
    | 'missing_auth_time' | 'multi_valid' | 'nbf' | 'nonce' | 'rotate_new' | 'rotate_same'
    | 'signature' | 'stale' | 'stale_auth_time' = 'valid';
  let metadataOverrides: Record<string, unknown> = {};
  let currentJwks = [publicJwk];
  let redirectToken = false;

  const fetchImplementation: typeof fetch = async (input, init) => {
    const url = String(input);
    if (url.endsWith('/.well-known/openid-configuration')) {
      return Response.json({
        issuer: config.issuer,
        authorization_endpoint: config.authorizationEndpoint,
        token_endpoint: config.tokenEndpoint,
        jwks_uri: config.jwksUri,
        response_types_supported: ['code'],
        grant_types_supported: ['authorization_code'],
        code_challenge_methods_supported: ['S256'],
        id_token_signing_alg_values_supported: ['RS256'],
        token_endpoint_auth_methods_supported: ['client_secret_basic'],
        response_modes_supported: ['query'],
        scopes_supported: ['openid', 'profile', 'email'],
        subject_types_supported: ['public'],
        ...metadataOverrides
      }, { headers: { 'content-type': 'application/json' } });
    }
    if (url === config.jwksUri) {
      return Response.json({ keys: currentJwks }, { headers: { 'content-type': 'application/json' } });
    }
    if (url === config.tokenEndpoint) {
      tokenCalls += 1;
      if (redirectToken) {
        return new Response(null, { status: 302, headers: { location: 'https://attacker.example/token' } });
      }
      const body = init?.body instanceof URLSearchParams
        ? init.body
        : new URLSearchParams(String(init?.body ?? ''));
      const verifier = body.get('code_verifier');
      assert.ok(verifier);
      assert.equal(createHash('sha256').update(verifier).digest('base64url'), expectedChallenge);
      const formEncode = (value: string) => new URLSearchParams({ value }).toString().slice('value='.length);
      assert.equal(
        new Headers(init?.headers).get('authorization'),
        `Basic ${Buffer.from(`${formEncode(config.clientId)}:${formEncode(config.clientSecret)}`).toString('base64')}`
      );

      const now = Math.floor(Date.now() / 1000);
      const issuer = mode === 'issuer' ? 'https://mix-up.example.test' : config.issuer;
      const audience = mode === 'audience'
        ? 'another-client'
        : ['azp', 'multi_valid'].includes(mode)
          ? [config.clientId, 'resource-audience']
          : config.clientId;
      const nonce = mode === 'nonce' ? 'wrong-nonce' : expectedNonce;
      const issuedAt = mode === 'future' ? now + 600 : mode === 'stale' ? now - 1_200 : now;
      const authenticationTime = mode === 'stale_auth_time' ? now - 1_200 : issuedAt;
      const expiresAt = mode === 'expired' ? now - 300 : now + 300;
      const privateKey = mode === 'signature'
        ? attacker.privateKey
        : ['rotate_new', 'rotate_same'].includes(mode)
          ? rotated.privateKey
          : signing.privateKey;
      const keyId = mode === 'rotate_new' ? 'rotated-key' : 'provider-key';
      if (mode === 'rotate_new') currentJwks = [rotatedJwk];
      if (mode === 'rotate_same') currentJwks = [{ ...rotatedJwk, kid: 'provider-key' }];
      let tokenBuilder = new SignJWT({
        nonce,
        ...(mode === 'missing_auth_time' ? {} : { auth_time: authenticationTime }),
        email: 'person@example.test',
        email_verified: true,
        ...(mode === 'azp' ? { azp: 'wrong-client' } : {}),
        ...(mode === 'multi_valid' ? { azp: config.clientId } : {}),
        ...(mode === 'nbf' ? { nbf: now + 300 } : {})
      })
        .setProtectedHeader({ alg: 'RS256', kid: keyId })
        .setIssuer(issuer)
        .setAudience(audience)
        .setIssuedAt(issuedAt)
        .setExpirationTime(expiresAt);
      if (mode !== 'missing_sub') tokenBuilder = tokenBuilder.setSubject('provider-subject');
      const idToken = await tokenBuilder.sign(privateKey);
      return Response.json({
        access_token: 'provider-access-token-canary',
        token_type: 'Bearer',
        expires_in: 300,
        id_token: idToken
      }, { headers: { 'content-type': 'application/json' } });
    }
    throw new Error(`unexpected OIDC URL: ${url}`);
  };

  return {
    fetchImplementation,
    prepare(authorizationUrl: URL) {
      expectedNonce = authorizationUrl.searchParams.get('nonce') ?? '';
      expectedChallenge = authorizationUrl.searchParams.get('code_challenge') ?? '';
    },
    set mode(value: typeof mode) { mode = value; },
    set metadata(value: Record<string, unknown>) { metadataOverrides = value; },
    set redirectToken(value: boolean) { redirectToken = value; },
    get tokenCalls() { return tokenCalls; }
  };
}

function callbackUrl(config: OidcRuntimeConfig, authorizationUrl: URL, code = 'authorization-code-canary') {
  const callback = new URL(config.redirectUri);
  callback.searchParams.set('code', code);
  callback.searchParams.set('state', authorizationUrl.searchParams.get('state')!);
  return callback;
}

test('OIDC environment is disabled by default and rejects incomplete or weak enabled configuration', () => {
  assert.equal(oidcConfigFromEnvironment({}), undefined);
  assert.equal(oidcConfigFromEnvironment({ HUMAN_AUTH_ENABLED: 'false' }), undefined);
  assert.throws(() => oidcConfigFromEnvironment({ HUMAN_AUTH_ENABLED: 'TRUE' }), /must be true or false/);
  assert.throws(() => oidcConfigFromEnvironment({ HUMAN_AUTH_ENABLED: 'true' }), /OIDC_ISSUER is required/);

  const key = randomBytes(32).toString('base64url');
  const base = {
    HUMAN_AUTH_ENABLED: 'true',
    OIDC_ISSUER: 'https://identity.example.test',
    OIDC_AUTHORIZATION_ENDPOINT: 'https://identity.example.test/authorize',
    OIDC_TOKEN_ENDPOINT: 'https://identity.example.test/token',
    OIDC_JWKS_URI: 'https://identity.example.test/jwks',
    OIDC_CLIENT_ID: 'client',
    OIDC_CLIENT_SECRET: 'oidc-client-secret-with-at-least-thirty-two-bytes',
    OIDC_REDIRECT_URI: 'https://app.example.test/auth/callback',
    OIDC_ID_TOKEN_SIGNING_ALG: 'RS256',
    OIDC_PKCE_KEYS: JSON.stringify({ 1: key }),
    OIDC_PKCE_CURRENT_KEY_VERSION: '1'
  };
  assert.equal(oidcConfigFromEnvironment(base)?.currentPkceKeyVersion, 1);
  assert.throws(
    () => oidcConfigFromEnvironment({ ...base, OIDC_CLIENT_SECRET: 'short' }),
    /at least 32 bytes/
  );
  assert.throws(
    () => oidcConfigFromEnvironment({ ...base, OIDC_PKCE_CURRENT_KEY_VERSION: '2' }),
    /must identify an active key/
  );
  assert.throws(
    () => oidcConfigFromEnvironment({ ...base, OIDC_ID_TOKEN_SIGNING_ALG: 'HS256' }),
    /not allowed/
  );
});

test('OIDC login stores only digests and AEAD material, validates a callback once, and creates no session cookie', async () => {
  const config = configuration();
  const database = memoryStore();
  const provider = await mockProvider(config);
  const telemetry = createAuthTestCollectors();
  const service = await createOidcService(config, database.store, provider.fetchImplementation, {
    metrics: telemetry.metricSink,
    alerts: telemetry.alertSink
  });

  const authorization = await service.startLogin({
    returnTo: '/dashboard?tab=entry',
    requestCorrelationId: 'request-login'
  });
  provider.prepare(authorization);
  assert.equal(authorization.origin + authorization.pathname, config.authorizationEndpoint);
  assert.equal(authorization.searchParams.get('response_type'), 'code');
  assert.equal(authorization.searchParams.get('code_challenge_method'), 'S256');
  assert.equal(authorization.searchParams.get('scope'), 'openid profile email');
  assert.equal(authorization.searchParams.get('max_age'), '0');
  assert.equal(authorization.searchParams.get('prompt'), null);
  assert.ok(authorization.searchParams.get('state'));
  assert.ok(authorization.searchParams.get('nonce'));

  const stored = [...database.transactions.values()][0]!;
  assert.equal(stored.stateDigest.length, 32);
  assert.equal(stored.nonceDigest.length, 32);
  assert.equal(stored.pkceVerifierNonce.length, 12);
  assert.equal(stored.pkceVerifierAuthTag.length, 16);
  assert.equal(stored.returnTo, '/dashboard?tab=entry');
  assert.equal('state' in stored, false);
  assert.equal('nonce' in stored, false);
  assert.equal('pkceVerifier' in stored, false);

  const app = createApp({ oidcService: service, authRateLimiter: permissiveAuthRateLimiter,
    testOnlyBypassHumanAuthRollout: true });
  const successful = await app.inject({
    method: 'GET',
    url: `/auth/callback?code=authorization-code-canary&state=${encodeURIComponent(authorization.searchParams.get('state')!)}`
  });
  assert.equal(successful.statusCode, 303);
  assert.equal(successful.headers.location, '/dashboard?tab=entry');
  assert.equal(successful.headers['cache-control'], 'no-store');
  const handoffCookie = String(successful.headers['set-cookie'] ?? '');
  assert.match(handoffCookie, /^__Host-eg_oidc_handoff=[A-Za-z0-9_-]{43}; Path=\/; HttpOnly; Secure; SameSite=Lax; Max-Age=300$/);
  assert.doesNotMatch(handoffCookie, /eg_session/);
  assert.equal(successful.headers['referrer-policy'], 'no-referrer');
  assert.equal(provider.tokenCalls, 1);
  assert.ok(telemetry.metrics.some((metric) => metric.name === 'auth_oidc_callback_total'
    && metric.labels.outcome === 'success'));
  assert.equal(database.handoff?.subject, 'provider-subject');

  const replay = await app.inject({
    method: 'GET',
    url: `/auth/callback?code=authorization-code-canary&state=${encodeURIComponent(authorization.searchParams.get('state')!)}`
  });
  assert.equal(replay.statusCode, 303);
  assert.equal(replay.headers.location, config.failurePath);
  assert.equal(
    replay.headers['set-cookie'],
    '__Host-eg_oidc_handoff=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0'
  );
  assert.equal(provider.tokenCalls, 1);
  assert.ok(telemetry.metrics.some((metric) => metric.name === 'auth_oidc_callback_total'
    && metric.labels.outcome === 'failure' && metric.labels.reason === 'state'));
  await app.close();
});

test('OIDC callback preserves state and performs no provider exchange after distributed denial', async () => {
  const config = configuration();
  const database = memoryStore();
  const provider = await mockProvider(config);
  const service = await createOidcService(config, database.store, provider.fetchImplementation, {
    rateLimiter: {
      async check(_action, _subject, consume = true) {
        return consume
          ? { allowed: true, retryAfterSeconds: 0, repeatedExcess: false }
          : { allowed: false, retryAfterSeconds: 30, repeatedExcess: true };
      },
      async reserve() {
        return { allowed: false, retryAfterSeconds: 30, repeatedExcess: true };
      },
      async finalize() {}
    }
  });
  const authorization = await service.startLogin({ requestCorrelationId: 'limited-login' });
  provider.prepare(authorization);
  await assert.rejects(
    service.completeCallback({
      callbackUrl: callbackUrl(config, authorization),
      requestCorrelationId: 'limited-callback',
      ipPrefix: '192.0.2.0/24'
    }),
    AuthRateLimitError
  );
  assert.equal(provider.tokenCalls, 0);
  const state = authorization.searchParams.get('state')!;
  assert.equal(database.transactions.get(createHash('sha256').update(state).digest('hex'))!.consumed, false);
});

test('OIDC callback denial stops immutable failure-audit growth at the distributed threshold', { skip: !runDatabaseTests }, async () => {
  const prisma = new PrismaClient();
  const config = configuration();
  const database = memoryStore();
  const provider = await mockProvider(config);
  const ipPrefix = `192.0.2.0/24-${randomUUID()}`;
  const correlationPrefix = `limited-invalid-state-${randomUUID()}`;
  database.store.appendAudit = async (input) => {
    await prisma.authenticationAuditEvent.create({
      data: {
        eventType: input.eventType,
        outcome: input.outcome,
        actorType: 'anonymous',
        requestCorrelationId: input.requestCorrelationId,
        reasonCode: input.reasonCode
      }
    });
  };
  try {
    const service = await createOidcService(config, database.store, provider.fetchImplementation, {
      rateLimiter: createPrismaAuthRateLimiter(prisma)
    });
    for (let index = 0; index < 15; index += 1) {
      await assert.rejects(service.completeCallback({
        callbackUrl: new URL(config.redirectUri),
        requestCorrelationId: `${correlationPrefix}-${index}`,
        ipPrefix
      }), index < 10 ? OidcCallbackError : AuthRateLimitError);
    }
    assert.equal(await prisma.authenticationAuditEvent.count({
      where: { requestCorrelationId: { startsWith: correlationPrefix } }
    }), 10);
  } finally {
    await prisma.authenticationRateLimit.deleteMany({ where: { subject: ipPrefix } });
    await prisma.$disconnect();
  }
});

test('OIDC callback finalizes exact exchange reservations as success or failure', async () => {
  const config = configuration();
  const database = memoryStore();
  const provider = await mockProvider(config);
  const finalized: Array<{ reservationId: string; outcome: 'consume' | 'release' }> = [];
  let sequence = 0;
  const service = await createOidcService(config, database.store, provider.fetchImplementation, {
    rateLimiter: {
      async check() { return { allowed: true, retryAfterSeconds: 0, repeatedExcess: false }; },
      async reserve() {
        sequence += 1;
        return { allowed: true, retryAfterSeconds: 0, repeatedExcess: false, reservationId: `reservation-${sequence}` };
      },
      async finalize(reservationId, outcome) { finalized.push({ reservationId, outcome }); }
    }
  });

  const successful = await service.startLogin({ requestCorrelationId: 'reserved-success' });
  provider.prepare(successful);
  await service.completeCallback({
    callbackUrl: callbackUrl(config, successful), requestCorrelationId: 'reserved-success-callback', ipPrefix: '192.0.2.0/24'
  });

  const failed = await service.startLogin({ requestCorrelationId: 'reserved-failure' });
  provider.prepare(failed);
  provider.mode = 'nonce';
  await assert.rejects(service.completeCallback({
    callbackUrl: callbackUrl(config, failed), requestCorrelationId: 'reserved-failure-callback', ipPrefix: '192.0.2.0/24'
  }), OidcCallbackError);
  assert.deepEqual(finalized, [
    { reservationId: 'reservation-1', outcome: 'release' },
    { reservationId: 'reservation-2', outcome: 'consume' }
  ]);
});

test('OIDC reauthentication persists trusted intent and requests fresh provider authentication', async () => {
  const config = configuration();
  const database = memoryStore();
  const provider = await mockProvider(config);
  const service = await createOidcService(config, database.store, provider.fetchImplementation);
  const familyId = randomUUID();
  const authorization = await service.startLogin({
    returnTo: '/settings', requestCorrelationId: 'reauthentication', reauthentication: true,
    reauthenticationFamilyId: familyId
  });
  assert.equal(authorization.searchParams.get('prompt'), 'login');
  assert.equal(authorization.searchParams.get('max_age'), '0');
  const transaction = [...database.transactions.values()][0]!;
  assert.equal(transaction.reauthenticationIntent, true);
  assert.equal(transaction.reauthenticationFamilyId, familyId);
  provider.prepare(authorization);
  await service.completeCallback({
    callbackUrl: callbackUrl(config, authorization), requestCorrelationId: 'reauthentication-callback'
  });
  assert.equal(database.handoff?.reauthenticationIntent, true);
  assert.equal(database.handoff?.reauthenticationFamilyId, familyId);
});

test('OIDC rejects unsafe return targets, corrupted AEAD, duplicate callbacks, and invalid ID-token claims generically', async () => {
  const config = configuration();
  const database = memoryStore();
  const provider = await mockProvider(config);
  const service = await createOidcService(config, database.store, provider.fetchImplementation);

  for (const unsafe of ['https://evil.example/', '//evil.example/', '/\\evil.example/', '/%5cevil', '/safe#fragment']) {
    const authorization = await service.startLogin({ returnTo: unsafe, requestCorrelationId: randomUUID() });
    const state = authorization.searchParams.get('state')!;
    const transaction = database.transactions.get(createHash('sha256').update(state).digest('hex'))!;
    assert.equal(transaction.returnTo, '/');
  }

  const corrupted = await service.startLogin({ returnTo: '/', requestCorrelationId: 'corrupt' });
  provider.prepare(corrupted);
  const corruptState = corrupted.searchParams.get('state')!;
  const corruptTransaction = database.transactions.get(createHash('sha256').update(corruptState).digest('hex'))!;
  corruptTransaction.pkceVerifierAuthTag = Buffer.alloc(16, 99);
  await assert.rejects(
    service.completeCallback({ callbackUrl: callbackUrl(config, corrupted), requestCorrelationId: 'corrupt-callback' }),
    OidcCallbackError
  );
  assert.equal(provider.tokenCalls, 0);

  for (const field of ['pkceVerifierCiphertext', 'pkceVerifierNonce'] as const) {
    const authorization = await service.startLogin({ returnTo: '/', requestCorrelationId: `corrupt-${field}` });
    provider.prepare(authorization);
    const state = authorization.searchParams.get('state')!;
    const transaction = database.transactions.get(createHash('sha256').update(state).digest('hex'))!;
    transaction[field][0] ^= 1;
    await assert.rejects(
      service.completeCallback({ callbackUrl: callbackUrl(config, authorization), requestCorrelationId: `callback-${field}` }),
      OidcCallbackError
    );
  }
  const aadTampered = await service.startLogin({ returnTo: '/', requestCorrelationId: 'corrupt-aad' });
  provider.prepare(aadTampered);
  const aadState = aadTampered.searchParams.get('state')!;
  database.transactions.get(createHash('sha256').update(aadState).digest('hex'))!.id = randomUUID();
  await assert.rejects(
    service.completeCallback({ callbackUrl: callbackUrl(config, aadTampered), requestCorrelationId: 'corrupt-aad' }),
    OidcCallbackError
  );
  assert.equal(provider.tokenCalls, 0);

  const duplicate = await service.startLogin({ returnTo: '/', requestCorrelationId: 'duplicate-parameters' });
  provider.prepare(duplicate);
  const duplicateCallback = callbackUrl(config, duplicate);
  duplicateCallback.searchParams.append('code', 'second-code');
  await assert.rejects(
    service.completeCallback({ callbackUrl: duplicateCallback, requestCorrelationId: 'duplicate-parameters' }),
    OidcCallbackError
  );
  assert.equal(provider.tokenCalls, 0);

  for (const mode of [
    'nonce', 'audience', 'azp', 'issuer', 'expired', 'future', 'missing_sub', 'missing_auth_time',
    'nbf', 'signature', 'stale', 'stale_auth_time'
  ] as const) {
    const authorization = await service.startLogin({ returnTo: '/', requestCorrelationId: `login-${mode}` });
    provider.prepare(authorization);
    provider.mode = mode;
    await assert.rejects(
      service.completeCallback({ callbackUrl: callbackUrl(config, authorization), requestCorrelationId: `callback-${mode}` }),
      OidcCallbackError
    );
  }
  assert.ok(database.audits.every((audit) => !JSON.stringify(audit).includes('authorization-code-canary')));
  assert.ok(database.audits.every((audit) => !JSON.stringify(audit).includes('provider-access-token-canary')));
});

test('OIDC accepts valid multiple audiences and controlled JWKS rotations', async () => {
  for (const mode of ['multi_valid', 'rotate_new', 'rotate_same'] as const) {
    const config = configuration();
    const database = memoryStore();
    const provider = await mockProvider(config);
    const service = await createOidcService(config, database.store, provider.fetchImplementation);
    const authorization = await service.startLogin({ returnTo: '/', requestCorrelationId: `login-${mode}` });
    provider.prepare(authorization);
    provider.mode = mode;
    await service.completeCallback({
      callbackUrl: callbackUrl(config, authorization),
      requestCorrelationId: `callback-${mode}`
    });
    assert.equal(provider.tokenCalls, 1);
  }
});

test('OIDC enforces the authorization-response issuer parameter when configured', async () => {
  const config = configuration();
  const database = memoryStore();
  const provider = await mockProvider(config);
  provider.metadata = { authorization_response_iss_parameter_supported: true };
  const service = await createOidcService(config, database.store, provider.fetchImplementation);

  const missing = await service.startLogin({ returnTo: '/', requestCorrelationId: 'missing-response-issuer' });
  provider.prepare(missing);
  await assert.rejects(
    service.completeCallback({ callbackUrl: callbackUrl(config, missing), requestCorrelationId: 'missing-response-issuer' }),
    OidcCallbackError
  );
  assert.equal(provider.tokenCalls, 0);

  const wrong = await service.startLogin({ returnTo: '/', requestCorrelationId: 'wrong-response-issuer' });
  provider.prepare(wrong);
  const wrongCallback = callbackUrl(config, wrong);
  wrongCallback.searchParams.set('iss', 'https://attacker.example');
  await assert.rejects(
    service.completeCallback({ callbackUrl: wrongCallback, requestCorrelationId: 'wrong-response-issuer' }),
    OidcCallbackError
  );

  const duplicate = await service.startLogin({ returnTo: '/', requestCorrelationId: 'duplicate-response-issuer' });
  provider.prepare(duplicate);
  const duplicateCallback = callbackUrl(config, duplicate);
  duplicateCallback.searchParams.append('iss', config.issuer);
  duplicateCallback.searchParams.append('iss', config.issuer);
  await assert.rejects(
    service.completeCallback({ callbackUrl: duplicateCallback, requestCorrelationId: 'duplicate-response-issuer' }),
    OidcCallbackError
  );
  assert.equal(provider.tokenCalls, 0);

  const valid = await service.startLogin({ returnTo: '/', requestCorrelationId: 'valid-response-issuer' });
  provider.prepare(valid);
  const validCallback = callbackUrl(config, valid);
  validCallback.searchParams.set('iss', config.issuer);
  await service.completeCallback({ callbackUrl: validCallback, requestCorrelationId: 'valid-response-issuer' });
  assert.equal(provider.tokenCalls, 1);
});

test('rotation rehearsal persists PKCE material, emits current, reads overlap, and fails closed after removal', async () => {
  const firstConfig = configuration({ currentPkceKeyVersion: 1 });
  const database = memoryStore();
  const provider = await mockProvider(firstConfig);
  const firstService = await createOidcService(firstConfig, database.store, provider.fetchImplementation);
  const authorization = await firstService.startLogin({ returnTo: '/', requestCorrelationId: 'old-key-login' });
  provider.prepare(authorization);

  const rotatedService = await createOidcService(
    configuration({ currentPkceKeyVersion: 2 }),
    database.store,
    provider.fetchImplementation
  );
  await rotatedService.completeCallback({
    callbackUrl: callbackUrl(firstConfig, authorization),
    requestCorrelationId: 'old-key-callback'
  });
  assert.equal(provider.tokenCalls, 1);

  const currentEmission = await rotatedService.startLogin({ returnTo: '/', requestCorrelationId: 'current-key-login' });
  const currentState = currentEmission.searchParams.get('state')!;
  assert.equal(database.transactions.get(createHash('sha256').update(currentState).digest('hex'))!.pkceKeyVersion, 2);

  const retirementCandidate = await firstService.startLogin({ returnTo: '/', requestCorrelationId: 'retired-key-login' });
  provider.prepare(retirementCandidate);
  const retiredService = await createOidcService(
    configuration({ currentPkceKeyVersion: 2, pkceKeys: new Map([[2, pkceTestKeys.get(2)!]]) }),
    database.store,
    provider.fetchImplementation
  );
  await assert.rejects(
    retiredService.completeCallback({
      callbackUrl: callbackUrl(firstConfig, retirementCandidate), requestCorrelationId: 'retired-key-callback'
    }),
    OidcCallbackError
  );
  assert.equal(provider.tokenCalls, 1);

  const compromisedCandidate = await rotatedService.startLogin({ returnTo: '/', requestCorrelationId: 'compromised-key-login' });
  provider.prepare(compromisedCandidate);
  const replacementConfig = configuration({
    currentPkceKeyVersion: 3,
    pkceKeys: new Map([[3, pkceTestKeys.get(3)!]])
  });
  const replacementService = await createOidcService(
    replacementConfig, database.store, provider.fetchImplementation
  );
  await assert.rejects(
    replacementService.completeCallback({
      callbackUrl: callbackUrl(firstConfig, compromisedCandidate), requestCorrelationId: 'compromised-key-callback'
    }),
    OidcCallbackError
  );
  const replacementEmission = await replacementService.startLogin({
    returnTo: '/', requestCorrelationId: 'replacement-key-login'
  });
  assert.equal(
    database.transactions.get(createHash('sha256').update(replacementEmission.searchParams.get('state')!).digest('hex'))!.pkceKeyVersion,
    3
  );

  const unknown = await rotatedService.startLogin({ returnTo: '/', requestCorrelationId: 'unknown-key-login' });
  provider.prepare(unknown);
  const state = unknown.searchParams.get('state')!;
  database.transactions.get(createHash('sha256').update(state).digest('hex'))!.pkceKeyVersion = 999;
  await assert.rejects(
    rotatedService.completeCallback({ callbackUrl: callbackUrl(firstConfig, unknown), requestCorrelationId: 'unknown-key-callback' }),
    OidcCallbackError
  );
  assert.equal(provider.tokenCalls, 1);
});

test('OIDC startup fails closed on metadata drift and never follows redirects', async () => {
  const config = configuration();
  const database = memoryStore();
  const provider = await mockProvider(config);
  provider.metadata = { token_endpoint: 'https://attacker.example/token' };
  const telemetry = createAuthTestCollectors();
  await assert.rejects(
    createOidcService(config, database.store, provider.fetchImplementation, { alerts: telemetry.alertSink }),
    /OIDC initialization failed/
  );
  assert.deepEqual(telemetry.alerts.map((alert) => alert.type), [
    'provider_configuration_drift', 'crypto_key_failure'
  ]);

  const redirectingFetch: typeof fetch = async () => new Response(null, {
    status: 302,
    headers: { location: 'https://attacker.example/' }
  });
  await assert.rejects(
    createOidcService(config, database.store, redirectingFetch),
    /OIDC initialization failed/
  );

  const missingCapabilities = await mockProvider(config);
  missingCapabilities.metadata = { subject_types_supported: [] };
  await assert.rejects(
    createOidcService(config, database.store, missingCapabilities.fetchImplementation),
    /OIDC initialization failed/
  );

  let pulls = 0;
  const oversizedFetch: typeof fetch = async () => new Response(new ReadableStream({
    pull(controller) {
      pulls += 1;
      controller.enqueue(new Uint8Array(65_536));
    }
  }), { headers: { 'content-type': 'application/json' } });
  await assert.rejects(createOidcService(config, database.store, oversizedFetch), /OIDC initialization failed/);
  assert.ok(pulls < 100);

  const tokenRedirectProvider = await mockProvider(config);
  const service = await createOidcService(config, database.store, tokenRedirectProvider.fetchImplementation);
  const authorization = await service.startLogin({ returnTo: '/', requestCorrelationId: 'token-redirect' });
  tokenRedirectProvider.prepare(authorization);
  tokenRedirectProvider.redirectToken = true;
  await assert.rejects(
    service.completeCallback({ callbackUrl: callbackUrl(config, authorization), requestCorrelationId: 'token-redirect' }),
    OidcCallbackError
  );
});

test('OIDC callback converts its one-time handoff into the final browser session', async () => {
  const handoffToken = generateSessionToken();
  const oldSessionToken = generateSessionToken();
  const sessionToken = generateSessionToken();
  let suppliedOldSession: string | undefined;
  let ambiguousAudits = 0;
  const sessionStore = {
    publicApplicationOrigin: 'https://app.example.test',
    async issueFromHandoff(input) {
      suppliedOldSession = input.oldSessionToken;
      assert.equal(input.handoffToken, handoffToken);
      return {
        sessionToken,
        csrfToken: generateSessionToken(),
        absoluteExpiresAt: new Date(Date.now() + 43_200_000),
        identity: {
          principalType: 'human' as const,
          authMethod: 'oidc-session' as const,
          accountId: randomUUID(),
          sessionId: randomUUID(),
          id: randomUUID(),
          role: 'provedor' as const,
          condominioIds: null
        }
      };
    },
    async authenticate() { return null; },
    async inspect() { return null; },
    async isRevoked() { return false; },
    async rotate() { return { status: 'stale' as const }; },
    async revoke() { return 'unavailable' as const; },
    async revokeAll() { return 'unavailable' as const; },
    async recordAmbiguousCredentials() { ambiguousAudits += 1; }
  } satisfies BrowserSessionStore;
  const oidcService = {
    failurePath: '/auth/error',
    async startLogin() { return new URL('https://identity.example.test/authorize'); },
    async completeCallback() {
      return {
        returnTo: '/dashboard',
        handoffToken,
        identity: {
          accountId: randomUUID(),
          externalIdentityId: randomUUID(),
          issuer: 'https://identity.example.test',
          subject: 'subject',
          authenticatedAt: new Date()
        }
      };
    }
  };
  const app = createApp({
    oidcService,
    browserSessionService: createBrowserSessionService(sessionStore),
    browserSessionStore: sessionStore,
    testOnlyBypassHumanAuthRollout: true,
    authRateLimiter: permissiveAuthRateLimiter
  });
  const ambiguous = await app.inject({
    method: 'GET', url: '/auth/callback?code=code&state=state',
    headers: {
      cookie: `${SESSION_COOKIE_NAME}=${oldSessionToken}`,
      authorization: `Bearer egdev_${generateSessionToken()}`
    }
  });
  assert.equal(ambiguous.statusCode, 400);
  assert.equal(ambiguous.headers['cache-control'], 'no-store');
  assert.equal(ambiguousAudits, 1);
  const response = await app.inject({
    method: 'GET',
    url: '/auth/callback?code=code&state=state',
    headers: { cookie: `${SESSION_COOKIE_NAME}=${oldSessionToken}` }
  });
  assert.equal(response.statusCode, 303);
  assert.equal(response.headers.location, '/dashboard');
  assert.equal(suppliedOldSession, oldSessionToken);
  assert.deepEqual(response.headers['set-cookie'], [
    `${SESSION_COOKIE_NAME}=${sessionToken}; Path=/; HttpOnly; Secure; SameSite=Lax`,
    '__Host-eg_oidc_handoff=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0'
  ]);
  await app.close();
});
