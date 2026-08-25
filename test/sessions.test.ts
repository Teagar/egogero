import assert from 'node:assert/strict';
import { createHash, randomBytes, randomUUID } from 'node:crypto';
import test from 'node:test';

import Fastify from 'fastify';

import { authorize } from '../src/auth.js';
import { createApp } from '../src/app.js';
import {
  CLEARED_SESSION_COOKIE,
  createBrowserSessionAuthenticator,
  createBrowserSessionService,
  createCredentialRouter,
  generateSessionToken,
  hasBrowserSessionCookie,
  parseBrowserSessionCookie,
  serializeBrowserSessionCookie,
  SESSION_COOKIE_NAME,
  sessionConfigFromEnvironment
} from '../src/sessions.js';
import type {
  BrowserSessionStore,
  HumanSessionIdentity
} from '../src/sessions.js';

test('session environment is opt-in and accepts only canonical versioned 32-byte base64url keys', () => {
  assert.equal(sessionConfigFromEnvironment({}), undefined);
  assert.equal(sessionConfigFromEnvironment({ HUMAN_AUTH_ENABLED: 'false' }), undefined);
  assert.throws(() => sessionConfigFromEnvironment({ HUMAN_AUTH_ENABLED: 'TRUE' }), /must be true or false/);
  assert.throws(
    () => sessionConfigFromEnvironment({ HUMAN_AUTH_ENABLED: 'true' }),
    /SESSION_CSRF_KEYS is required/
  );

  const key = randomBytes(32).toString('base64url');
  const valid = sessionConfigFromEnvironment({
    HUMAN_AUTH_ENABLED: 'true',
    PUBLIC_APPLICATION_ORIGIN: 'https://app.example.test',
    SESSION_CSRF_KEYS: JSON.stringify({ 1: key }),
    SESSION_CSRF_CURRENT_KEY_VERSION: '1'
  });
  assert.equal(valid?.currentCsrfKeyVersion, 1);
  assert.equal(valid?.publicApplicationOrigin, 'https://app.example.test');
  assert.deepEqual(valid?.csrfKeys.get(1), Buffer.from(key, 'base64url'));

  for (const keys of [
    '{}',
    '[]',
    '{',
    JSON.stringify({ 0: key }),
    JSON.stringify({ '01': key }),
    JSON.stringify({ 1: randomBytes(31).toString('base64url') }),
    JSON.stringify({ 1: `${key}=` })
  ]) {
    assert.throws(() => sessionConfigFromEnvironment({
      HUMAN_AUTH_ENABLED: 'true',
      PUBLIC_APPLICATION_ORIGIN: 'https://app.example.test',
      SESSION_CSRF_KEYS: keys,
      SESSION_CSRF_CURRENT_KEY_VERSION: '1'
    }));
  }
  assert.throws(() => sessionConfigFromEnvironment({
    HUMAN_AUTH_ENABLED: 'true',
    PUBLIC_APPLICATION_ORIGIN: 'https://app.example.test',
    SESSION_CSRF_KEYS: JSON.stringify({ 1: key }),
    SESSION_CSRF_CURRENT_KEY_VERSION: '2'
  }), /must identify an active key/);
  for (const origin of [
    'http://app.example.test',
    'https://user@app.example.test',
    'https://app.example.test/path',
    'https://app.example.test/',
    'https://app.example.test?query=1'
  ]) {
    assert.throws(() => sessionConfigFromEnvironment({
      HUMAN_AUTH_ENABLED: 'true',
      PUBLIC_APPLICATION_ORIGIN: origin,
      SESSION_CSRF_KEYS: JSON.stringify({ 1: key }),
      SESSION_CSRF_CURRENT_KEY_VERSION: '1'
    }), /exact HTTPS origin/);
  }
});

test('session tokens and cookies have one exact opaque credential format', () => {
  for (let index = 0; index < 32; index += 1) {
    assert.match(generateSessionToken(), /^[A-Za-z0-9_-]{43}$/);
  }
  const token = generateSessionToken();
  const serialized = serializeBrowserSessionCookie(token);
  assert.equal(
    serialized,
    `${SESSION_COOKIE_NAME}=${token}; Path=/; HttpOnly; Secure; SameSite=Lax`
  );
  assert.equal(parseBrowserSessionCookie(`other=a; ${SESSION_COOKIE_NAME}=${token}`), token);
  assert.equal(parseBrowserSessionCookie(`${SESSION_COOKIE_NAME}=${token}; ${SESSION_COOKIE_NAME}=${token}`), null);
  assert.equal(parseBrowserSessionCookie(`${SESSION_COOKIE_NAME}=short`), null);
  assert.equal(parseBrowserSessionCookie([`${SESSION_COOKIE_NAME}=${token}`, 'other=b']), token);
  assert.equal(parseBrowserSessionCookie([`${SESSION_COOKIE_NAME}=${token}`, `${SESSION_COOKIE_NAME}=${token}`]), null);
  assert.equal(hasBrowserSessionCookie(`${SESSION_COOKIE_NAME}=malformed`), true);
  assert.equal(hasBrowserSessionCookie('other=value'), false);
  assert.throws(() => serializeBrowserSessionCookie('not-a-token'), /Invalid browser session token/);
});

test('browser authenticator rejects malformed and duplicate cookies before storage and forwards request id', async () => {
  const token = generateSessionToken();
  const identity: HumanSessionIdentity = {
    principalType: 'human',
    authMethod: 'oidc-session',
    accountId: randomUUID(),
    sessionId: randomUUID(),
    role: 'provedor',
    id: randomUUID(),
    condominioIds: null
  };
  const calls: Array<{ token: string; requestId: string }> = [];
  const store = {
    publicApplicationOrigin: 'https://app.example.test',
    async authenticate(value: string, requestId: string) {
      calls.push({ token: value, requestId });
      return identity;
    },
    async inspect() { return null; }
  } as unknown as BrowserSessionStore;
  const authenticator = createBrowserSessionAuthenticator(store);

  await assert.rejects(authenticator.authenticate({
    id: 'malformed-request', method: 'GET', headers: { cookie: `${SESSION_COOKIE_NAME}=bad` }
  } as never), { code: 'authentication_required' });
  await assert.rejects(authenticator.authenticate({
    id: 'duplicate-request', method: 'GET', headers: { cookie: `${SESSION_COOKIE_NAME}=${token}; ${SESSION_COOKIE_NAME}=${token}` }
  } as never), { code: 'authentication_required' });
  assert.equal(calls.length, 0);

  const authenticated = await authenticator.authenticate({
    id: 'request-123', method: 'GET', headers: { cookie: `theme=dark; ${SESSION_COOKIE_NAME}=${token}` }
  } as never);
  assert.deepEqual(authenticated, identity);
  assert.deepEqual(calls, [{ token, requestId: 'request-123' }]);
  await assert.rejects(authenticator.authenticate({
    id: 'unsafe-request', method: 'POST', headers: { cookie: `${SESSION_COOKIE_NAME}=${token}` }
  } as never), { statusCode: 403, code: 'csrf_required' });
  assert.equal(calls.length, 2);
});

test('browser session service exposes issuer operations and secure cookie lifecycle', async () => {
  const token = generateSessionToken();
  const store = {
    publicApplicationOrigin: 'https://app.example.test',
    async issueFromHandoff() { return null; },
    async authenticate() { return null; },
    async inspect() { return null; },
    async isRevoked() { return false; },
    async rotate() { return { status: 'stale' as const }; },
    async revoke() { return 'already-revoked' as const; },
    async revokeAll() { return 'revoked' as const; },
    async recordAmbiguousCredentials() {}
  } satisfies BrowserSessionStore;
  const service = createBrowserSessionService(store);
  assert.equal(await service.issueFromHandoff({ handoffToken: token, requestCorrelationId: 'issue' }), null);
  assert.deepEqual(await service.rotate({ sessionToken: token, requestCorrelationId: 'rotate' }), { status: 'stale' });
  assert.equal(await service.revoke({ sessionToken: token, requestCorrelationId: 'revoke' }), 'already-revoked');
  assert.equal(await service.revokeAll({ sessionToken: token, requestCorrelationId: 'all' }), 'revoked');
  assert.equal(service.sessionCookie(token), serializeBrowserSessionCookie(token));
  assert.equal(service.clearSessionCookie(), CLEARED_SESSION_COOKIE);
});

test('credential router rejects browser and Bearer credentials together without fallback', async () => {
  const token = generateSessionToken();
  let ambiguousAudits = 0;
  let deviceCalls = 0;
  let developmentCalls = 0;
  const store = {
    publicApplicationOrigin: 'https://app.example.test',
    async issueFromHandoff() { return null; },
    async authenticate() {
      return {
        principalType: 'human' as const,
        authMethod: 'oidc-session' as const,
        accountId: randomUUID(),
        sessionId: randomUUID(),
        id: randomUUID(),
        role: 'provedor' as const,
        condominioIds: null
      };
    },
    async inspect() { return null; },
    async isRevoked() { return false; },
    async rotate() { return { status: 'stale' as const }; },
    async revoke() { return 'unavailable' as const; },
    async revokeAll() { return 'unavailable' as const; },
    async recordAmbiguousCredentials() { ambiguousAudits += 1; }
  } satisfies BrowserSessionStore;
  const router = createCredentialRouter(
    store,
    { async authenticate() { deviceCalls += 1; return null; } },
    { async authenticate() { developmentCalls += 1; return null; } }
  );

  await assert.rejects(router.authenticate({
    id: 'ambiguous',
    headers: { cookie: `${SESSION_COOKIE_NAME}=${token}`, authorization: `Bearer egdev_${generateSessionToken()}` }
  } as never), { statusCode: 400, code: 'ambiguous_credentials' });
  assert.equal(ambiguousAudits, 1);
  assert.equal(deviceCalls, 0);
  assert.equal(developmentCalls, 0);

  await router.authenticate({ id: 'bearer', headers: { authorization: 'Bearer invalid' } } as never);
  assert.equal(deviceCalls, 1);
  assert.equal(developmentCalls, 1);
  await router.authenticate({ id: 'development', headers: {} } as never);
  assert.equal(developmentCalls, 2);

  const app = Fastify({ logger: false });
  app.get('/', { preHandler: authorize(router, 'convites:validate') }, async () => ({ ok: true }));
  app.post('/', { preHandler: authorize(router, 'convites:validate') }, async () => ({ ok: true }));
  const ambiguous = await app.inject({
    method: 'GET',
    url: '/',
    headers: {
      cookie: `${SESSION_COOKIE_NAME}=${token}`,
      authorization: `Bearer egdev_${generateSessionToken()}`
    }
  });
  assert.equal(ambiguous.statusCode, 400);
  assert.deepEqual(ambiguous.json(), { error: 'ambiguous_credentials' });
  assert.equal(ambiguous.headers['cache-control'], 'no-store');
  const malformedDevice = await app.inject({
    method: 'GET',
    url: '/',
    headers: { cookie: `${SESSION_COOKIE_NAME}=${token}`, authorization: 'Bearer egdev_short' }
  });
  assert.equal(malformedDevice.statusCode, 400);
  const unsafe = await app.inject({ method: 'POST', url: '/', headers: { cookie: `${SESSION_COOKIE_NAME}=${token}` } });
  assert.equal(unsafe.statusCode, 403);
  assert.deepEqual(unsafe.json(), { error: 'csrf_required' });
  await app.close();
});

test('cookie mutations require matching CSRF, exact origin or Referer, and JSON before handlers run', async () => {
  const token = generateSessionToken();
  const csrfToken = generateSessionToken();
  const identity: HumanSessionIdentity = {
    principalType: 'human', authMethod: 'oidc-session', accountId: randomUUID(), sessionId: randomUUID(),
    role: 'provedor', id: randomUUID(), condominioIds: null
  };
  let handlerCalls = 0;
  let authenticationLive = true;
  let inspectionLive = true;
  const store = {
    publicApplicationOrigin: 'https://app.example.test',
    async authenticate() { return authenticationLive ? identity : null; },
    async inspect() {
      if (!inspectionLive) return null;
      return {
        identity,
        familyId: randomUUID(),
        account: { id: identity.accountId, displayName: 'Person' },
        memberships: [], activeTenantId: null, csrfToken,
        csrfDigest: createHash('sha256').update(Buffer.from(csrfToken, 'base64url')).digest(),
        expiresAt: new Date(Date.now() + 60_000), idleExpiresAt: new Date(Date.now() + 60_000),
        authenticatedAt: new Date()
      };
    }
  } as unknown as BrowserSessionStore;
  const app = Fastify({ logger: false });
  app.post('/', { preHandler: authorize(createBrowserSessionAuthenticator(store), 'condominios:manage') }, async () => {
    handlerCalls += 1;
    return { ok: true };
  });
  const cookie = `${SESSION_COOKIE_NAME}=${token}`;
  const validHeaders = {
    cookie,
    origin: 'https://app.example.test',
    'content-type': 'application/json; charset=utf-8',
    'x-csrf-token': csrfToken
  };
  const missingCsrf: Record<string, string> = { ...validHeaders };
  delete missingCsrf['x-csrf-token'];
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
  const lastIndex = alphabet.indexOf(csrfToken.at(-1)!);
  const noncanonicalAlias = `${csrfToken.slice(0, -1)}${alphabet[lastIndex + 1]}`;
  assert.deepEqual(Buffer.from(noncanonicalAlias, 'base64url'), Buffer.from(csrfToken, 'base64url'));
  for (const headers of [
    missingCsrf,
    { ...validHeaders, 'x-csrf-token': generateSessionToken() },
    { ...validHeaders, 'x-csrf-token': noncanonicalAlias },
    { ...validHeaders, origin: 'https://hostile.example.test' },
    { ...validHeaders, 'content-type': 'text/plain' }
  ]) {
    const response = await app.inject({ method: 'POST', url: '/', headers: headers as never, payload: {} });
    assert.equal(response.statusCode, 403);
    assert.equal(response.headers['cache-control'], 'no-store');
  }
  assert.equal(handlerCalls, 0);
  const referer = await app.inject({
    method: 'POST', url: '/', payload: {},
    headers: {
      cookie,
      referer: 'https://app.example.test/page',
      'content-type': 'application/json; charset=utf-8',
      'x-csrf-token': csrfToken
    }
  });
  assert.equal(referer.statusCode, 200);
  const valid = await app.inject({ method: 'POST', url: '/', headers: validHeaders, payload: {} });
  assert.equal(valid.statusCode, 200);
  assert.equal(handlerCalls, 2);
  authenticationLive = false;
  const invalidSession = await app.inject({ method: 'POST', url: '/', headers: validHeaders, payload: {} });
  assert.equal(invalidSession.statusCode, 401);
  assert.equal(invalidSession.headers['set-cookie'], CLEARED_SESSION_COOKIE);
  authenticationLive = true;
  inspectionLive = false;
  const failedInspection = await app.inject({ method: 'POST', url: '/', headers: validHeaders, payload: {} });
  assert.equal(failedInspection.statusCode, 401);
  assert.equal(failedInspection.headers['set-cookie'], CLEARED_SESSION_COOKIE);
  await app.close();
});

test('browser auth endpoints are no-store and implement session, tenant, logout, and recent-auth contracts', async () => {
  const token = generateSessionToken();
  const replacement = generateSessionToken();
  const csrfToken = generateSessionToken();
  const accountId = randomUUID();
  const membershipId = randomUUID();
  const identity: HumanSessionIdentity = {
    principalType: 'human', authMethod: 'oidc-session', accountId, sessionId: randomUUID(),
    role: 'provedor', id: accountId, condominioIds: null
  };
  const snapshot = {
    identity,
    familyId: randomUUID(),
    account: { id: accountId, displayName: 'Person' },
    memberships: [{ id: membershipId, role: 'provedor' as const, tenantId: null, tenantLabel: null,
      residentId: null, residentLabel: null }],
    activeMembershipId: membershipId, activeTenantId: null, csrfToken,
    csrfDigest: createHash('sha256').update(Buffer.from(csrfToken, 'base64url')).digest(),
    expiresAt: new Date('2030-01-01T00:00:00Z'), idleExpiresAt: new Date('2030-01-01T00:00:00Z'),
    authenticatedAt: new Date()
  };
  let revoked = 0;
  let revokedState = false;
  let authenticationLive = true;
  let ambiguousAudits = 0;
  let reauthenticationFamilyId: string | undefined;
  let reauthenticationReturnTo: string | undefined;
  let reauthenticationAllowed = true;
  let reauthenticationChecks = 0;
  let createdIntents = 0;
  let startLoginFails = false;
  const reauthenticationIntents = new Map<string, '/app' | '/logout-all/continue'>();
  let staleRotation = false;
  let revokeAllResult: 'revoked' | 'reauthentication-required' = 'reauthentication-required';
  const store = {
    publicApplicationOrigin: 'https://app.example.test',
    async issueFromHandoff() { return null; },
    async authenticate() { return authenticationLive ? identity : null; },
    async inspect() { return snapshot; },
    async isRevoked() { return revokedState; },
    async rotate() {
      if (staleRotation) return { status: 'stale' as const };
      return { status: 'rotated' as const, sessionToken: replacement, csrfToken, identity, absoluteExpiresAt: snapshot.expiresAt };
    },
    async revoke() { revoked += 1; return 'revoked' as const; },
    async revokeAll() { return revokeAllResult; },
    async createReauthenticationStartIntent({ returnTo }: { returnTo: '/app' | '/logout-all/continue' }) {
      createdIntents += 1;
      const intent = generateSessionToken();
      reauthenticationIntents.set(intent, returnTo);
      return intent;
    },
    async consumeReauthenticationStartIntent({ intentToken }: { intentToken: string }) {
      const returnTo = reauthenticationIntents.get(intentToken);
      if (!returnTo) return null;
      reauthenticationIntents.delete(intentToken);
      return { accountId, familyId: snapshot.familyId, returnTo };
    },
    async recordAmbiguousCredentials() { ambiguousAudits += 1; }
  } satisfies BrowserSessionStore;
  const oidcService = {
    failurePath: '/auth/error',
    async startLogin(input: { reauthenticationFamilyId?: string; returnTo?: string }) {
      if (startLoginFails) throw new Error('provider unavailable');
      reauthenticationFamilyId = input.reauthenticationFamilyId;
      reauthenticationReturnTo = input.returnTo;
      return new URL('https://identity.example.test/authorize?max_age=0&prompt=login');
    },
    async completeCallback() { throw new Error('not used'); }
  };
  const app = createApp({
    browserSessionStore: store,
    browserSessionService: createBrowserSessionService(store),
    oidcService,
    authRateLimiter: {
      async check(action) {
        if (action === 'reauthentication_account') {
          reauthenticationChecks += 1;
          return reauthenticationAllowed
            ? { allowed: true, retryAfterSeconds: 0, repeatedExcess: false }
            : { allowed: false, retryAfterSeconds: 17, repeatedExcess: false };
        }
        return { allowed: true, retryAfterSeconds: 0, repeatedExcess: false };
      },
      async reserveFailure() { return { allowed: true, retryAfterSeconds: 0, repeatedExcess: false, reservationId: randomUUID() }; },
      async finalizeFailure() {}
    }
  });
  const cookie = `${SESSION_COOKIE_NAME}=${token}`;
  const headers = {
    cookie, origin: 'https://app.example.test', 'content-type': 'application/json', 'x-csrf-token': csrfToken
  };
  const session = await app.inject({ method: 'GET', url: '/auth/session', headers: { cookie } });
  assert.equal(session.statusCode, 200);
  assert.equal(session.headers['cache-control'], 'no-store');
  assert.equal(session.json().csrfToken, csrfToken);
  assert.equal(session.json().activeMembershipId, membershipId);
  assert.deepEqual(session.json().memberships[0], {
    id: membershipId, role: 'provedor', tenantId: null, tenantLabel: null,
    residentId: null, residentLabel: null
  });
  const ambiguous = await app.inject({
    method: 'GET', url: '/auth/session',
    headers: { cookie, authorization: `Bearer egdev_${generateSessionToken()}` }
  });
  assert.equal(ambiguous.statusCode, 400);
  assert.equal(ambiguous.headers['cache-control'], 'no-store');
  assert.equal(ambiguousAudits, 1);
  reauthenticationAllowed = false;
  const deniedReauthentication = await app.inject({ method: 'POST', url: '/auth/reauthenticate', headers, payload: {} });
  assert.equal(deniedReauthentication.statusCode, 429);
  assert.equal(deniedReauthentication.headers['retry-after'], '17');
  assert.equal(createdIntents, 0, 'a denied POST must not persist an intent');
  reauthenticationAllowed = true;
  const reauthenticate = await app.inject({ method: 'POST', url: '/auth/reauthenticate', headers, payload: {} });
  assert.equal(reauthenticate.statusCode, 200);
  assert.match(reauthenticate.json().navigateTo, /^\/auth\/reauthenticate\/start\/[A-Za-z0-9_-]{43}$/);
  assert.equal(createdIntents, 1);
  const reauthenticateStart = await app.inject({
    method: 'GET', url: reauthenticate.json().navigateTo, headers: { cookie }
  });
  assert.equal(reauthenticateStart.statusCode, 303);
  assert.equal(reauthenticateStart.headers.location, 'https://identity.example.test/authorize?max_age=0&prompt=login');
  assert.equal(reauthenticationFamilyId, snapshot.familyId);
  assert.equal(reauthenticationReturnTo, '/app');
  assert.equal(reauthenticationChecks, 2, 'GET must not perform a second limiter check');
  assert.equal((await app.inject({
    method: 'GET', url: reauthenticate.json().navigateTo, headers: { cookie }
  })).statusCode, 401, 'a start intent is single use');
  const failingStart = await app.inject({
    method: 'POST', url: '/auth/reauthenticate', headers, payload: { returnTo: '/logout-all/continue' }
  });
  assert.equal(failingStart.statusCode, 200);
  startLoginFails = true;
  const failedStart = await app.inject({ method: 'GET', url: failingStart.json().navigateTo, headers: { cookie } });
  assert.equal(failedStart.statusCode, 303);
  assert.equal(failedStart.headers.location, '/auth/error');
  startLoginFails = false;
  assert.equal((await app.inject({
    method: 'GET', url: failingStart.json().navigateTo, headers: { cookie }
  })).statusCode, 401, 'a failed provider start still consumes the authorized intent');
  assert.equal(createdIntents, 2);
  assert.equal(reauthenticationChecks, 3);
  const tenant = await app.inject({ method: 'POST', url: '/auth/tenant', headers, payload: { membershipId } });
  assert.equal(tenant.statusCode, 204);
  assert.equal(tenant.headers['set-cookie'], serializeBrowserSessionCookie(replacement));
  staleRotation = true;
  const stale = await app.inject({ method: 'POST', url: '/auth/tenant', headers, payload: { membershipId } });
  assert.equal(stale.statusCode, 409);
  assert.equal(stale.headers['set-cookie'], undefined, 'a losing tab must not clear a winner cookie');
  assert.equal((await app.inject({ method: 'GET', url: '/auth/tenant', headers: { cookie } })).statusCode, 404);
  const recent = await app.inject({ method: 'POST', url: '/auth/logout-all', headers, payload: {} });
  assert.equal(recent.statusCode, 403);
  assert.deepEqual(recent.json(), { error: 'reauthentication_required' });
  revokeAllResult = 'revoked';
  const all = await app.inject({ method: 'POST', url: '/auth/logout-all', headers, payload: {} });
  assert.equal(all.statusCode, 204);
  assert.equal(all.headers['set-cookie'], CLEARED_SESSION_COOKIE);
  const logout = await app.inject({ method: 'POST', url: '/auth/logout', headers, payload: {} });
  assert.equal(logout.statusCode, 204);
  assert.equal(revoked, 1);
  authenticationLive = false;
  revokedState = true;
  const repeatedRevoked = await app.inject({
    method: 'POST', url: '/auth/logout', payload: {},
    headers: { cookie, origin: 'https://app.example.test', 'content-type': 'application/json' }
  });
  assert.equal(repeatedRevoked.statusCode, 204);
  assert.equal(repeatedRevoked.headers['set-cookie'], CLEARED_SESSION_COOKIE);
  assert.equal(revoked, 1);
  const repeated = await app.inject({
    method: 'POST', url: '/auth/logout', payload: {},
    headers: { origin: 'https://app.example.test', 'content-type': 'application/json' }
  });
  assert.equal(repeated.statusCode, 204);
  assert.equal(repeated.headers['cache-control'], 'no-store');
  await app.close();
});
