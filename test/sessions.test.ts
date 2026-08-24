import assert from 'node:assert/strict';
import { randomBytes, randomUUID } from 'node:crypto';
import test from 'node:test';

import Fastify from 'fastify';

import { authorize } from '../src/auth.js';
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
    SESSION_CSRF_KEYS: JSON.stringify({ 1: key }),
    SESSION_CSRF_CURRENT_KEY_VERSION: '1'
  });
  assert.equal(valid?.currentCsrfKeyVersion, 1);
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
      SESSION_CSRF_KEYS: keys,
      SESSION_CSRF_CURRENT_KEY_VERSION: '1'
    }));
  }
  assert.throws(() => sessionConfigFromEnvironment({
    HUMAN_AUTH_ENABLED: 'true',
    SESSION_CSRF_KEYS: JSON.stringify({ 1: key }),
    SESSION_CSRF_CURRENT_KEY_VERSION: '2'
  }), /must identify an active key/);
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
    async authenticate(value: string, requestId: string) {
      calls.push({ token: value, requestId });
      return identity;
    }
  } as BrowserSessionStore;
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
    async issueFromHandoff() { return null; },
    async authenticate() { return null; },
    async rotate() { return { status: 'stale' as const }; },
    async revoke() { return 'already-revoked' as const; },
    async revokeAll() { return 3; },
    async recordAmbiguousCredentials() {}
  } satisfies BrowserSessionStore;
  const service = createBrowserSessionService(store);
  assert.equal(await service.issueFromHandoff({ handoffToken: token, requestCorrelationId: 'issue' }), null);
  assert.deepEqual(await service.rotate({ sessionToken: token, requestCorrelationId: 'rotate' }), { status: 'stale' });
  assert.equal(await service.revoke({ sessionToken: token, requestCorrelationId: 'revoke' }), 'already-revoked');
  assert.equal(await service.revokeAll({ accountId: randomUUID(), requestCorrelationId: 'all' }), 3);
  assert.equal(service.sessionCookie(token), serializeBrowserSessionCookie(token));
  assert.equal(service.clearSessionCookie(), CLEARED_SESSION_COOKIE);
});

test('credential router rejects browser and Bearer credentials together without fallback', async () => {
  const token = generateSessionToken();
  let ambiguousAudits = 0;
  let deviceCalls = 0;
  let developmentCalls = 0;
  const store = {
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
    async rotate() { return { status: 'stale' as const }; },
    async revoke() { return 'unavailable' as const; },
    async revokeAll() { return 0; },
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
