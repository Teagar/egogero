import assert from 'node:assert/strict';
import test from 'node:test';

import Fastify from 'fastify';

import { authorize, createDevelopmentHeaderAuthenticator } from '../src/auth.js';
import { registerConviteRoutes } from '../src/convites.js';
import type { InvitationStore } from '../src/convites.js';
import {
  createDeviceAuthenticator,
  createMemoryDeviceRateLimiter,
  generateDeviceApiKey,
  registerDeviceRoutes
} from '../src/dispositivos.js';
import type { DeviceRecord, DeviceStore } from '../src/dispositivos.js';

const CONDOMINIUM_ID = '00000000-0000-4000-8000-000000000001';
const OTHER_CONDOMINIUM_ID = '00000000-0000-4000-8000-000000000002';
const DEVICE_ID = '00000000-0000-4000-8000-000000000003';
const API_KEY = `egdev_${'a'.repeat(43)}`;
const NOW = new Date('2026-08-24T12:00:00.000Z');

function managementHeaders(condominiumId = CONDOMINIUM_ID) {
  return {
    'x-development-user-id': 'syndic-1',
    'x-development-user-role': 'sindico',
    'x-development-condominio-id': condominiumId
  };
}

function deviceRecord(): DeviceRecord {
  return {
    id: DEVICE_ID,
    createdAt: NOW,
    deletedAt: null,
    nome: 'Tablet portaria',
    condominioId: CONDOMINIUM_ID,
    status: 'ativo',
    ultimoUsoEm: null
  };
}

test('device API keys have a fixed opaque format', () => {
  const keys = Array.from({ length: 100 }, generateDeviceApiKey);
  assert.ok(keys.every((key) => /^egdev_[A-Za-z0-9_-]{43}$/.test(key)));
  assert.equal(new Set(keys).size, keys.length);
});

test('device management returns plaintext only at provisioning and enforces tenant RBAC', async () => {
  let createCalls = 0;
  let listCalls = 0;
  let revokeCalls = 0;
  const store: DeviceStore = {
    async create() {
      createCalls += 1;
      return { device: deviceRecord(), apiKey: API_KEY };
    },
    async list() {
      listCalls += 1;
      return [deviceRecord()];
    },
    async revoke() {
      revokeCalls += 1;
      return 'revoked';
    },
    async authenticate() {
      throw new Error('Unexpected authentication');
    }
  };
  const app = Fastify({ logger: false });
  registerDeviceRoutes(app, store, createDevelopmentHeaderAuthenticator(true));
  const path = `/condominios/${CONDOMINIUM_ID}/dispositivos`;

  const created = await app.inject({ method: 'POST', url: path, headers: managementHeaders(), payload: { nome: ' Tablet portaria ' } });
  assert.equal(created.statusCode, 201);
  assert.equal(created.headers['cache-control'], 'no-store');
  assert.equal(created.json().apiKey, API_KEY);

  const listed = await app.inject({ method: 'GET', url: path, headers: managementHeaders() });
  assert.equal(listed.statusCode, 200);
  assert.equal(listed.body.includes(API_KEY), false);
  assert.equal(Object.hasOwn(listed.json()[0], 'apiKey'), false);

  const revoked = await app.inject({ method: 'DELETE', url: `${path}/${DEVICE_ID}`, headers: managementHeaders() });
  assert.equal(revoked.statusCode, 204);

  for (const method of ['POST', 'GET', 'DELETE'] as const) {
    const response = await app.inject({
      method,
      url: method === 'DELETE' ? `${path}/${DEVICE_ID}` : path,
      headers: managementHeaders(OTHER_CONDOMINIUM_ID),
      payload: method === 'POST' ? { nome: 'Other' } : undefined
    });
    assert.equal(response.statusCode, 403);
  }
  assert.deepEqual({ createCalls, listCalls, revokeCalls }, { createCalls: 1, listCalls: 1, revokeCalls: 1 });
  await app.close();
});

test('Bearer authentication resolves the device tenant and rejects malformed credentials before storage', async () => {
  const seen: string[] = [];
  const store: DeviceStore = {
    async create() { throw new Error('Unexpected create'); },
    async list() { throw new Error('Unexpected list'); },
    async revoke() { throw new Error('Unexpected revoke'); },
    async authenticate(apiKey) {
      seen.push(apiKey);
      return apiKey === API_KEY ? { id: DEVICE_ID, condominiumId: CONDOMINIUM_ID } : null;
    }
  };
  const app = Fastify({ logger: false });
  app.get('/', { preHandler: authorize(createDeviceAuthenticator(store), 'convites:validate') }, async (request) => request.authenticatedIdentity);

  assert.equal((await app.inject({ method: 'GET', url: '/' })).statusCode, 401);
  assert.equal((await app.inject({ method: 'GET', url: '/', headers: { authorization: `Basic ${API_KEY}` } })).statusCode, 401);
  const authenticated = await app.inject({ method: 'GET', url: '/', headers: { authorization: `Bearer ${API_KEY}` } });
  assert.equal(authenticated.statusCode, 200);
  assert.deepEqual(authenticated.json(), {
    id: DEVICE_ID,
    role: 'portaria',
    condominioIds: [CONDOMINIUM_ID],
    principalType: 'device',
    authMethod: 'device'
  });
  assert.deepEqual(seen, [API_KEY]);
  await app.close();
});

test('memory rate limiter allows 20 attempts per moving minute and applies progressive backoff', async () => {
  const limiter = createMemoryDeviceRateLimiter();
  for (let attempt = 0; attempt < 20; attempt += 1) {
    assert.deepEqual(await limiter.consume(DEVICE_ID, NOW), { allowed: true, remaining: 19 - attempt });
  }
  assert.deepEqual(await limiter.consume(DEVICE_ID, NOW), { allowed: false, retryAfterSeconds: 15 });
  assert.deepEqual(await limiter.consume(DEVICE_ID, new Date(NOW.getTime() + 1_000)), { allowed: false, retryAfterSeconds: 14 });
  assert.deepEqual(await limiter.consume(DEVICE_ID, new Date(NOW.getTime() + 15_000)), { allowed: false, retryAfterSeconds: 30 });
  assert.deepEqual(await limiter.consume(DEVICE_ID, new Date(NOW.getTime() + 61_000)), { allowed: true, remaining: 19 });
});

function validationDependencies() {
  let validations = 0;
  const unavailable = async () => { throw new Error('Unexpected management access'); };
  const db = {
    condominio: { create: unavailable, findMany: unavailable, findFirst: unavailable, updateMany: unavailable },
    morador: { create: unavailable, findMany: unavailable, findFirst: unavailable, updateMany: unavailable },
    convidado: { create: unavailable, findMany: unavailable, findFirst: unavailable, updateMany: unavailable }
  };
  const store: InvitationStore = {
    createActive: unavailable,
    createBatchActive: unavailable,
    async validateActive() {
      validations += 1;
      return { allowed: false, reason: 'invalid_or_unavailable' };
    },
    listOwnedAudits: unavailable,
    revokeActive: unavailable
  };
  const authenticator = {
    async authenticate() {
      return {
        id: DEVICE_ID,
        role: 'portaria' as const,
        condominioIds: [CONDOMINIUM_ID],
        principalType: 'device' as const,
        authMethod: 'device' as const
      };
    }
  };
  return { db, store, authenticator, validationCount: () => validations };
}

test('validation rate limiting returns standard headers without consuming or auditing a 21st attempt', async () => {
  const dependencies = validationDependencies();
  const app = Fastify({ logger: false });
  registerConviteRoutes(
    app,
    dependencies.db,
    dependencies.store,
    dependencies.authenticator,
    undefined,
    undefined,
    createMemoryDeviceRateLimiter()
  );

  for (let attempt = 0; attempt < 20; attempt += 1) {
    const response = await app.inject({
      method: 'POST',
      url: '/portaria/convites/validar',
      payload: { token: '123456', tipoAcesso: 'pedestre' }
    });
    assert.equal(response.statusCode, 200);
    assert.equal(response.headers['x-ratelimit-limit'], '20');
    assert.equal(response.headers['x-ratelimit-remaining'], String(19 - attempt));
  }

  const blocked = await app.inject({
    method: 'POST',
    url: '/portaria/convites/validar',
    payload: { token: '123456', tipoAcesso: 'pedestre' }
  });
  assert.equal(blocked.statusCode, 429);
  assert.equal(blocked.headers['retry-after'], '15');
  assert.deepEqual(blocked.json(), { allowed: false, reason: 'rate_limited' });
  assert.equal(dependencies.validationCount(), 20);
  await app.close();
});

test('HTTPS enforcement accepts forwarded protocol only from an explicitly trusted proxy', async () => {
  for (const trustProxy of [false, '127.0.0.1'] as const) {
    const dependencies = validationDependencies();
    const app = Fastify({ logger: false, trustProxy });
    registerConviteRoutes(
      app,
      dependencies.db,
      dependencies.store,
      dependencies.authenticator,
      undefined,
      undefined,
      createMemoryDeviceRateLimiter(),
      createMemoryDeviceRateLimiter(),
      true
    );
    const response = await app.inject({
      method: 'POST',
      url: '/portaria/convites/validar',
      headers: { 'x-forwarded-proto': 'https' },
      payload: { token: '123456', tipoAcesso: 'pedestre' }
    });
    assert.equal(response.statusCode, trustProxy ? 200 : 426);
    assert.equal(dependencies.validationCount(), trustProxy ? 1 : 0);
    await app.close();
  }
});
