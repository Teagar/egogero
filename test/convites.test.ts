import assert from 'node:assert/strict';
import test from 'node:test';

import Fastify from 'fastify';

import { createDevelopmentHeaderAuthenticator } from '../src/auth.js';
import {
  ActiveTokenCollisionError,
  consumeInvitationToken,
  createInvitation,
  generateSixDigitToken,
  registerConviteRoutes
} from '../src/convites.js';
import type { InvitationRecord, InvitationStore } from '../src/convites.js';

const CONDOMINIO_ID = '00000000-0000-4000-8000-000000000001';
const OTHER_CONDOMINIO_ID = '00000000-0000-4000-8000-000000000002';
const MORADOR_ID = '00000000-0000-4000-8000-000000000101';
const OTHER_MORADOR_ID = '00000000-0000-4000-8000-000000000102';
const CONVIDADO_ID = '00000000-0000-4000-8000-000000000201';
const NOW = new Date('2026-08-24T05:00:00.000Z');
const EXPIRES_AT = new Date('2026-08-25T05:00:00.000Z');
const data = {
  condominioId: CONDOMINIO_ID,
  moradorId: MORADOR_ID,
  convidadoId: CONVIDADO_ID,
  tipo: 'visitante' as const,
  expiresAt: EXPIRES_AT
};

function record(token: string): InvitationRecord {
  return {
    id: `invitation-${token}`,
    createdAt: NOW,
    deletedAt: null,
    ...data,
    usedAt: null,
    tokenDigest: null
  };
}

function uniqueMemoryStore(initialTokens: string[] = []): InvitationStore & { activeTokens: Set<string> } {
  const activeTokens = new Set(initialTokens);
  return {
    activeTokens,
    async createActive(input) {
      if (activeTokens.has(input.token)) {
        throw new ActiveTokenCollisionError();
      }
      activeTokens.add(input.token);
      return record(input.token);
    },
    async consumeActive(token) {
      return activeTokens.delete(token);
    }
  };
}

test('production generator always returns a zero-padded numeric six-digit token', () => {
  for (let index = 0; index < 10_000; index += 1) {
    assert.match(generateSixDigitToken(), /^[0-9]{6}$/);
  }
});

test('service allocates 100k active tokens without an active collision under deterministic collision pressure', async () => {
  const store = uniqueMemoryStore();
  let next = 0;

  for (let index = 0; index < 100_000; index += 1) {
    const result = await createInvitation(store, data, {
      // Every token after the first collides once before the next candidate is produced.
      generateToken: () => String(Math.floor(next++ / 2)).padStart(6, '0'),
      now: () => NOW
    });
    assert.ok(result);
  }

  assert.equal(store.activeTokens.size, 100_000);
});

test('database collision is retried and concurrent creators cannot retain the same token', async () => {
  const retryStore = uniqueMemoryStore(['123456']);
  const candidates = ['123456', '654321'];
  const retried = await createInvitation(retryStore, data, {
    generateToken: () => candidates.shift()!,
    now: () => NOW
  });
  assert.equal(retried?.token, '654321');

  const concurrentStore = uniqueMemoryStore();
  function competingGenerator(fallback: string) {
    let attempt = 0;
    return () => attempt++ === 0 ? '111111' : fallback;
  }
  const results = await Promise.all([
    createInvitation(concurrentStore, data, { generateToken: competingGenerator('222222'), now: () => NOW }),
    createInvitation(concurrentStore, data, { generateToken: competingGenerator('333333'), now: () => NOW })
  ]);

  assert.equal(new Set(results.map((result) => result?.token)).size, 2);
  assert.equal(concurrentStore.activeTokens.size, 2);
});

test('atomic consumption rejects replay and malformed tokens without store access', async () => {
  const store = uniqueMemoryStore(['123456']);
  assert.equal(await consumeInvitationToken(store, '123456', NOW), true);
  assert.equal(await consumeInvitationToken(store, '123456', NOW), false);
  assert.equal(await consumeInvitationToken(store, 'not-a-token', NOW), false);
});

test('creation route exposes the token once and enforces tenant and resident ownership before store access', async () => {
  let storeCalls = 0;
  const store: InvitationStore = {
    async createActive(input) {
      storeCalls += 1;
      return record(input.token);
    },
    async consumeActive() {
      throw new Error('not used by creation route');
    }
  };
  const app = Fastify({ logger: false });
  registerConviteRoutes(app, store, createDevelopmentHeaderAuthenticator(true));
  const path = `/condominios/${CONDOMINIO_ID}/moradores/${MORADOR_ID}/convidados/${CONVIDADO_ID}/convites`;
  const residentHeaders = {
    'x-development-user-id': MORADOR_ID,
    'x-development-user-role': 'morador',
    'x-development-condominio-id': CONDOMINIO_ID
  };
  const payload = { tipo: 'prestador', expiresAt: EXPIRES_AT.toISOString() };

  const created = await app.inject({ method: 'POST', url: path, headers: residentHeaders, payload });
  assert.equal(created.statusCode, 201);
  assert.match(created.json().token, /^[0-9]{6}$/);
  assert.equal(created.headers['cache-control'], 'no-store');
  assert.deepEqual(Object.keys(created.json()).sort(), [
    'condominioId', 'convidadoId', 'createdAt', 'expiresAt', 'id', 'moradorId', 'tipo', 'token'
  ]);
  assert.equal(storeCalls, 1);

  const wrongResident = await app.inject({
    method: 'POST',
    url: path.replace(MORADOR_ID, OTHER_MORADOR_ID),
    headers: residentHeaders,
    payload
  });
  assert.equal(wrongResident.statusCode, 403);

  const wrongTenant = await app.inject({
    method: 'POST',
    url: path.replace(CONDOMINIO_ID, OTHER_CONDOMINIO_ID),
    headers: residentHeaders,
    payload
  });
  assert.equal(wrongTenant.statusCode, 403);

  const gateHeaders = {
    'x-development-user-id': 'gate-1',
    'x-development-user-role': 'portaria',
    'x-development-condominio-id': CONDOMINIO_ID
  };
  const gate = await app.inject({ method: 'POST', url: path, headers: gateHeaders, payload });
  assert.equal(gate.statusCode, 403);
  assert.equal(storeCalls, 1);
  await app.close();
});

test('creation fails closed for inactive ownership, past expiration, and exhausted collisions', async () => {
  const missingStore: InvitationStore = {
    async createActive() {
      return null;
    },
    async consumeActive() {
      return false;
    }
  };
  assert.equal(await createInvitation(missingStore, data, { generateToken: () => '123456', now: () => NOW }), null);

  await assert.rejects(
    createInvitation(missingStore, { ...data, expiresAt: NOW }, { generateToken: () => '123456', now: () => NOW }),
    /expiration must be in the future/
  );

  const occupied = uniqueMemoryStore(['123456']);
  await assert.rejects(
    createInvitation(occupied, data, { generateToken: () => '123456', maxAttempts: 2, now: () => NOW }),
    /Could not allocate/
  );
});
