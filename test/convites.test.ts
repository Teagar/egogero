import assert from 'node:assert/strict';
import test from 'node:test';

import Fastify from 'fastify';

import { createApp } from '../src/app.js';
import type { AppDependencies, AppStore } from '../src/app.js';
import { createDevelopmentHeaderAuthenticator } from '../src/auth.js';
import {
  ActiveTokenCollisionError,
  consumeInvitationToken,
  createInvitation,
  createInvitations,
  generateSixDigitToken,
  invitationStatus,
  invitationMessage,
  registerConviteRoutes
} from '../src/convites.js';
import type { InvitationAllocation, InvitationRecord, InvitationStore, NotificationSender } from '../src/convites.js';

const authenticator = createDevelopmentHeaderAuthenticator(true);
const uuid = (n: number) => `00000000-0000-4000-8000-${String(n).padStart(12, '0')}`;
const CONDOMINIO_ID = uuid(1);
const OTHER_CONDOMINIO_ID = uuid(2);
const MORADOR_ID = uuid(101);
const OTHER_MORADOR_ID = uuid(102);
const CONVIDADO_ID = uuid(201);
const SECOND_CONVIDADO_ID = uuid(202);
const OTHER_CONVIDADO_ID = uuid(203);
const DELETED_CONVIDADO_ID = uuid(204);
const NOW = new Date('2026-08-24T05:00:00.000Z');
const EXPIRES_AT = new Date('2026-08-25T05:00:00.000Z');
const data = {
  condominioId: CONDOMINIO_ID,
  moradorId: MORADOR_ID,
  convidadoId: CONVIDADO_ID,
  tipo: 'visitante' as const,
  expiresAt: EXPIRES_AT
};
const residentHeaders = {
  'x-development-user-id': MORADOR_ID,
  'x-development-user-role': 'morador',
  'x-development-condominio-id': CONDOMINIO_ID
};

function record(input: InvitationAllocation, index = 0): InvitationRecord {
  return {
    id: uuid(300 + index),
    createdAt: input.now,
    deletedAt: null,
    condominioId: input.condominioId,
    moradorId: input.moradorId,
    convidadoId: input.convidadoId,
    tipo: input.tipo,
    expiresAt: input.expiresAt,
    usedAt: null,
    revokedAt: null,
    tokenDigest: null
  };
}

function uniqueMemoryStore(initialTokens: string[] = []): InvitationStore & {
  activeTokens: Set<string>;
  batchCalls: number;
} {
  const activeTokens = new Set(initialTokens);
  const store = {
    activeTokens,
    batchCalls: 0,
    async createBatchActive(inputs: readonly InvitationAllocation[]) {
      store.batchCalls += 1;
      const candidates = new Set<string>();
      for (const input of inputs) {
        if (activeTokens.has(input.token) || candidates.has(input.token)) {
          throw new ActiveTokenCollisionError();
        }
        candidates.add(input.token);
      }
      for (const input of inputs) {
        activeTokens.add(input.token);
      }
      return inputs.map(record);
    },
    async createActive(input: InvitationAllocation) {
      const records = await store.createBatchActive([input]);
      return records[0] ?? null;
    },
    async consumeActive(token: string) {
      return activeTokens.delete(token);
    },
    async revokeActive() {
      return 'revoked' as const;
    }
  };
  return store;
}

function batchStore({ condominiumDeleted = false, residentDeleted = false, email = null, telefone = null }: { condominiumDeleted?: boolean; residentDeleted?: boolean; email?: string | null; telefone?: string | null } = {}): AppStore {
  const condominios = new Map([
    [CONDOMINIO_ID, condominiumDeleted ? new Date() : null],
    [OTHER_CONDOMINIO_ID, null]
  ]);
  const moradores = new Map([
    [MORADOR_ID, { condominioId: CONDOMINIO_ID, deletedAt: residentDeleted ? new Date() : null }],
    [OTHER_MORADOR_ID, { condominioId: OTHER_CONDOMINIO_ID, deletedAt: null }]
  ]);
  const convidados = new Map([
    [CONVIDADO_ID, { condominioId: CONDOMINIO_ID, moradorId: MORADOR_ID, deletedAt: null }],
    [SECOND_CONVIDADO_ID, { condominioId: CONDOMINIO_ID, moradorId: MORADOR_ID, deletedAt: null }],
    [OTHER_CONVIDADO_ID, { condominioId: OTHER_CONDOMINIO_ID, moradorId: OTHER_MORADOR_ID, deletedAt: null }],
    [DELETED_CONVIDADO_ID, { condominioId: CONDOMINIO_ID, moradorId: MORADOR_ID, deletedAt: new Date() }]
  ]);
  const guestRecord = (id: string, condo: string, owner: string, deletedAt: Date | null) => ({
    id,
    createdAt: NOW,
    deletedAt,
    nome: 'Guest',
    email,
    telefone,
    condominioId: condo,
    moradorId: owner,
    ultimoUsoEm: null
  });

  return {
    condominio: {
      async create() { throw new Error('Unexpected condominium create'); },
      async findMany() { return []; },
      async findFirst({ where }) {
        return condominios.get(where.id) === null
          ? { id: where.id, createdAt: NOW, deletedAt: null, nome: 'A', responsavel: 'B', tipo: 'C' }
          : null;
      },
      async updateMany() { return { count: 0 }; }
    },
    morador: {
      async create() { throw new Error('Unexpected resident create'); },
      async findMany() { return []; },
      async findFirst({ where }) {
        const row = moradores.get(where.id);
        return row && row.condominioId === where.condominioId && row.deletedAt === null
          && condominios.get(row.condominioId) === null
          ? {
              id: where.id,
              createdAt: NOW,
              deletedAt: null,
              nome: 'Resident',
              condominioId: row.condominioId,
              enderecoRua: 'A',
              enderecoNumero: '1',
              enderecoBloco: null,
              enderecoApartamento: null
            }
          : null;
      },
      async updateMany() { return { count: 0 }; }
    },
    convidado: {
      async create() { throw new Error('Guests must not be created by batch invitations'); },
      async findMany() { return []; },
      async findFirst({ where }) {
        const row = convidados.get(where.id);
        return row && row.condominioId === where.condominioId && row.moradorId === where.moradorId
          && row.deletedAt === null && condominios.get(row.condominioId) === null
          ? guestRecord(where.id, row.condominioId, row.moradorId, row.deletedAt)
          : null;
      },
      async updateMany() { return { count: 0 }; }
    }
  };
}

test('production generator always returns a zero-padded numeric six-digit token', () => {
  for (let index = 0; index < 10_000; index += 1) {
    assert.match(generateSixDigitToken(), /^[0-9]{6}$/);
  }
});

test('service allocates 100k active tokens without an active collision under deterministic pressure', async () => {
  const store = uniqueMemoryStore();
  let next = 0;
  for (let index = 0; index < 100_000; index += 1) {
    const result = await createInvitation(store, data, {
      generateToken: () => String(Math.floor(next++ / 2)).padStart(6, '0'),
      now: () => NOW
    });
    assert.ok(result);
  }
  assert.equal(store.activeTokens.size, 100_000);
});

test('single and batch allocation retry collisions through the same algorithm', async () => {
  const singleStore = uniqueMemoryStore(['123456']);
  const singleCandidates = ['123456', '654321'];
  const single = await createInvitation(singleStore, data, {
    generateToken: () => singleCandidates.shift()!,
    now: () => NOW
  });
  assert.equal(single?.token, '654321');

  const batchStore = uniqueMemoryStore(['111111']);
  const batchCandidates = ['111111', '222222', '333333', '444444'];
  const batch = await createInvitations(
    batchStore,
    [data, { ...data, convidadoId: SECOND_CONVIDADO_ID }],
    { generateToken: () => batchCandidates.shift()!, now: () => NOW }
  );
  assert.deepEqual(batch?.map((result) => result.token), ['333333', '444444']);
  assert.equal(batchStore.activeTokens.has('222222'), false, 'failed attempt must not partially persist');
});

test('atomic consumption rejects replay and malformed tokens without store access', async () => {
  const store = uniqueMemoryStore(['123456']);
  assert.equal(await consumeInvitationToken(store, '123456', NOW), true);
  assert.equal(await consumeInvitationToken(store, '123456', NOW), false);
  assert.equal(await consumeInvitationToken(store, 'not-a-token', NOW), false);
});

test('invitation lifecycle derives active and expired from time while used and revoked are terminal', () => {
  const base = { usedAt: null, revokedAt: null, expiresAt: EXPIRES_AT };
  assert.equal(invitationStatus(base, NOW), 'active');
  assert.equal(invitationStatus({ ...base, expiresAt: NOW }, NOW), 'expired');
  assert.equal(invitationStatus({ ...base, revokedAt: NOW }, new Date('2026-08-26T05:00:00.000Z')), 'revoked');
  assert.equal(invitationStatus({ ...base, usedAt: NOW }, new Date('2026-08-26T05:00:00.000Z')), 'used');
});

test('revocation route is scoped, idempotent for revoked invitations, and fails closed otherwise', async () => {
  const outcomes: Array<'revoked' | 'already-revoked' | 'unavailable'> = ['revoked', 'already-revoked', 'unavailable'];
  const calls: Array<{ id: string; condominioId: string; moradorId: string }> = [];
  const store: InvitationStore = {
    async createActive() { throw new Error('Unexpected create'); },
    async createBatchActive() { throw new Error('Unexpected create'); },
    async consumeActive() { throw new Error('Unexpected consume'); },
    async revokeActive(args) {
      calls.push(args);
      return outcomes.shift() ?? 'unavailable';
    }
  };
  const app = Fastify({ logger: false });
  registerConviteRoutes(app, batchStore(), store, authenticator);
  const path = `/condominios/${CONDOMINIO_ID}/moradores/${MORADOR_ID}/convites/${uuid(300)}`;

  assert.equal((await app.inject({ method: 'DELETE', url: path, headers: residentHeaders })).statusCode, 204);
  assert.equal((await app.inject({ method: 'DELETE', url: path, headers: residentHeaders })).statusCode, 204);
  assert.equal((await app.inject({ method: 'DELETE', url: path, headers: residentHeaders })).statusCode, 404);
  assert.deepEqual(calls[0], { id: uuid(300), condominioId: CONDOMINIO_ID, moradorId: MORADOR_ID });
  assert.equal((await app.inject({ method: 'DELETE', url: path.replace(MORADOR_ID, OTHER_MORADOR_ID), headers: residentHeaders })).statusCode, 403);
  assert.equal((await app.inject({ method: 'DELETE', url: path.replace(CONDOMINIO_ID, OTHER_CONDOMINIO_ID), headers: residentHeaders })).statusCode, 403);
  assert.equal((await app.inject({ method: 'DELETE', url: path.replace(uuid(300), 'invalid'), headers: residentHeaders })).statusCode, 400);
  await app.close();
});

test('single creation exposes plaintext once with no-store and enforces scope before storage', async () => {
  const store = uniqueMemoryStore();
  const app = Fastify({ logger: false });
  registerConviteRoutes(app, batchStore(), store, authenticator);
  const path = `/condominios/${CONDOMINIO_ID}/moradores/${MORADOR_ID}/convidados/${CONVIDADO_ID}/convites`;
  const payload = { tipo: 'prestador', expiresAt: EXPIRES_AT.toISOString() };

  const created = await app.inject({ method: 'POST', url: path, headers: residentHeaders, payload });
  assert.equal(created.statusCode, 201);
  assert.match(created.json().token, /^[0-9]{6}$/);
  assert.equal(created.headers['cache-control'], 'no-store');

  const calls = store.batchCalls;
  const wrongOwner = await app.inject({
    method: 'POST',
    url: path.replace(MORADOR_ID, OTHER_MORADOR_ID),
    headers: residentHeaders,
    payload
  });
  const wrongTenant = await app.inject({
    method: 'POST',
    url: path.replace(CONDOMINIO_ID, OTHER_CONDOMINIO_ID),
    headers: residentHeaders,
    payload
  });
  assert.equal(wrongOwner.statusCode, 403);
  assert.equal(wrongTenant.statusCode, 403);
  assert.equal(store.batchCalls, calls);
  await app.close();
});

test('invitation template replaces every documented placeholder deterministically', () => {
  const message = invitationMessage({
    condominiumName: 'Residencial A',
    residentName: 'Maria',
    generatedAt: NOW,
    expiresAt: EXPIRES_AT,
    token: '123456'
  });
  assert.equal(message.subject, 'Convite de acesso ao condomínio Residencial A');
  assert.equal(
    message.body,
    'Seu código para a entrada no condomínio Residencial A foi gerado por Maria às 05:00 do dia 24/08/2026 e será expirado em 25/08/2026 às 05:00.\nSeu código é: 123456'
  );
});

test('single invitation sends exactly one message per supplied channel and none without contacts', async () => {
  for (const contacts of [
    { email: 'ana@example.com', telefone: null, expectedEmail: 1, expectedSms: 0 },
    { email: null, telefone: '+5511999999999', expectedEmail: 0, expectedSms: 1 },
    { email: 'ana@example.com', telefone: '+5511999999999', expectedEmail: 1, expectedSms: 1 },
    { email: null, telefone: null, expectedEmail: 0, expectedSms: 0 }
  ]) {
    const convite = uniqueMemoryStore();
    const sent: { emails: unknown[]; sms: unknown[] } = { emails: [], sms: [] };
    const notifications: NotificationSender = {
      email: { async send(to, message) { sent.emails.push({ to, message }); } },
      sms: { async send(to, body) { sent.sms.push({ to, body }); } }
    };
    const app = Fastify({ logger: false });
    registerConviteRoutes(app, batchStore(contacts), convite, authenticator, notifications);
    const response = await app.inject({ method: 'POST', url: `/condominios/${CONDOMINIO_ID}/moradores/${MORADOR_ID}/convidados/${CONVIDADO_ID}/convites`, headers: residentHeaders, payload: { tipo: 'visitante', expiresAt: EXPIRES_AT.toISOString() } });
    assert.equal(response.statusCode, 201);
    assert.equal(sent.emails.length, contacts.expectedEmail);
    assert.equal(sent.sms.length, contacts.expectedSms);
    await app.close();
  }
});

test('createApp honors an explicit notification sender when a database is supplied', async () => {
  const convite = uniqueMemoryStore();
  const sent: string[] = [];
  const notificationSender: NotificationSender = {
    email: { async send(to) { sent.push(to); } },
    sms: { async send() { throw new Error('Unexpected SMS'); } }
  };
  const app = createApp({
    db: { ...batchStore({ email: 'ana@example.com' }), convite },
    authenticator,
    notificationSender
  });
  const response = await app.inject({
    method: 'POST',
    url: `/condominios/${CONDOMINIO_ID}/moradores/${MORADOR_ID}/convidados/${CONVIDADO_ID}/convites`,
    headers: residentHeaders,
    payload: { tipo: 'visitante', expiresAt: EXPIRES_AT.toISOString() }
  });

  assert.equal(response.statusCode, 201);
  assert.deepEqual(sent, ['ana@example.com']);
  await app.close();
});

test('production default reports unavailable delivery after issuing without exposing the token', async () => {
  const convite = uniqueMemoryStore();
  const app = createApp({
    db: { ...batchStore({ email: 'ana@example.com' }), convite },
    authenticator
  });
  const response = await app.inject({
    method: 'POST',
    url: `/condominios/${CONDOMINIO_ID}/moradores/${MORADOR_ID}/convidados/${CONVIDADO_ID}/convites`,
    headers: residentHeaders,
    payload: { tipo: 'visitante', expiresAt: EXPIRES_AT.toISOString() }
  });

  assert.equal(response.statusCode, 502);
  assert.equal(response.json().token, undefined);
  assert.equal(convite.activeTokens.size, 1);
  await app.close();
});

test('sender failure is explicit after issuance and does not expose the token', async () => {
  const convite = uniqueMemoryStore();
  const notifications: NotificationSender = {
    email: { async send() { throw new Error('provider unavailable'); } },
    sms: { async send() {} }
  };
  const app = Fastify({ logger: false });
  registerConviteRoutes(app, batchStore({ email: 'ana@example.com' }), convite, authenticator, notifications);
  const response = await app.inject({ method: 'POST', url: `/condominios/${CONDOMINIO_ID}/moradores/${MORADOR_ID}/convidados/${CONVIDADO_ID}/convites`, headers: residentHeaders, payload: { tipo: 'visitante', expiresAt: EXPIRES_AT.toISOString() } });
  assert.equal(response.statusCode, 502);
  assert.equal(response.json().token, undefined);
  assert.equal(convite.activeTokens.size, 1);
  await app.close();
});

test('batch creation issues only registered active guests in one atomic store call', async () => {
  const convite = uniqueMemoryStore();
  const db: AppDependencies = { ...batchStore(), convite };
  const app = createApp({ db, authenticator });
  const response = await app.inject({
    method: 'POST',
    url: `/condominios/${CONDOMINIO_ID}/moradores/${MORADOR_ID}/convites/multiplos`,
    headers: residentHeaders,
    payload: { convidadoIds: [CONVIDADO_ID, SECOND_CONVIDADO_ID] }
  });

  assert.equal(response.statusCode, 201);
  assert.equal(response.headers['cache-control'], 'no-store');
  assert.deepEqual(
    response.json().convites.map((item: { convidadoId: string }) => item.convidadoId),
    [CONVIDADO_ID, SECOND_CONVIDADO_ID]
  );
  assert.equal(convite.batchCalls, 1);
  assert.equal(convite.activeTokens.size, 2);
  await app.close();
});

test('batch validation rejects duplicates, inactive, cross-tenant, and cross-owner guests before storage', async () => {
  const cases = [
    [{}, 400],
    [{ convidadoIds: [CONVIDADO_ID, CONVIDADO_ID] }, 400],
    [{ convidadoIds: [uuid(999)] }, 404],
    [{ convidadoIds: [CONVIDADO_ID, uuid(999)] }, 404],
    [{ convidadoIds: [DELETED_CONVIDADO_ID] }, 404],
    [{ convidadoIds: [OTHER_CONVIDADO_ID] }, 404]
  ] as const;

  for (const [payload, status] of cases) {
    const convite = uniqueMemoryStore();
    const app = createApp({ db: { ...batchStore(), convite }, authenticator });
    const response = await app.inject({
      method: 'POST',
      url: `/condominios/${CONDOMINIO_ID}/moradores/${MORADOR_ID}/convites/multiplos`,
      headers: residentHeaders,
      payload
    });
    assert.equal(response.statusCode, status);
    assert.equal(convite.batchCalls, 0);
    await app.close();
  }
});

test('batch creation rejects disabled parents and fails closed without a token store', async () => {
  for (const options of [{ residentDeleted: true }, { condominiumDeleted: true }]) {
    const convite = uniqueMemoryStore();
    const app = createApp({ db: { ...batchStore(options), convite }, authenticator });
    const response = await app.inject({
      method: 'POST',
      url: `/condominios/${CONDOMINIO_ID}/moradores/${MORADOR_ID}/convites/multiplos`,
      headers: residentHeaders,
      payload: { convidadoIds: [CONVIDADO_ID] }
    });
    assert.equal(response.statusCode, 404);
    assert.equal(convite.batchCalls, 0);
    await app.close();
  }

  const app = createApp({ db: batchStore(), authenticator });
  const response = await app.inject({
    method: 'POST',
    url: `/condominios/${CONDOMINIO_ID}/moradores/${MORADOR_ID}/convites/multiplos`,
    headers: residentHeaders,
    payload: { convidadoIds: [CONVIDADO_ID] }
  });
  assert.equal(response.statusCode, 503);
  await app.close();
});
