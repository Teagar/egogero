import assert from 'node:assert/strict';
import test from 'node:test';

import { createApp } from '../src/app.js';
import type { AppStore } from '../src/app.js';
import { createDevelopmentHeaderAuthenticator } from '../src/auth.js';
import type { InvitationBatch, InvitationIssuer } from '../src/convites.js';

const authenticator = createDevelopmentHeaderAuthenticator(true);
const uuid = (n: number) => `00000000-0000-4000-8000-${String(n).padStart(12, '0')}`;
const condominioId = uuid(1);
const moradorId = uuid(2);
const otherCondominioId = uuid(3);
const otherMoradorId = uuid(4);
const guestId = uuid(5);
const secondGuestId = uuid(6);
const otherGuestId = uuid(7);
const deletedGuestId = uuid(8);
const residentHeaders = {
  'x-development-user-id': moradorId,
  'x-development-user-role': 'morador',
  'x-development-condominio-id': condominioId
};
const batchUrl = `/condominios/${condominioId}/moradores/${moradorId}/convites/multiplos`;

function batchStore({ condominiumDeleted = false, residentDeleted = false } = {}): AppStore {
  const condominios = new Map([[condominioId, condominiumDeleted ? new Date() : null], [otherCondominioId, null]]);
  const moradores = new Map([[moradorId, { condominioId, deletedAt: residentDeleted ? new Date() : null }], [otherMoradorId, { condominioId: otherCondominioId, deletedAt: null }]]);
  const convidados = new Map([
    [guestId, { condominioId, moradorId, deletedAt: null }],
    [secondGuestId, { condominioId, moradorId, deletedAt: null }],
    [otherGuestId, { condominioId: otherCondominioId, moradorId: otherMoradorId, deletedAt: null }],
    [deletedGuestId, { condominioId, moradorId, deletedAt: new Date() }]
  ]);
  const record = (id: string, condo: string, owner: string, deletedAt: Date | null) => ({
    id,
    createdAt: new Date(),
    deletedAt,
    nome: 'Guest',
    condominioId: condo,
    moradorId: owner,
    ultimoUsoEm: null
  });

  return {
    condominio: {
      async create() { throw new Error('Unexpected condominium create'); },
      async findMany() { return []; },
      async findFirst({ where }) { return condominios.get(where.id) === null ? { id: where.id, createdAt: new Date(), deletedAt: null, nome: 'A', responsavel: 'B', tipo: 'C' } : null; },
      async updateMany() { return { count: 0 }; }
    },
    morador: {
      async create() { throw new Error('Unexpected resident create'); },
      async findMany() { return []; },
      async findFirst({ where }) {
        const row = moradores.get(where.id);
        return row && row.condominioId === where.condominioId && row.deletedAt === null && condominios.get(row.condominioId) === null
          ? { id: where.id, createdAt: new Date(), deletedAt: null, nome: 'Resident', condominioId: row.condominioId, enderecoRua: 'A', enderecoNumero: '1', enderecoBloco: null, enderecoApartamento: null }
          : null;
      },
      async updateMany() { return { count: 0 }; }
    },
    convidado: {
      async create() { throw new Error('Guests must not be created by batch invitations'); },
      async findMany() { return []; },
      async findFirst({ where }) {
        const row = convidados.get(where.id);
        return row && row.condominioId === where.condominioId && row.moradorId === where.moradorId && row.deletedAt === null && condominios.get(row.condominioId) === null
          ? record(where.id, row.condominioId, row.moradorId, row.deletedAt)
          : null;
      },
      async updateMany() { return { count: 0 }; }
    }
  };
}

function issuer(batches: InvitationBatch[]): InvitationIssuer {
  return {
    async issueForRegisteredGuests(batch) {
      batches.push(batch);
      return batch.convidadoIds.map((convidadoId, index) => ({
        conviteId: uuid(100 + index), convidadoId, token: `token-${index}`, expiraEm: new Date('2026-12-01T00:00:00.000Z')
      }));
    }
  };
}

test('batch invitations issue every active, registered guest in one call', async () => {
  const batches: InvitationBatch[] = [];
  const app = createApp({ db: batchStore(), authenticator, invitationIssuer: issuer(batches) });
  const response = await app.inject({ method: 'POST', url: batchUrl, headers: residentHeaders, payload: { convidadoIds: [guestId, secondGuestId] } });

  assert.equal(response.statusCode, 201);
  assert.deepEqual(batches, [{ condominioId, moradorId, convidadoIds: [guestId, secondGuestId] }]);
  assert.deepEqual(response.json().convites.map((convite: { convidadoId: string }) => convite.convidadoId), [guestId, secondGuestId]);
  await app.close();
});

test('batch invitations reject malformed, duplicate, unknown, deleted, cross-tenant, and cross-owner guests before issuing', async () => {
  const cases = [
    [{}, 400],
    [{ convidadoIds: [guestId, guestId] }, 400],
    [{ convidadoIds: [uuid(999)] }, 404],
    [{ convidadoIds: [guestId, uuid(999)] }, 404],
    [{ convidadoIds: [deletedGuestId] }, 404],
    [{ convidadoIds: [otherGuestId] }, 404]
  ] as const;

  for (const [payload, status] of cases) {
    const batches: InvitationBatch[] = [];
    const app = createApp({ db: batchStore(), authenticator, invitationIssuer: issuer(batches) });
    const response = await app.inject({ method: 'POST', url: batchUrl, headers: residentHeaders, payload });
    assert.equal(response.statusCode, status);
    assert.equal(batches.length, 0);
    await app.close();
  }
});

test('batch invitations are authorized and tenant-scoped before issuing', async () => {
  const batches: InvitationBatch[] = [];
  const app = createApp({ db: batchStore(), authenticator, invitationIssuer: issuer(batches) });
  const forbidden = await app.inject({ method: 'POST', url: batchUrl, headers: { ...residentHeaders, 'x-development-user-id': otherMoradorId }, payload: { convidadoIds: [guestId] } });
  const otherTenant = await app.inject({ method: 'POST', url: batchUrl.replace(condominioId, otherCondominioId).replace(moradorId, otherMoradorId), headers: residentHeaders, payload: { convidadoIds: [otherGuestId] } });

  assert.equal(forbidden.statusCode, 403);
  assert.equal(otherTenant.statusCode, 403);
  assert.equal(batches.length, 0);
  await app.close();
});

test('batch invitations reject disabled resident and condominium parents before issuing', async () => {
  for (const options of [{ residentDeleted: true }, { condominiumDeleted: true }]) {
    const batches: InvitationBatch[] = [];
    const app = createApp({ db: batchStore(options), authenticator, invitationIssuer: issuer(batches) });
    const response = await app.inject({ method: 'POST', url: batchUrl, headers: residentHeaders, payload: { convidadoIds: [guestId] } });

    assert.equal(response.statusCode, 404);
    assert.deepEqual(response.json(), { error: 'Resident not found' });
    assert.equal(batches.length, 0);
    await app.close();
  }
});

test('batch invitations fail closed when no issuer is wired', async () => {
  const app = createApp({ db: batchStore(), authenticator });
  const response = await app.inject({ method: 'POST', url: batchUrl, headers: residentHeaders, payload: { convidadoIds: [guestId] } });

  assert.equal(response.statusCode, 503);
  assert.deepEqual(response.json(), { error: 'Invitation issuing is unavailable' });
  await app.close();
});
