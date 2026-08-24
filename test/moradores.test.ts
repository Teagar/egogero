import assert from 'node:assert/strict';
import test from 'node:test';

import { createApp } from '../src/app.js';
import type { AppStore } from '../src/app.js';
import { createDevelopmentHeaderAuthenticator } from '../src/auth.js';

const authenticator = createDevelopmentHeaderAuthenticator('test');
const providerHeaders = { 'x-development-user-id': 'provider-1', 'x-development-user-role': 'provedor' };
const sindicoHeaders = { 'x-development-user-id': 'manager-1', 'x-development-user-role': 'sindico' };
const moradorHeaders = { 'x-development-user-id': 'resident-1', 'x-development-user-role': 'morador' };

type StoredCondominio = Awaited<ReturnType<AppStore['condominio']['create']>>;
type StoredMorador = Awaited<ReturnType<AppStore['morador']['create']>>;

function cloneCondominio(condominio: StoredCondominio) {
  return {
    ...condominio,
    createdAt: new Date(condominio.createdAt),
    deletedAt: condominio.deletedAt ? new Date(condominio.deletedAt) : null
  };
}

function cloneMorador(morador: StoredMorador) {
  return {
    ...morador,
    createdAt: new Date(morador.createdAt),
    deletedAt: morador.deletedAt ? new Date(morador.deletedAt) : null
  };
}

function uuid(nextId: number) {
  return `00000000-0000-4000-8000-${String(nextId).padStart(12, '0')}`;
}

function createFakeStore() {
  const condominios = new Map<string, StoredCondominio>();
  const moradores = new Map<string, StoredMorador>();
  let nextCondominioId = 1;
  let nextMoradorId = 101;

  const db: AppStore = {
    condominio: {
      async create({ data }) {
        const row = {
          id: uuid(nextCondominioId),
          createdAt: new Date(Date.UTC(2026, 0, nextCondominioId)),
          deletedAt: null,
          ...data
        };

        nextCondominioId += 1;
        condominios.set(row.id, row);
        return cloneCondominio(row);
      },
      async findMany({ where, orderBy }) {
        assert.equal(where.deletedAt, null);
        assert.equal(orderBy.createdAt, 'desc');

        return Array.from(condominios.values())
          .filter((row) => row.deletedAt === null)
          .sort((left, right) => right.createdAt.getTime() - left.createdAt.getTime())
          .map(cloneCondominio);
      },
      async findFirst({ where }) {
        const row = condominios.get(where.id);

        if (!row || row.deletedAt !== where.deletedAt) {
          return null;
        }

        return cloneCondominio(row);
      },
      async updateMany({ where, data }) {
        const row = condominios.get(where.id);

        if (!row || row.deletedAt !== where.deletedAt) {
          return { count: 0 };
        }

        condominios.set(row.id, { ...row, ...data });
        return { count: 1 };
      }
    },
    morador: {
      async create({ data }) {
        const row = {
          id: uuid(nextMoradorId),
          createdAt: new Date(Date.UTC(2026, 0, nextMoradorId - 100)),
          deletedAt: null,
          ...data
        };

        nextMoradorId += 1;
        moradores.set(row.id, row);
        return cloneMorador(row);
      },
      async findMany({ where, orderBy }) {
        assert.equal(where.deletedAt, null);
        assert.equal(orderBy.createdAt, 'desc');

        return Array.from(moradores.values())
          .filter((row) => row.condominioId === where.condominioId && row.deletedAt === null)
          .sort((left, right) => right.createdAt.getTime() - left.createdAt.getTime())
          .map(cloneMorador);
      },
      async findFirst({ where }) {
        const row = moradores.get(where.id);

        if (!row || row.deletedAt !== where.deletedAt) {
          return null;
        }

        if (where.condominioId && row.condominioId !== where.condominioId) {
          return null;
        }

        return cloneMorador(row);
      },
      async updateMany({ where, data }) {
        const row = moradores.get(where.id);

        if (!row || row.deletedAt !== where.deletedAt || row.condominioId !== where.condominioId) {
          return { count: 0 };
        }

        moradores.set(row.id, { ...row, ...data });
        return { count: 1 };
      }
    }
  };

  return db;
}

async function createCondominio(app: ReturnType<typeof createApp>, nome = 'Residencial Aurora') {
  const response = await app.inject({
    method: 'POST',
    url: '/condominios',
    headers: providerHeaders,
    payload: { nome, responsavel: 'Ana Silva', tipo: 'residencial' }
  });

  assert.equal(response.statusCode, 201);
  return response.json() as { id: string };
}

async function createMorador(app: ReturnType<typeof createApp>, condominioId: string, nome = 'Joao Moraes') {
  const response = await app.inject({
    method: 'POST',
    url: '/moradores',
    headers: providerHeaders,
    payload: { condominioId, nome, endereco: { rua: 'Rua A', numero: '123' } }
  });

  assert.equal(response.statusCode, 201);
  return response.json() as { id: string; condominioId: string; nome: string };
}

test('provedor or sindico creates resident only for an active condominium', async () => {
  const app = createApp({ db: createFakeStore(), authenticator });
  const condominio = await createCondominio(app);

  const createResponse = await app.inject({
    method: 'POST',
    url: '/moradores',
    headers: sindicoHeaders,
    payload: {
      condominioId: condominio.id,
      nome: 'Maria Souza',
      endereco: { rua: 'Rua das Palmeiras', numero: '45' }
    }
  });

  assert.equal(createResponse.statusCode, 201);
  assert.deepEqual(createResponse.json(), {
    id: '00000000-0000-4000-8000-000000000101',
    createdAt: '2026-01-01T00:00:00.000Z',
    condominioId: condominio.id,
    nome: 'Maria Souza',
    endereco: { rua: 'Rua das Palmeiras', numero: '45' }
  });

  const deletedCondominio = await createCondominio(app, 'Residencial Inativo');
  const deleteResponse = await app.inject({
    method: 'DELETE',
    url: `/condominios/${deletedCondominio.id}`,
    headers: providerHeaders
  });
  assert.equal(deleteResponse.statusCode, 204);

  const inactiveResponse = await app.inject({
    method: 'POST',
    url: '/moradores',
    headers: providerHeaders,
    payload: {
      condominioId: deletedCondominio.id,
      nome: 'Pedro Lima',
      endereco: { bloco: 'B', apartamento: '204' }
    }
  });

  assert.equal(inactiveResponse.statusCode, 404);
  assert.deepEqual(inactiveResponse.json(), { error: 'Condominium not found' });

  const invalidResponse = await app.inject({
    method: 'POST',
    url: '/moradores',
    headers: providerHeaders,
    payload: { condominioId: 'not-a-uuid', nome: 'Pedro Lima', endereco: { rua: 'Rua A', numero: '1' } }
  });

  assert.equal(invalidResponse.statusCode, 400);
  assert.deepEqual(invalidResponse.json(), { error: 'Invalid resident payload' });

  await app.close();
});

test('listing residents by condominium does not leak other condominiums or deleted residents', async () => {
  const app = createApp({ db: createFakeStore(), authenticator });
  const firstCondominio = await createCondominio(app, 'Residencial A');
  const secondCondominio = await createCondominio(app, 'Residencial B');
  const firstResident = await createMorador(app, firstCondominio.id, 'Morador A');
  await createMorador(app, secondCondominio.id, 'Morador B');
  const deletedResident = await createMorador(app, firstCondominio.id, 'Morador Excluido');

  const deleteResponse = await app.inject({
    method: 'DELETE',
    url: `/condominios/${firstCondominio.id}/moradores/${deletedResident.id}`,
    headers: providerHeaders
  });
  assert.equal(deleteResponse.statusCode, 204);

  const listResponse = await app.inject({
    method: 'GET',
    url: `/condominios/${firstCondominio.id}/moradores`,
    headers: providerHeaders
  });

  assert.equal(listResponse.statusCode, 200);
  assert.deepEqual(listResponse.json(), [
    {
      id: firstResident.id,
      createdAt: '2026-01-01T00:00:00.000Z',
      condominioId: firstCondominio.id,
      nome: 'Morador A',
      endereco: { rua: 'Rua A', numero: '123' }
    }
  ]);

  await app.close();
});

test('resident read, update and delete are scoped to the condominium', async () => {
  const app = createApp({ db: createFakeStore(), authenticator });
  const firstCondominio = await createCondominio(app, 'Residencial A');
  const secondCondominio = await createCondominio(app, 'Residencial B');
  const resident = await createMorador(app, firstCondominio.id, 'Carlos Nunes');

  const leakedGetResponse = await app.inject({
    method: 'GET',
    url: `/condominios/${secondCondominio.id}/moradores/${resident.id}`,
    headers: providerHeaders
  });
  assert.equal(leakedGetResponse.statusCode, 404);

  const leakedPatchResponse = await app.inject({
    method: 'PATCH',
    url: `/condominios/${secondCondominio.id}/moradores/${resident.id}`,
    headers: providerHeaders,
    payload: { nome: 'Carlos Vazado' }
  });
  assert.equal(leakedPatchResponse.statusCode, 404);

  const updateResponse = await app.inject({
    method: 'PATCH',
    url: `/condominios/${firstCondominio.id}/moradores/${resident.id}`,
    headers: providerHeaders,
    payload: { nome: 'Carlos Nunes Filho', endereco: { bloco: 'C', apartamento: '301' } }
  });

  assert.equal(updateResponse.statusCode, 200);
  assert.deepEqual(updateResponse.json(), {
    id: resident.id,
    createdAt: '2026-01-01T00:00:00.000Z',
    condominioId: firstCondominio.id,
    nome: 'Carlos Nunes Filho',
    endereco: { bloco: 'C', apartamento: '301' }
  });

  const leakedDeleteResponse = await app.inject({
    method: 'DELETE',
    url: `/condominios/${secondCondominio.id}/moradores/${resident.id}`,
    headers: providerHeaders
  });
  assert.equal(leakedDeleteResponse.statusCode, 404);

  const deleteResponse = await app.inject({
    method: 'DELETE',
    url: `/condominios/${firstCondominio.id}/moradores/${resident.id}`,
    headers: providerHeaders
  });
  assert.equal(deleteResponse.statusCode, 204);

  const getDeletedResponse = await app.inject({
    method: 'GET',
    url: `/condominios/${firstCondominio.id}/moradores/${resident.id}`,
    headers: providerHeaders
  });
  assert.equal(getDeletedResponse.statusCode, 404);

  await app.close();
});

test('resident endpoints validate payload and authorization boundary', async () => {
  const app = createApp({ db: createFakeStore(), authenticator });
  const condominio = await createCondominio(app);
  const resident = await createMorador(app, condominio.id);

  const requests = [
    { method: 'POST', url: '/moradores', payload: { condominioId: condominio.id, nome: 'A', endereco: { rua: 'A', numero: '1' } } },
    { method: 'GET', url: `/condominios/${condominio.id}/moradores` },
    { method: 'GET', url: `/condominios/${condominio.id}/moradores/${resident.id}` },
    { method: 'PATCH', url: `/condominios/${condominio.id}/moradores/${resident.id}`, payload: { nome: 'Novo' } },
    { method: 'DELETE', url: `/condominios/${condominio.id}/moradores/${resident.id}` }
  ] as const;

  for (const request of requests) {
    const missingRoleResponse = await app.inject(request);
    assert.equal(missingRoleResponse.statusCode, 401, `${request.method} ${request.url}`);

    const forbiddenResponse = await app.inject({ ...request, headers: moradorHeaders });
    assert.equal(forbiddenResponse.statusCode, 403, `${request.method} ${request.url}`);
  }

  const partialAddressResponse = await app.inject({
    method: 'POST',
    url: '/moradores',
    headers: providerHeaders,
    payload: { condominioId: condominio.id, nome: 'Endereco Parcial', endereco: { rua: 'Rua A' } }
  });
  assert.equal(partialAddressResponse.statusCode, 400);
  assert.deepEqual(partialAddressResponse.json(), { error: 'Invalid resident payload' });

  const mixedAddressResponse = await app.inject({
    method: 'PATCH',
    url: `/condominios/${condominio.id}/moradores/${resident.id}`,
    headers: providerHeaders,
    payload: { endereco: { rua: 'Rua A', numero: '1', bloco: 'B', apartamento: '2' } }
  });
  assert.equal(mixedAddressResponse.statusCode, 400);
  assert.deepEqual(mixedAddressResponse.json(), { error: 'Invalid resident payload' });

  await app.close();
});
