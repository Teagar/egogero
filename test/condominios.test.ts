import assert from 'node:assert/strict';
import test from 'node:test';

import { createApp } from '../src/app.js';
import type { AppStore } from '../src/app.js';
import { createDevelopmentHeaderAuthenticator } from '../src/auth.js';

const authenticator = createDevelopmentHeaderAuthenticator(true);
const providerHeaders = {
  'x-development-user-id': 'provider-1',
  'x-development-user-role': 'provedor',
  'x-development-condominio-id': '*'
};
const moradorHeaders = {
  'x-development-user-id': 'resident-1',
  'x-development-user-role': 'morador',
  'x-development-condominio-id': '00000000-0000-4000-8000-000000000001'
};

type StoredCondominio = Awaited<ReturnType<AppStore['condominio']['create']>>;

function clone(condominio: StoredCondominio) {
  return {
    ...condominio,
    createdAt: new Date(condominio.createdAt),
    deletedAt: condominio.deletedAt ? new Date(condominio.deletedAt) : null
  };
}

function createFakeStore() {
  const rows = new Map<string, StoredCondominio>();
  let nextId = 1;

  const db: AppStore = {
    condominio: {
      async create({ data }) {
        const row = {
          id: `00000000-0000-4000-8000-${String(nextId).padStart(12, '0')}`,
          createdAt: new Date(Date.UTC(2026, 0, nextId)),
          deletedAt: null,
          ...data
        };

        nextId += 1;
        rows.set(row.id, row);
        return clone(row);
      },
      async findMany({ where, orderBy }) {
        assert.equal(where.deletedAt, null);
        assert.equal(orderBy.createdAt, 'desc');

        return Array.from(rows.values())
          .filter((row) => row.deletedAt === null)
          .sort((left, right) => right.createdAt.getTime() - left.createdAt.getTime())
          .map(clone);
      },
      async findFirst({ where }) {
        const row = rows.get(where.id);

        if (!row || row.deletedAt !== where.deletedAt) {
          return null;
        }

        return clone(row);
      },
      async updateMany({ where, data }) {
        const row = rows.get(where.id);

        if (!row || row.deletedAt !== where.deletedAt) {
          return { count: 0 };
        }

        rows.set(row.id, { ...row, ...data });
        return { count: 1 };
      }
    },
    morador: {
      async create() {
        throw new Error('Unexpected resident create');
      },
      async findMany() {
        throw new Error('Unexpected resident findMany');
      },
      async findFirst() {
        throw new Error('Unexpected resident findFirst');
      },
      async updateMany() {
        throw new Error('Unexpected resident updateMany');
      }
    },
    convidado: {
      async create() {
        throw new Error('Unexpected guest create');
      },
      async findMany() {
        throw new Error('Unexpected guest findMany');
      },
      async findFirst() {
        throw new Error('Unexpected guest findFirst');
      },
      async updateMany() {
        throw new Error('Unexpected guest updateMany');
      }
    }
  };

  return db;
}

test('provedor creates, edits and soft-deletes a condominium', async () => {
  const app = createApp({ db: createFakeStore(), authenticator });

  const createResponse = await app.inject({
    method: 'POST',
    url: '/condominios',
    headers: providerHeaders,
    payload: {
      nome: 'Residencial Aurora',
      responsavel: 'Ana Silva',
      tipo: 'residencial'
    }
  });

  assert.equal(createResponse.statusCode, 201);
  const created = createResponse.json();
  assert.match(created.id, /^[0-9a-f-]{36}$/);
  assert.equal(created.createdAt, '2026-01-01T00:00:00.000Z');
  assert.equal(created.nome, 'Residencial Aurora');
  assert.equal(created.responsavel, 'Ana Silva');
  assert.equal(created.tipo, 'residencial');

  const updateResponse = await app.inject({
    method: 'PATCH',
    url: `/condominios/${created.id}`,
    headers: providerHeaders,
    payload: {
      nome: 'Residencial Aurora Norte',
      responsavel: 'Bruno Costa',
      tipo: 'misto'
    }
  });

  assert.equal(updateResponse.statusCode, 200);
  assert.deepEqual(updateResponse.json(), {
    id: created.id,
    createdAt: '2026-01-01T00:00:00.000Z',
    nome: 'Residencial Aurora Norte',
    responsavel: 'Bruno Costa',
    tipo: 'misto'
  });

  const deleteResponse = await app.inject({
    method: 'DELETE',
    url: `/condominios/${created.id}`,
    headers: providerHeaders
  });

  assert.equal(deleteResponse.statusCode, 204);

  const getDeletedResponse = await app.inject({
    method: 'GET',
    url: `/condominios/${created.id}`,
    headers: providerHeaders
  });

  assert.equal(getDeletedResponse.statusCode, 404);

  const listResponse = await app.inject({ method: 'GET', url: '/condominios', headers: providerHeaders });

  assert.equal(listResponse.statusCode, 200);
  assert.deepEqual(listResponse.json(), []);

  await app.close();
});

test('morador receives 403 on condominium endpoints', async () => {
  const app = createApp({ db: createFakeStore(), authenticator });
  const id = '00000000-0000-4000-8000-000000000001';
  const requests = [
    { method: 'POST', url: '/condominios', payload: { nome: 'A', responsavel: 'B', tipo: 'C' } },
    { method: 'GET', url: '/condominios' },
    { method: 'GET', url: `/condominios/${id}` },
    { method: 'PATCH', url: `/condominios/${id}`, payload: { nome: 'Novo' } },
    { method: 'DELETE', url: `/condominios/${id}` }
  ] as const;

  for (const request of requests) {
    const response = await app.inject({ ...request, headers: moradorHeaders });
    assert.equal(response.statusCode, 403, `${request.method} ${request.url}`);
  }

  await app.close();
});

test('condominium creation validates required string fields', async () => {
  const app = createApp({ db: createFakeStore(), authenticator });
  const response = await app.inject({
    method: 'POST',
    url: '/condominios',
    headers: providerHeaders,
    payload: {
      nome: 'Residencial Aurora',
      responsavel: '',
      tipo: 'residencial'
    }
  });

  assert.equal(response.statusCode, 400);
  assert.deepEqual(response.json(), { error: 'Invalid condominium payload' });

  await app.close();
});
