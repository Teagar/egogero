import assert from 'node:assert/strict';
import test from 'node:test';

import { createApp } from '../src/app.js';
import type { AppStore } from '../src/app.js';
import { ROLES, createDevelopmentHeaderAuthenticator } from '../src/auth.js';
import type { Role } from '../src/auth.js';

const CONDOMINIO_ID = '00000000-0000-4000-8000-000000000001';
const MORADOR_ID = '00000000-0000-4000-8000-000000000101';
const createdAt = new Date('2026-01-01T00:00:00.000Z');
const authenticator = createDevelopmentHeaderAuthenticator('test');

const condominio = {
  id: CONDOMINIO_ID,
  createdAt,
  deletedAt: null,
  nome: 'Residencial Aurora',
  responsavel: 'Ana Silva',
  tipo: 'residencial'
};

const morador = {
  id: MORADOR_ID,
  createdAt,
  deletedAt: null,
  nome: 'Joao Moraes',
  condominioId: CONDOMINIO_ID,
  enderecoRua: 'Rua A',
  enderecoNumero: '123',
  enderecoBloco: null,
  enderecoApartamento: null
};

function createAuthorizationStore(): AppStore {
  return {
    condominio: {
      async create({ data }) {
        return { ...condominio, ...data };
      },
      async findMany() {
        return [condominio];
      },
      async findFirst({ where }) {
        return where.id === CONDOMINIO_ID ? condominio : null;
      },
      async updateMany({ where }) {
        return { count: where.id === CONDOMINIO_ID ? 1 : 0 };
      }
    },
    morador: {
      async create({ data }) {
        return { ...morador, ...data };
      },
      async findMany() {
        return [morador];
      },
      async findFirst({ where }) {
        return where.id === MORADOR_ID && (!where.condominioId || where.condominioId === CONDOMINIO_ID)
          ? morador
          : null;
      },
      async updateMany({ where }) {
        return { count: where.id === MORADOR_ID && where.condominioId === CONDOMINIO_ID ? 1 : 0 };
      }
    }
  };
}

type Endpoint = {
  name: string;
  request: {
    method: 'GET' | 'POST' | 'PATCH' | 'DELETE';
    url: string;
    payload?: Record<string, unknown>;
  };
  roles: readonly Role[];
  successStatus: number;
};

const endpoints: Endpoint[] = [
  {
    name: 'create condominium',
    request: {
      method: 'POST',
      url: '/condominios',
      payload: { nome: 'Residencial Aurora', responsavel: 'Ana Silva', tipo: 'residencial' }
    },
    roles: ['provedor'],
    successStatus: 201
  },
  { name: 'list condominiums', request: { method: 'GET', url: '/condominios' }, roles: ['provedor'], successStatus: 200 },
  {
    name: 'read condominium',
    request: { method: 'GET', url: `/condominios/${CONDOMINIO_ID}` },
    roles: ['provedor'],
    successStatus: 200
  },
  {
    name: 'update condominium',
    request: { method: 'PATCH', url: `/condominios/${CONDOMINIO_ID}`, payload: { nome: 'Novo nome' } },
    roles: ['provedor'],
    successStatus: 200
  },
  {
    name: 'delete condominium',
    request: { method: 'DELETE', url: `/condominios/${CONDOMINIO_ID}` },
    roles: ['provedor'],
    successStatus: 204
  },
  {
    name: 'create resident',
    request: {
      method: 'POST',
      url: '/moradores',
      payload: { condominioId: CONDOMINIO_ID, nome: 'Joao Moraes', endereco: { rua: 'Rua A', numero: '123' } }
    },
    roles: ['provedor', 'sindico'],
    successStatus: 201
  },
  {
    name: 'list residents',
    request: { method: 'GET', url: `/condominios/${CONDOMINIO_ID}/moradores` },
    roles: ['provedor', 'sindico'],
    successStatus: 200
  },
  {
    name: 'read resident',
    request: { method: 'GET', url: `/condominios/${CONDOMINIO_ID}/moradores/${MORADOR_ID}` },
    roles: ['provedor', 'sindico'],
    successStatus: 200
  },
  {
    name: 'update resident',
    request: {
      method: 'PATCH',
      url: `/condominios/${CONDOMINIO_ID}/moradores/${MORADOR_ID}`,
      payload: { nome: 'Novo nome' }
    },
    roles: ['provedor', 'sindico'],
    successStatus: 200
  },
  {
    name: 'delete resident',
    request: { method: 'DELETE', url: `/condominios/${CONDOMINIO_ID}/moradores/${MORADOR_ID}` },
    roles: ['provedor', 'sindico'],
    successStatus: 204
  }
];

function developmentHeaders(role: Role) {
  return {
    'x-development-user-id': `${role}-1`,
    'x-development-user-role': role
  };
}

test('RBAC matrix covers every official role and business endpoint', async () => {
  for (const endpoint of endpoints) {
    for (const role of ROLES) {
      const app = createApp({ db: createAuthorizationStore(), authenticator });
      const response = await app.inject({ ...endpoint.request, headers: developmentHeaders(role) });
      const expectedStatus = endpoint.roles.includes(role) ? endpoint.successStatus : 403;

      assert.equal(response.statusCode, expectedStatus, `${role}: ${endpoint.name}`);
      await app.close();
    }
  }
});

test('business endpoints reject missing identity and the legacy role header', async () => {
  for (const endpoint of endpoints) {
    const app = createApp({ db: createAuthorizationStore(), authenticator });
    const missingIdentity = await app.inject(endpoint.request);
    const forgedLegacyRole = await app.inject({
      ...endpoint.request,
      headers: { 'x-user-role': 'provedor' }
    });
    const developmentRoleWithoutIdentity = await app.inject({
      ...endpoint.request,
      headers: { 'x-development-user-role': 'provedor' }
    });

    assert.equal(missingIdentity.statusCode, 401, `missing identity: ${endpoint.name}`);
    assert.equal(forgedLegacyRole.statusCode, 401, `legacy header bypass: ${endpoint.name}`);
    assert.equal(developmentRoleWithoutIdentity.statusCode, 401, `role without identity: ${endpoint.name}`);
    await app.close();
  }
});

test('development authenticator is unavailable outside development and test', () => {
  assert.throws(
    () => createDevelopmentHeaderAuthenticator('production'),
    /disabled outside development and test/
  );
  assert.doesNotThrow(() => createDevelopmentHeaderAuthenticator('development'));
  assert.doesNotThrow(() => createDevelopmentHeaderAuthenticator('test'));
});
