import assert from 'node:assert/strict';
import test from 'node:test';

import { createApp } from '../src/app.js';
import type { AppStore } from '../src/app.js';
import { ROLES, createDevelopmentHeaderAuthenticator } from '../src/auth.js';
import type { Role } from '../src/auth.js';

const CONDOMINIO_ID = '00000000-0000-4000-8000-000000000001';
const OTHER_CONDOMINIO_ID = '00000000-0000-4000-8000-000000000002';
const MORADOR_ID = '00000000-0000-4000-8000-000000000101';
const createdAt = new Date('2026-01-01T00:00:00.000Z');
const authenticator = createDevelopmentHeaderAuthenticator(true);

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

const otherCondominio = { ...condominio, id: OTHER_CONDOMINIO_ID, nome: 'Residencial Horizonte' };
const otherMorador = { ...morador, id: '00000000-0000-4000-8000-000000000102', condominioId: OTHER_CONDOMINIO_ID };

function createAuthorizationStore(): AppStore {
  return {
    condominio: {
      async create({ data }) {
        return { ...condominio, ...data };
      },
      async findMany() {
        return [condominio, otherCondominio];
      },
      async findFirst({ where }) {
        return [condominio, otherCondominio].find((row) => row.id === where.id) ?? null;
      },
      async updateMany({ where }) {
        return { count: [CONDOMINIO_ID, OTHER_CONDOMINIO_ID].includes(where.id) ? 1 : 0 };
      }
    },
    morador: {
      async create({ data }) {
        return { ...morador, ...data };
      },
      async findMany({ where }) {
        return [morador, otherMorador].filter((row) => row.condominioId === where.condominioId);
      },
      async findFirst({ where }) {
        return (
          [morador, otherMorador].find(
            (row) => row.id === where.id && (!where.condominioId || where.condominioId === row.condominioId)
          ) ?? null
        );
      },
      async updateMany({ where }) {
        const found = [morador, otherMorador].some(
          (row) => row.id === where.id && row.condominioId === where.condominioId
        );
        return { count: found ? 1 : 0 };
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
    'x-development-user-role': role,
    'x-development-condominio-id': role === 'provedor' ? '*' : CONDOMINIO_ID
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
      headers: { 'x-user-id': 'provider-1', 'x-user-role': 'provedor', 'x-condominio-id': '*' }
    });
    const developmentRoleWithoutIdentity = await app.inject({
      ...endpoint.request,
      headers: { 'x-development-user-role': 'provedor' }
    });
    const developmentIdentityWithoutScope = await app.inject({
      ...endpoint.request,
      headers: { 'x-development-user-id': 'provider-1', 'x-development-user-role': 'provedor' }
    });
    const developmentProviderWithoutGlobalScope = await app.inject({
      ...endpoint.request,
      headers: {
        'x-development-user-id': 'provider-1',
        'x-development-user-role': 'provedor',
        'x-development-condominio-id': CONDOMINIO_ID
      }
    });

    assert.equal(missingIdentity.statusCode, 401, `missing identity: ${endpoint.name}`);
    assert.equal(forgedLegacyRole.statusCode, 401, `legacy header bypass: ${endpoint.name}`);
    assert.equal(developmentRoleWithoutIdentity.statusCode, 401, `role without identity: ${endpoint.name}`);
    assert.equal(developmentIdentityWithoutScope.statusCode, 401, `identity without scope: ${endpoint.name}`);
    assert.equal(developmentProviderWithoutGlobalScope.statusCode, 401, `provider without global scope: ${endpoint.name}`);
    await app.close();
  }
});

test('tenant matrix prevents a sindico from reaching another condominium before store access', async () => {
  const otherResidentEndpoints = endpoints.slice(5).map((endpoint) => ({
    ...endpoint,
    request: {
      ...endpoint.request,
      url: endpoint.request.url.replaceAll(CONDOMINIO_ID, OTHER_CONDOMINIO_ID).replaceAll(MORADOR_ID, otherMorador.id),
      payload: endpoint.request.payload
        ? { ...endpoint.request.payload, condominioId: OTHER_CONDOMINIO_ID }
        : undefined
    }
  }));

  for (const endpoint of otherResidentEndpoints) {
    for (const role of ROLES) {
      let storeCalls = 0;
      let condominioStoreCalls = 0;
      const store = createAuthorizationStore();
      const db: AppStore = {
        condominio: {
          create: async (args) => {
            storeCalls += 1;
            condominioStoreCalls += 1;
            return store.condominio.create(args);
          },
          findMany: async (args) => {
            storeCalls += 1;
            condominioStoreCalls += 1;
            return store.condominio.findMany(args);
          },
          findFirst: async (args) => {
            storeCalls += 1;
            condominioStoreCalls += 1;
            return store.condominio.findFirst(args);
          },
          updateMany: async (args) => {
            storeCalls += 1;
            condominioStoreCalls += 1;
            return store.condominio.updateMany(args);
          }
        },
        morador: {
          create: async (args) => {
            storeCalls += 1;
            return store.morador.create(args);
          },
          findMany: async (args) => {
            storeCalls += 1;
            return store.morador.findMany(args);
          },
          findFirst: async (args) => {
            storeCalls += 1;
            return store.morador.findFirst(args);
          },
          updateMany: async (args) => {
            storeCalls += 1;
            return store.morador.updateMany(args);
          }
        }
      };
      const app = createApp({ db, authenticator });
      const response = await app.inject({ ...endpoint.request, headers: developmentHeaders(role) });

      if (role === 'provedor') {
        assert.equal(response.statusCode, endpoint.successStatus, `${role}: ${endpoint.name}`);
        assert.ok(storeCalls > 0, `${role}: ${endpoint.name} should reach its tenant data`);
        assert.equal(condominioStoreCalls, 0, `${role}: ${endpoint.name} used a preliminary condominium check`);
      } else {
        assert.equal(response.statusCode, 403, `${role}: ${endpoint.name}`);
        assert.equal(storeCalls, 0, `${role}: ${endpoint.name} crossed the authorization boundary`);
      }

      await app.close();
    }
  }
});

test('route inventory keeps every business route in the RBAC matrix', async () => {
  const app = createApp();
  await app.ready();

  assert.equal(
    app.printRoutes({ commonPrefix: false }),
    [
      '├── /health (GET, HEAD)',
      '├── /condominios (POST, GET, HEAD)',
      '│   └── /:id|:condominioId (GET, HEAD, PATCH, DELETE)',
      '│       └── /moradores (GET, HEAD)',
      '│           └── /:id (GET, HEAD, PATCH, DELETE)',
      '└── /moradores (POST)',
      ''
    ].join('\n')
  );
  assert.equal(endpoints.length, 10);

  await app.close();
});

test('development authenticator requires explicit opt-in', () => {
  assert.throws(() => createDevelopmentHeaderAuthenticator(false), /requires explicit opt-in/);
  assert.doesNotThrow(() => createDevelopmentHeaderAuthenticator(true));
});
