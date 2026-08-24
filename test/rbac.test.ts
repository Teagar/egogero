import assert from 'node:assert/strict';
import test from 'node:test';

import { createApp } from '../src/app.js';
import type { AppDependencies } from '../src/app.js';
import { ROLES, createDevelopmentHeaderAuthenticator } from '../src/auth.js';
import type { Role } from '../src/auth.js';

const CONDOMINIO_ID = '00000000-0000-4000-8000-000000000001';
const OTHER_CONDOMINIO_ID = '00000000-0000-4000-8000-000000000002';
const MORADOR_ID = '00000000-0000-4000-8000-000000000101';
const CONVIDADO_ID = '00000000-0000-4000-8000-000000000201';
const NOTIFICATION_ID = '00000000-0000-4000-8000-000000000401';
const DEVICE_ID = '00000000-0000-4000-8000-000000000501';
const createdAt = new Date('2026-01-01T00:00:00.000Z');
const authenticator = createDevelopmentHeaderAuthenticator(true);

const condominio = {
  id: CONDOMINIO_ID,
  createdAt,
  deletedAt: null,
  nome: 'Residencial Aurora',
  responsavel: 'Ana Silva',
  tipo: 'residencial',
  timezone: 'America/Sao_Paulo'
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
const convidado = {
  id: CONVIDADO_ID,
  createdAt,
  deletedAt: null,
  nome: 'Convidado',
  condominioId: CONDOMINIO_ID,
  moradorId: MORADOR_ID,
  ultimoUsoEm: null
};
const otherConvidado = {
  ...convidado,
  id: '00000000-0000-4000-8000-000000000202',
  condominioId: OTHER_CONDOMINIO_ID,
  moradorId: otherMorador.id
};
const convite = {
  id: '00000000-0000-4000-8000-000000000301',
  createdAt,
  deletedAt: null,
  condominioId: CONDOMINIO_ID,
  moradorId: MORADOR_ID,
  convidadoId: CONVIDADO_ID,
  tipo: 'visitante' as const,
  expiresAt: new Date('2099-01-01T00:00:00.000Z'),
  usedAt: null,
  revokedAt: null,
  tokenDigest: null,
  timeZone: 'America/Sao_Paulo'
};

function createAuthorizationStore(): AppDependencies {
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
    },
    convidado: {
      async create({ data }) {
        return { ...convidado, ...data };
      },
      async findMany({ where }) {
        return [convidado, otherConvidado].filter(
          (row) => row.condominioId === where.condominioId && row.moradorId === where.moradorId
        );
      },
      async findFirst({ where }) {
        return (
          [convidado, otherConvidado].find(
            (row) => row.id === where.id && row.condominioId === where.condominioId && row.moradorId === where.moradorId
          ) ?? null
        );
      },
      async updateMany({ where }) {
        const found = [convidado, otherConvidado].some(
          (row) => row.id === where.id && row.condominioId === where.condominioId && row.moradorId === where.moradorId
        );
        return { count: found ? 1 : 0 };
      }
    },
    convite: {
      async issueIdempotent(args) {
        const results = args.invitations.map((item, index) => ({
          convite: { ...convite, ...item, id: `convite-${index}` },
          token: String(index).padStart(6, '0')
        }));
        return { statusCode: 201, responseText: JSON.stringify(await args.buildResponse(results)), replayed: false };
      },
      async createActive(data) {
        return { ...convite, ...data };
      },
      async createBatchActive(data) {
        return data.map((item, index) => ({ ...convite, ...item, id: `convite-${index}` }));
      },
      async validateActive(_args, now) {
        return {
          allowed: true,
          guest: { name: convidado.nome },
          invitation: { type: convite.tipo },
          event: {
            invitationId: convite.id,
            condominiumId: CONDOMINIO_ID,
            residentId: MORADOR_ID,
            guestId: CONVIDADO_ID,
            invitationType: convite.tipo,
            usedAt: now
          }
        };
      },
      async listOwnedAudits() {
        return [];
      },
      async revokeActive() {
        return 'revoked' as const;
      }
    },
    dispositivo: {
      async create({ condominiumId, name }) {
        return {
          device: {
            id: DEVICE_ID,
            createdAt,
            deletedAt: null,
            nome: name,
            condominioId: condominiumId,
            status: 'ativo' as const,
            ultimoUsoEm: null
          },
          apiKey: `egdev_${'a'.repeat(43)}`
        };
      },
      async list() {
        return [];
      },
      async revoke() {
        return 'revoked' as const;
      },
      async authenticate() {
        return null;
      }
    },
    notificacao: {
      async list() {
        return [];
      },
      async markRead() {
        return 'read' as const;
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
      payload: { nome: 'Residencial Aurora', responsavel: 'Ana Silva', tipo: 'residencial', timezone: 'America/Sao_Paulo' }
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
  },
  {
    name: 'list recent guests',
    request: { method: 'GET', url: `/condominios/${CONDOMINIO_ID}/moradores/${MORADOR_ID}/convidados/recentes` },
    roles: ['provedor', 'sindico', 'morador'],
    successStatus: 200
  },
  {
    name: 'create guest',
    request: {
      method: 'POST',
      url: `/condominios/${CONDOMINIO_ID}/moradores/${MORADOR_ID}/convidados`,
      payload: { nome: 'Convidado' }
    },
    roles: ['provedor', 'sindico', 'morador'],
    successStatus: 201
  },
  {
    name: 'list guests',
    request: { method: 'GET', url: `/condominios/${CONDOMINIO_ID}/moradores/${MORADOR_ID}/convidados` },
    roles: ['provedor', 'sindico', 'morador'],
    successStatus: 200
  },
  {
    name: 'read guest',
    request: {
      method: 'GET',
      url: `/condominios/${CONDOMINIO_ID}/moradores/${MORADOR_ID}/convidados/${CONVIDADO_ID}`
    },
    roles: ['provedor', 'sindico', 'morador'],
    successStatus: 200
  },
  {
    name: 'update guest',
    request: {
      method: 'PATCH',
      url: `/condominios/${CONDOMINIO_ID}/moradores/${MORADOR_ID}/convidados/${CONVIDADO_ID}`,
      payload: { nome: 'Novo nome' }
    },
    roles: ['provedor', 'sindico', 'morador'],
    successStatus: 200
  },
  {
    name: 'delete guest',
    request: {
      method: 'DELETE',
      url: `/condominios/${CONDOMINIO_ID}/moradores/${MORADOR_ID}/convidados/${CONVIDADO_ID}`
    },
    roles: ['provedor', 'sindico', 'morador'],
    successStatus: 204
  },
  {
    name: 'create invitation',
    request: {
      method: 'POST',
      url: `/condominios/${CONDOMINIO_ID}/moradores/${MORADOR_ID}/convidados/${CONVIDADO_ID}/convites`,
      payload: { tipo: 'visitante', expiresAt: '2099-01-01T00:00:00.000Z' }
    },
    roles: ['provedor', 'sindico', 'morador'],
    successStatus: 201
  },
  {
    name: 'create batch invitations',
    request: {
      method: 'POST',
      url: `/condominios/${CONDOMINIO_ID}/moradores/${MORADOR_ID}/convites/multiplos`,
      payload: { convidadoIds: [CONVIDADO_ID] }
    },
    roles: ['provedor', 'sindico', 'morador'],
    successStatus: 201
  },
  {
    name: 'revoke invitation',
    request: {
      method: 'DELETE',
      url: `/condominios/${CONDOMINIO_ID}/moradores/${MORADOR_ID}/convites/${convite.id}`
    },
    roles: ['provedor', 'sindico', 'morador'],
    successStatus: 204
  },
  {
    name: 'update condominium invitation limit',
    request: { method: 'PATCH', url: `/condominios/${CONDOMINIO_ID}/limite-diario-convites`, payload: { dailyInvitationLimit: 10 } },
    roles: ['provedor', 'sindico'],
    successStatus: 200
  },
  {
    name: 'update resident invitation limit',
    request: {
      method: 'PATCH',
      url: `/condominios/${CONDOMINIO_ID}/moradores/${MORADOR_ID}/limite-diario-convites`,
      payload: { dailyInvitationLimit: 10 }
    },
    roles: ['provedor', 'sindico'],
    successStatus: 200
  },
  {
    name: 'list owned access audits',
    request: { method: 'GET', url: `/condominios/${CONDOMINIO_ID}/moradores/${MORADOR_ID}/auditorias-acesso` },
    roles: ['morador'],
    successStatus: 200
  },
  {
    name: 'list own notifications',
    request: { method: 'GET', url: `/condominios/${CONDOMINIO_ID}/moradores/${MORADOR_ID}/notificacoes` },
    roles: ['morador'],
    successStatus: 200
  },
  {
    name: 'mark own notification read',
    request: { method: 'PATCH', url: `/condominios/${CONDOMINIO_ID}/moradores/${MORADOR_ID}/notificacoes/${NOTIFICATION_ID}` },
    roles: ['morador'],
    successStatus: 200
  },
  {
    name: 'provision gatehouse device',
    request: { method: 'POST', url: `/condominios/${CONDOMINIO_ID}/dispositivos`, payload: { nome: 'Tablet portaria' } },
    roles: ['provedor', 'sindico'],
    successStatus: 201
  },
  {
    name: 'list gatehouse devices',
    request: { method: 'GET', url: `/condominios/${CONDOMINIO_ID}/dispositivos` },
    roles: ['provedor', 'sindico'],
    successStatus: 200
  },
  {
    name: 'revoke gatehouse device',
    request: { method: 'DELETE', url: `/condominios/${CONDOMINIO_ID}/dispositivos/${DEVICE_ID}` },
    roles: ['provedor', 'sindico'],
    successStatus: 204
  },
  {
    name: 'validate invitation at gatehouse',
    request: { method: 'POST', url: '/portaria/convites/validar', payload: { token: '123456', tipoAcesso: 'pedestre' } },
    roles: ['portaria'],
    successStatus: 200
  }
];

function developmentHeaders(role: Role) {
  return {
    'x-development-user-id': role === 'morador' ? MORADOR_ID : `${role}-1`,
    'x-development-user-role': role,
    'x-development-condominio-id': role === 'provedor' ? '*' : CONDOMINIO_ID,
    'idempotency-key': `rbac-test-${role}-invitation-key`
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
  const otherResidentEndpoints = endpoints.slice(5).filter((endpoint) => endpoint.name !== 'validate invitation at gatehouse').map((endpoint) => ({
    ...endpoint,
    request: {
      ...endpoint.request,
      url: endpoint.request.url
        .replaceAll(CONDOMINIO_ID, OTHER_CONDOMINIO_ID)
        .replaceAll(MORADOR_ID, otherMorador.id)
        .replaceAll(CONVIDADO_ID, otherConvidado.id),
      payload: endpoint.request.payload
        ? Object.fromEntries(Object.entries(endpoint.request.payload).map(([key, value]) => [
            key,
            key === 'condominioId' && value === CONDOMINIO_ID
              ? OTHER_CONDOMINIO_ID
              : Array.isArray(value)
                ? value.map((id) => id === CONVIDADO_ID ? otherConvidado.id : id)
                : value
          ]))
        : undefined
    }
  }));

  for (const endpoint of otherResidentEndpoints) {
    for (const role of ROLES) {
      let storeCalls = 0;
      let condominioStoreCalls = 0;
      const store = createAuthorizationStore();
      const db: AppDependencies = {
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
        },
        convidado: {
          create: async (args) => {
            storeCalls += 1;
            return store.convidado.create(args);
          },
          findMany: async (args) => {
            storeCalls += 1;
            return store.convidado.findMany(args);
          },
          findFirst: async (args) => {
            storeCalls += 1;
            return store.convidado.findFirst(args);
          },
          updateMany: async (args) => {
            storeCalls += 1;
            return store.convidado.updateMany(args);
          }
        },
        convite: {
          issueIdempotent: async (args) => {
            storeCalls += 1;
            return store.convite!.issueIdempotent!(args);
          },
          createActive: async (args) => {
            storeCalls += 1;
            return store.convite!.createActive(args);
          },
          createBatchActive: async (args) => {
            storeCalls += 1;
            return store.convite!.createBatchActive(args);
          },
          validateActive: async (args, now) => {
            storeCalls += 1;
            return store.convite!.validateActive(args, now);
          },
          listOwnedAudits: async (args) => {
            storeCalls += 1;
            return store.convite!.listOwnedAudits(args);
          },
          revokeActive: async (args, now) => {
            storeCalls += 1;
            return store.convite!.revokeActive(args, now);
          }
        },
        dispositivo: {
          async create(args) {
            storeCalls += 1;
            return store.dispositivo!.create(args);
          },
          async list(args) {
            storeCalls += 1;
            return store.dispositivo!.list(args);
          },
          async revoke(args) {
            storeCalls += 1;
            return store.dispositivo!.revoke(args);
          },
          async authenticate(apiKey, now) {
            storeCalls += 1;
            return store.dispositivo!.authenticate(apiKey, now);
          }
        }
      };
      const app = createApp({ db, authenticator });
      const response = await app.inject({ ...endpoint.request, headers: developmentHeaders(role) });

      if (role === 'provedor' && endpoint.roles.includes(role)) {
        assert.equal(response.statusCode, endpoint.successStatus, `${role}: ${endpoint.name}`);
        assert.ok(storeCalls > 0, `${role}: ${endpoint.name} should reach its tenant data`);
        if (!['create invitation', 'update condominium invitation limit'].includes(endpoint.name)) {
          assert.equal(condominioStoreCalls, 0, `${role}: ${endpoint.name} used a preliminary condominium check`);
        }
      } else {
        assert.equal(response.statusCode, 403, `${role}: ${endpoint.name}`);
        assert.equal(storeCalls, 0, `${role}: ${endpoint.name} crossed the authorization boundary`);
      }

      await app.close();
    }
  }
});

test('resident guest ownership is enforced before any store access', async () => {
  let storeCalls = 0;
  const inaccessible = async () => {
    storeCalls += 1;
    throw new Error('Authorization boundary reached the store');
  };
  const db: AppDependencies = {
    condominio: { create: inaccessible, findMany: inaccessible, findFirst: inaccessible, updateMany: inaccessible },
    morador: { create: inaccessible, findMany: inaccessible, findFirst: inaccessible, updateMany: inaccessible },
    convidado: { create: inaccessible, findMany: inaccessible, findFirst: inaccessible, updateMany: inaccessible },
    convite: { createActive: inaccessible, createBatchActive: inaccessible, validateActive: inaccessible, listOwnedAudits: inaccessible, revokeActive: inaccessible }
  };

  for (const endpoint of endpoints.slice(10)) {
    const app = createApp({ db, authenticator });
    const request = {
      ...endpoint.request,
      url: endpoint.request.url.replaceAll(MORADOR_ID, otherMorador.id)
    };
    const response = await app.inject({ ...request, headers: developmentHeaders('morador') });

    assert.equal(response.statusCode, 403, endpoint.name);
    assert.equal(storeCalls, 0, endpoint.name);
    await app.close();
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
      '│       ├── /limite-diario-convites (PATCH)',
      '│       ├── /moradores (GET, HEAD)',
      '│       │   └── /:id|:moradorId (GET, HEAD, PATCH, DELETE)',
      '│       │       ├── /limite-diario-convites (PATCH)',
      '│       │       ├── /convidados (POST, GET, HEAD)',
      '│       │       │   ├── /recentes (GET, HEAD)',
      '│       │       │   └── /:id|:convidadoId (GET, HEAD, PATCH, DELETE)',
      '│       │       │       └── /convites (POST)',
      '│       │       ├── /convites/multiplos (POST)',
      '│       │       ├── /convites/:conviteId (DELETE)',
      '│       │       ├── /auditorias-acesso (GET, HEAD)',
      '│       │       └── /notificacoes (GET, HEAD)',
      '│       │           └── /:notificationId (PATCH)',
      '│       └── /dispositivos (POST, GET, HEAD)',
      '│           └── /:deviceId (DELETE)',
      '├── /moradores (POST)',
      '└── /portaria/convites/validar (POST)',
      ''
    ].join('\n')
  );
  assert.equal(endpoints.length, 28);

  await app.close();
});

test('development authenticator requires explicit opt-in', () => {
  assert.throws(() => createDevelopmentHeaderAuthenticator(false), /requires explicit opt-in/);
  assert.doesNotThrow(() => createDevelopmentHeaderAuthenticator(true));
});
