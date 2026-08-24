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
const uuid = (n: number) => `00000000-0000-4000-8000-${String(n).padStart(12, '0')}`;
type BaseRow = { id: string; createdAt: Date; deletedAt: Date | null };
type CondominioRow = BaseRow & { nome: string; responsavel: string; tipo: string; timezone: string };
type MoradorRow = BaseRow & {
  nome: string;
  condominioId: string;
  enderecoRua: string | null;
  enderecoNumero: string | null;
  enderecoBloco: string | null;
  enderecoApartamento: string | null;
};
type ConvidadoRow = BaseRow & {
  nome: string;
  email: string | null;
  telefone: string | null;
  condominioId: string;
  moradorId: string;
  ultimoUsoEm: Date | null;
  anonymizedAt: Date | null;
};

function fakeStore() {
  const condominios = new Map<string, CondominioRow>();
  const moradores = new Map<string, MoradorRow>();
  const convidados = new Map<string, ConvidadoRow>();
  let next = 1;
  const active = <T extends { deletedAt: Date | null }>(row: T) => row.deletedAt === null;
  const hasActiveParents = (row: ConvidadoRow) =>
    moradores.get(row.moradorId)?.deletedAt === null && condominios.get(row.condominioId)?.deletedAt === null;
  const db: AppStore = {
    condominio: {
      async create({ data }) { const id = next++; const row = { id: uuid(id), createdAt: new Date(Date.UTC(2026, 0, id)), deletedAt: null, ...data }; condominios.set(row.id, row); return row; },
      async findMany() { return [...condominios.values()].filter(active); },
      async findFirst({ where }) { const row = condominios.get(where.id); return row && active(row) ? row : null; },
      async updateMany({ where, data }) { const row = condominios.get(where.id); if (!row || !active(row)) return { count: 0 }; Object.assign(row, data); return { count: 1 }; }
    },
    morador: {
      async create({ data }) { const id = next++; const row = { id: uuid(id), createdAt: new Date(Date.UTC(2026, 0, id)), deletedAt: null, ...data }; moradores.set(row.id, row); return row; },
      async findMany({ where }) { return [...moradores.values()].filter((row) => row.condominioId === where.condominioId && active(row)); },
      async findFirst({ where }) { const row = moradores.get(where.id); return row && row.condominioId === where.condominioId && active(row) && condominios.get(row.condominioId)?.deletedAt === null ? row : null; },
      async updateMany({ where, data }) { const row = moradores.get(where.id); if (!row || row.condominioId !== where.condominioId || !active(row) || condominios.get(row.condominioId)?.deletedAt !== null) return { count: 0 }; Object.assign(row, data); return { count: 1 }; }
    },
    convidado: {
      async create({ data }) { const morador = moradores.get(data.moradorId); if (!morador || !active(morador) || morador.condominioId !== data.condominioId || condominios.get(data.condominioId)?.deletedAt !== null) return null; const id = next++; const row = { id: uuid(id), createdAt: new Date(Date.UTC(2026, 0, id)), deletedAt: null, ultimoUsoEm: null, anonymizedAt: null, ...data }; convidados.set(row.id, row); return row; },
      async findMany({ where, orderBy, take }) {
        assert.deepEqual(orderBy, [
          { ultimoUsoEm: { sort: 'desc', nulls: 'last' } },
          { createdAt: 'desc' },
          { id: 'desc' }
        ]);
        const rows = [...convidados.values()].filter((row) => row.condominioId === where.condominioId && row.moradorId === where.moradorId && active(row) && hasActiveParents(row));
        rows.sort((a, b) =>
          (b.ultimoUsoEm?.getTime() ?? -Infinity) - (a.ultimoUsoEm?.getTime() ?? -Infinity) ||
          b.createdAt.getTime() - a.createdAt.getTime() ||
          b.id.localeCompare(a.id)
        );
        return take ? rows.slice(0, take) : rows;
      },
      async findFirst({ where }) { const row = convidados.get(where.id); return row && row.condominioId === where.condominioId && row.moradorId === where.moradorId && active(row) && hasActiveParents(row) ? row : null; },
      async updateMany({ where, data }) { const row = convidados.get(where.id); if (!row || row.condominioId !== where.condominioId || row.moradorId !== where.moradorId || (where.anonymizedAt === null && row.anonymizedAt !== null) || !active(row) || !hasActiveParents(row)) return { count: 0 }; Object.assign(row, data); return { count: 1 }; }
    }
  };

  return { db, convidados };
}

async function setup(app: ReturnType<typeof createApp>) {
  const condominium = await app.inject({ method: 'POST', url: '/condominios', headers: providerHeaders, payload: { nome: 'A', responsavel: 'R', tipo: 'residencial', timezone: 'America/Sao_Paulo' } });
  const condominioId = condominium.json().id;
  const resident = await app.inject({ method: 'POST', url: '/moradores', headers: providerHeaders, payload: { condominioId, nome: 'Morador', endereco: { rua: 'A', numero: '1' } } });
  return { condominioId, moradorId: resident.json().id };
}

test('guest CRUD and recent guests are ordered, limited, and scoped to the responsible resident', async () => {
  const store = fakeStore();
  const app = createApp({ db: store.db, authenticator });
  const first = await setup(app);
  const residentHeaders = {
    'x-development-user-id': first.moradorId,
    'x-development-user-role': 'morador',
    'x-development-condominio-id': first.condominioId
  };
  const secondResident = await app.inject({ method: 'POST', url: '/moradores', headers: providerHeaders, payload: { condominioId: first.condominioId, nome: 'Outro', endereco: { rua: 'B', numero: '2' } } });
  const otherMoradorId = secondResident.json().id;
  const guestIds: string[] = [];

  for (const nome of ['Um', 'Dois', 'Tres']) {
    const response = await app.inject({ method: 'POST', url: `/condominios/${first.condominioId}/moradores/${first.moradorId}/convidados`, headers: residentHeaders, payload: { nome } });
    assert.equal(response.statusCode, 201);
    assert.equal(response.json().moradorId, first.moradorId);
    assert.equal(response.json().ultimoUsoEm, null);
    guestIds.push(response.json().id);
  }

  // PC-7 owns recording invitation usage; the fixture represents its persisted result.
  store.convidados.get(guestIds[0])!.ultimoUsoEm = new Date('2026-02-01T00:00:00.000Z');
  store.convidados.get(guestIds[2])!.ultimoUsoEm = new Date('2026-02-01T00:00:00.000Z');
  await app.inject({ method: 'PATCH', url: `/condominios/${first.condominioId}/moradores/${first.moradorId}/convidados/${guestIds[0]}`, headers: residentHeaders, payload: { nome: 'Um atualizado' } });
  const recent = await app.inject({ method: 'GET', url: `/condominios/${first.condominioId}/moradores/${first.moradorId}/convidados/recentes?limite=2`, headers: residentHeaders });
  assert.equal(recent.statusCode, 200);
  assert.equal(recent.json().length, 2);
  assert.deepEqual(recent.json().map((guest: { nome: string }) => guest.nome), ['Tres', 'Um atualizado']);

  const list = await app.inject({ method: 'GET', url: `/condominios/${first.condominioId}/moradores/${first.moradorId}/convidados`, headers: residentHeaders });
  assert.deepEqual(list.json().map((guest: { nome: string }) => guest.nome), ['Tres', 'Um atualizado', 'Dois']);

  const leaked = await app.inject({ method: 'GET', url: `/condominios/${first.condominioId}/moradores/${otherMoradorId}/convidados`, headers: providerHeaders });
  assert.deepEqual(leaked.json(), []);
  const deleted = await app.inject({ method: 'DELETE', url: `/condominios/${first.condominioId}/moradores/${first.moradorId}/convidados/${guestIds[1]}`, headers: residentHeaders });
  assert.equal(deleted.statusCode, 204);
  const afterDelete = await app.inject({ method: 'GET', url: `/condominios/${first.condominioId}/moradores/${first.moradorId}/convidados`, headers: residentHeaders });
  assert.equal(afterDelete.json().length, 2);
  await app.close();
});

test('guest contacts are nullable, trimmed, and validated', async () => {
  const store = fakeStore();
  const app = createApp({ db: store.db, authenticator });
  const { condominioId, moradorId } = await setup(app);
  const path = `/condominios/${condominioId}/moradores/${moradorId}/convidados`;

  const valid = await app.inject({
    method: 'POST',
    url: path,
    headers: providerHeaders,
    payload: { nome: 'Ana', email: ' ana@example.com ', telefone: ' +55 11 99999-9999 ' }
  });
  assert.equal(valid.statusCode, 201);
  assert.equal(valid.json().email, 'ana@example.com');
  assert.equal(valid.json().telefone, '+55 11 99999-9999');

  for (const payload of [
    { nome: 'Ana', email: 'invalid' },
    { nome: 'Ana', telefone: '123' },
    { nome: 'Ana', email: 1 },
    { nome: 'Ana', telefone: {} }
  ]) {
    assert.equal((await app.inject({ method: 'POST', url: path, headers: providerHeaders, payload })).statusCode, 400);
  }

  const nullable = await app.inject({
    method: 'PATCH',
    url: `${path}/${valid.json().id}`,
    headers: providerHeaders,
    payload: { nome: 'Ana', email: null, telefone: null }
  });
  assert.equal(nullable.statusCode, 200);
  assert.equal(nullable.json().email, null);
  assert.equal(nullable.json().telefone, null);

  store.convidados.get(valid.json().id)!.anonymizedAt = new Date();
  const reidentified = await app.inject({
    method: 'PATCH',
    url: `${path}/${valid.json().id}`,
    headers: providerHeaders,
    payload: { nome: 'Ana restored', email: 'restored@example.com' }
  });
  assert.equal(reidentified.statusCode, 404);
  await app.close();
});

test('guest routes reject inactive condominium and resident parents', async () => {
  const store = fakeStore();
  const app = createApp({ db: store.db, authenticator });
  const { condominioId, moradorId } = await setup(app);
  const created = await app.inject({
    method: 'POST',
    url: `/condominios/${condominioId}/moradores/${moradorId}/convidados`,
    headers: providerHeaders,
    payload: { nome: 'Convidado' }
  });
  const convidadoId = created.json().id;

  await app.inject({ method: 'DELETE', url: `/condominios/${condominioId}/moradores/${moradorId}`, headers: providerHeaders });

  const residentRequests = [
    { method: 'GET', url: `/condominios/${condominioId}/moradores/${moradorId}/convidados/recentes` },
    { method: 'POST', url: `/condominios/${condominioId}/moradores/${moradorId}/convidados`, payload: { nome: 'Outro' } },
    { method: 'GET', url: `/condominios/${condominioId}/moradores/${moradorId}/convidados` },
    { method: 'GET', url: `/condominios/${condominioId}/moradores/${moradorId}/convidados/${convidadoId}` },
    { method: 'PATCH', url: `/condominios/${condominioId}/moradores/${moradorId}/convidados/${convidadoId}`, payload: { nome: 'Outro' } },
    { method: 'DELETE', url: `/condominios/${condominioId}/moradores/${moradorId}/convidados/${convidadoId}` }
  ] as const;

  for (const request of residentRequests) {
    const response = await app.inject({ ...request, headers: providerHeaders });
    assert.equal(response.statusCode, 404, `${request.method} ${request.url}`);
  }

  await app.inject({ method: 'DELETE', url: `/condominios/${condominioId}`, headers: providerHeaders });
  const condominiumResponse = await app.inject({
    method: 'GET',
    url: `/condominios/${condominioId}/moradores/${moradorId}/convidados`,
    headers: providerHeaders
  });
  assert.equal(condominiumResponse.statusCode, 404);
  assert.deepEqual(condominiumResponse.json(), { error: 'Resident not found' });
  await app.close();
});
