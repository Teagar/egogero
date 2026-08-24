import assert from 'node:assert/strict';
import test from 'node:test';

import { createApp } from '../src/app.js';
import type { AppStore } from '../src/app.js';

const headers = { 'x-user-role': 'provedor' };
const uuid = (n: number) => `00000000-0000-4000-8000-${String(n).padStart(12, '0')}`;
type BaseRow = { id: string; createdAt: Date; deletedAt: Date | null };
type CondominioRow = BaseRow & { nome: string; responsavel: string; tipo: string };
type MoradorRow = BaseRow & {
  nome: string;
  condominioId: string;
  enderecoRua: string | null;
  enderecoNumero: string | null;
  enderecoBloco: string | null;
  enderecoApartamento: string | null;
};
type ConvidadoRow = BaseRow & { nome: string; condominioId: string; moradorId: string; ultimoUsoEm: Date | null };

function fakeStore() {
  const condominios = new Map<string, CondominioRow>();
  const moradores = new Map<string, MoradorRow>();
  const convidados = new Map<string, ConvidadoRow>();
  let next = 1;
  const active = <T extends { deletedAt: Date | null }>(row: T) => row.deletedAt === null;
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
      async findFirst({ where }) { const row = moradores.get(where.id); return row && row.condominioId === where.condominioId && active(row) ? row : null; },
      async updateMany({ where, data }) { const row = moradores.get(where.id); if (!row || row.condominioId !== where.condominioId || !active(row)) return { count: 0 }; Object.assign(row, data); return { count: 1 }; }
    },
    convidado: {
      async create({ data }) { const id = next++; const row = { id: uuid(id), createdAt: new Date(Date.UTC(2026, 0, id)), deletedAt: null, ultimoUsoEm: null, ...data }; convidados.set(row.id, row); return row; },
      async findMany({ where, orderBy, take }) {
        assert.deepEqual(orderBy, [
          { ultimoUsoEm: { sort: 'desc', nulls: 'last' } },
          { createdAt: 'desc' },
          { id: 'desc' }
        ]);
        const rows = [...convidados.values()].filter((row) => row.condominioId === where.condominioId && row.moradorId === where.moradorId && active(row));
        rows.sort((a, b) =>
          (b.ultimoUsoEm?.getTime() ?? -Infinity) - (a.ultimoUsoEm?.getTime() ?? -Infinity) ||
          b.createdAt.getTime() - a.createdAt.getTime() ||
          b.id.localeCompare(a.id)
        );
        return take ? rows.slice(0, take) : rows;
      },
      async findFirst({ where }) { const row = convidados.get(where.id); return row && row.condominioId === where.condominioId && row.moradorId === where.moradorId && active(row) ? row : null; },
      async updateMany({ where, data }) { const row = convidados.get(where.id); if (!row || row.condominioId !== where.condominioId || row.moradorId !== where.moradorId || !active(row)) return { count: 0 }; Object.assign(row, data); return { count: 1 }; }
    }
  };

  return { db, convidados };
}

async function setup(app: ReturnType<typeof createApp>) {
  const condominium = await app.inject({ method: 'POST', url: '/condominios', headers, payload: { nome: 'A', responsavel: 'R', tipo: 'residencial' } });
  const condominioId = condominium.json().id;
  const resident = await app.inject({ method: 'POST', url: '/moradores', headers, payload: { condominioId, nome: 'Morador', endereco: { rua: 'A', numero: '1' } } });
  return { condominioId, moradorId: resident.json().id };
}

test('guest CRUD and recent guests are ordered, limited, and scoped to the responsible resident', async () => {
  const store = fakeStore();
  const app = createApp({ db: store.db });
  const first = await setup(app);
  const secondResident = await app.inject({ method: 'POST', url: '/moradores', headers, payload: { condominioId: first.condominioId, nome: 'Outro', endereco: { rua: 'B', numero: '2' } } });
  const otherMoradorId = secondResident.json().id;
  const guestIds: string[] = [];

  for (const nome of ['Um', 'Dois', 'Tres']) {
    const response = await app.inject({ method: 'POST', url: `/condominios/${first.condominioId}/moradores/${first.moradorId}/convidados`, headers, payload: { nome } });
    assert.equal(response.statusCode, 201);
    assert.equal(response.json().moradorId, first.moradorId);
    assert.equal(response.json().ultimoUsoEm, null);
    guestIds.push(response.json().id);
  }

  // PC-7 owns recording invitation usage; the fixture represents its persisted result.
  store.convidados.get(guestIds[0])!.ultimoUsoEm = new Date('2026-02-01T00:00:00.000Z');
  store.convidados.get(guestIds[2])!.ultimoUsoEm = new Date('2026-02-01T00:00:00.000Z');
  await app.inject({ method: 'PATCH', url: `/condominios/${first.condominioId}/moradores/${first.moradorId}/convidados/${guestIds[0]}`, headers, payload: { nome: 'Um atualizado' } });
  const recent = await app.inject({ method: 'GET', url: `/condominios/${first.condominioId}/moradores/${first.moradorId}/convidados/recentes?limite=2`, headers });
  assert.equal(recent.statusCode, 200);
  assert.equal(recent.json().length, 2);
  assert.deepEqual(recent.json().map((guest: { nome: string }) => guest.nome), ['Tres', 'Um atualizado']);

  const list = await app.inject({ method: 'GET', url: `/condominios/${first.condominioId}/moradores/${first.moradorId}/convidados`, headers });
  assert.deepEqual(list.json().map((guest: { nome: string }) => guest.nome), ['Tres', 'Um atualizado', 'Dois']);

  const leaked = await app.inject({ method: 'GET', url: `/condominios/${first.condominioId}/moradores/${otherMoradorId}/convidados`, headers });
  assert.deepEqual(leaked.json(), []);
  const deleted = await app.inject({ method: 'DELETE', url: `/condominios/${first.condominioId}/moradores/${first.moradorId}/convidados/${guestIds[1]}`, headers });
  assert.equal(deleted.statusCode, 204);
  const afterDelete = await app.inject({ method: 'GET', url: `/condominios/${first.condominioId}/moradores/${first.moradorId}/convidados`, headers });
  assert.equal(afterDelete.json().length, 2);
  await app.close();
});

test('guest routes reject inactive condominium and resident parents', async () => {
  const store = fakeStore();
  const app = createApp({ db: store.db });
  const { condominioId, moradorId } = await setup(app);
  const created = await app.inject({
    method: 'POST',
    url: `/condominios/${condominioId}/moradores/${moradorId}/convidados`,
    headers,
    payload: { nome: 'Convidado' }
  });
  const convidadoId = created.json().id;

  await app.inject({ method: 'DELETE', url: `/condominios/${condominioId}/moradores/${moradorId}`, headers });

  const residentRequests = [
    { method: 'GET', url: `/condominios/${condominioId}/moradores/${moradorId}/convidados/recentes` },
    { method: 'POST', url: `/condominios/${condominioId}/moradores/${moradorId}/convidados`, payload: { nome: 'Outro' } },
    { method: 'GET', url: `/condominios/${condominioId}/moradores/${moradorId}/convidados` },
    { method: 'GET', url: `/condominios/${condominioId}/moradores/${moradorId}/convidados/${convidadoId}` },
    { method: 'PATCH', url: `/condominios/${condominioId}/moradores/${moradorId}/convidados/${convidadoId}`, payload: { nome: 'Outro' } },
    { method: 'DELETE', url: `/condominios/${condominioId}/moradores/${moradorId}/convidados/${convidadoId}` }
  ] as const;

  for (const request of residentRequests) {
    const response = await app.inject({ ...request, headers });
    assert.equal(response.statusCode, 404, `${request.method} ${request.url}`);
    assert.deepEqual(response.json(), { error: 'Resident not found' });
  }

  await app.inject({ method: 'DELETE', url: `/condominios/${condominioId}`, headers });
  const condominiumResponse = await app.inject({
    method: 'GET',
    url: `/condominios/${condominioId}/moradores/${moradorId}/convidados`,
    headers
  });
  assert.equal(condominiumResponse.statusCode, 404);
  assert.deepEqual(condominiumResponse.json(), { error: 'Condominium not found' });
  await app.close();
});
