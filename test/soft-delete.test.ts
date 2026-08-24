import assert from 'node:assert/strict';
import test from 'node:test';

import { createSoftDeleteRepository } from '../src/lib/soft-delete.js';

interface GuestRecord {
  id: string;
  condominioId: string;
  auditEntryIds: string[];
  deletedAt: Date | null;
}

type GuestWhere = Partial<Pick<GuestRecord, 'id' | 'condominioId' | 'deletedAt'>>;
type GuestWhereUnique = Pick<GuestRecord, 'id'> & { deletedAt?: Date | null };
type GuestOrderBy = Partial<Record<'id' | 'deletedAt', 'asc' | 'desc'>>;

function createGuestDelegate(initialRows: GuestRecord[]) {
  const rows = initialRows.map((row) => ({ ...row, auditEntryIds: [...row.auditEntryIds] }));

  function matches(row: GuestRecord, where: GuestWhere) {
    return Object.entries(where).every(([key, value]) => row[key as keyof GuestRecord] === value);
  }

  return {
    rows,
    async findMany({ where }: { where: GuestWhere }) {
      return rows.filter((row) => matches(row, where));
    },
    async findFirst({ where }: { where: GuestWhere }) {
      return rows.find((row) => matches(row, where)) ?? null;
    },
    async findUnique({ where }: { where: GuestWhereUnique }) {
      return rows.find((row) => row.id === where.id) ?? null;
    },
    async update({ where, data }: { where: GuestWhereUnique; data: { deletedAt: Date } }) {
      const row = rows.find((candidate) => matches(candidate, where));

      if (!row) {
        throw new Error('Record not found');
      }

      row.deletedAt = data.deletedAt;
      return row;
    },
    async updateMany({ where, data }: { where: GuestWhere; data: { deletedAt: Date } }) {
      const matchingRows = rows.filter((row) => matches(row, where));
      matchingRows.forEach((row) => {
        row.deletedAt = data.deletedAt;
      });
      return { count: matchingRows.length };
    }
  };
}

function createGuestRepository(rows: GuestRecord[], deletedAt = new Date('2026-08-24T04:00:00Z')) {
  const delegate = createGuestDelegate(rows);
  const repository = createSoftDeleteRepository<
    GuestRecord,
    GuestWhere,
    GuestWhereUnique,
    GuestOrderBy,
    keyof GuestRecord,
    { count: number }
  >(delegate, () => deletedAt);

  return { delegate, repository };
}

test('default queries exclude deleted records and cannot override the active filter', async () => {
  const active = {
    id: 'active',
    condominioId: 'condominio-1',
    auditEntryIds: ['audit-1'],
    deletedAt: null
  };
  const deleted = {
    id: 'deleted',
    condominioId: 'condominio-1',
    auditEntryIds: ['audit-2'],
    deletedAt: new Date('2026-08-23T00:00:00Z')
  };
  const { repository } = createGuestRepository([active, deleted]);

  assert.deepEqual(await repository.findMany(), [active]);
  assert.deepEqual(await repository.findMany({ where: { deletedAt: deleted.deletedAt } }), [active]);
  assert.equal(await repository.findUnique({ id: deleted.id }), null);
});

test('delete marks deletedAt while preserving relationships and audit history', async () => {
  const guest = {
    id: 'guest-1',
    condominioId: 'condominio-1',
    auditEntryIds: ['audit-1', 'audit-2'],
    deletedAt: null
  };
  const deletedAt = new Date('2026-08-24T04:00:00Z');
  const { delegate, repository } = createGuestRepository([guest], deletedAt);

  await repository.delete({ id: guest.id });

  assert.equal(delegate.rows.length, 1);
  assert.equal(await repository.findUnique({ id: guest.id }), null);
  assert.deepEqual(await repository.findUniqueIncludingDeleted({ id: guest.id }), {
    ...guest,
    deletedAt
  });
});

test('deleteMany updates only active matching records', async () => {
  const alreadyDeletedAt = new Date('2026-08-23T00:00:00Z');
  const deletedAt = new Date('2026-08-24T04:00:00Z');
  const { delegate, repository } = createGuestRepository(
    [
      { id: 'one', condominioId: 'a', auditEntryIds: [], deletedAt: null },
      { id: 'two', condominioId: 'a', auditEntryIds: [], deletedAt: alreadyDeletedAt },
      { id: 'three', condominioId: 'b', auditEntryIds: [], deletedAt: null }
    ],
    deletedAt
  );

  assert.deepEqual(await repository.deleteMany({ condominioId: 'a' }), { count: 1 });
  assert.equal(delegate.rows[0]?.deletedAt, deletedAt);
  assert.equal(delegate.rows[1]?.deletedAt, alreadyDeletedAt);
  assert.equal(delegate.rows[2]?.deletedAt, null);
});
