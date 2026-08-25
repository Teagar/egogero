import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';

const migration = new URL('../prisma/migrations/0023_add_human_gatehouse_access_audit/migration.sql', import.meta.url);

test('human gatehouse audit is additive, actor-aware, indexed, and immutable', async () => {
  const sql = await readFile(migration, 'utf8');
  assert.match(sql, /CREATE TABLE "AuditoriaAcessoHumano"/);
  assert.match(sql, /"accountId" UUID NOT NULL/);
  assert.match(sql, /"membershipId" UUID NOT NULL/);
  assert.match(sql, /"condominioId" TEXT NOT NULL/);
  assert.match(sql, /reject_human_access_audit_mutation/);
  assert.match(sql, /BEFORE UPDATE OR DELETE/);
  assert.match(sql, /BEFORE TRUNCATE/);
  assert.doesNotMatch(sql, /ALTER TABLE "AuditoriaAcesso"/);
});
