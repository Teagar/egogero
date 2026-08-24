import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';

const migrationPath = new URL('../prisma/migrations/0009_add_immutable_access_audit/migration.sql', import.meta.url);
const schemaPath = new URL('../prisma/schema.prisma', import.meta.url);

test('access audit schema stores only identifiers and rejects every mutation in PostgreSQL', async () => {
  const [migration, schema] = await Promise.all([
    readFile(migrationPath, 'utf8'),
    readFile(schemaPath, 'utf8')
  ]);

  assert.match(migration, /^BEGIN;/);
  assert.match(migration, /CREATE TABLE "AuditoriaAcesso"/);
  assert.match(migration, /CREATE TYPE "TipoAcesso" AS ENUM \('pedestre', 'veiculo'\)/);
  assert.match(migration, /CREATE TYPE "ResultadoAcesso" AS ENUM \('permitido', 'negado'\)/);
  assert.match(migration, /BEFORE UPDATE OR DELETE ON "AuditoriaAcesso"/);
  assert.match(migration, /BEFORE TRUNCATE ON "AuditoriaAcesso"/);
  assert.match(migration, /length\("dispositivoId"\) BETWEEN 1 AND 128/);
  assert.match(migration, /RAISE EXCEPTION 'access audit rows are immutable'/);
  assert.doesNotMatch(migration, /token|digest|nome|email|telefone/i);
  assert.match(migration, /COMMIT;\s*$/);

  const auditModel = schema.match(/model AuditoriaAcesso \{[\s\S]*?\n\}/)?.[0] ?? '';
  assert.match(auditModel, /condominioId\s+String/);
  assert.match(auditModel, /dispositivoId\s+String/);
  assert.match(auditModel, /tipoAcesso\s+TipoAcesso/);
  assert.match(auditModel, /resultado\s+ResultadoAcesso/);
  assert.doesNotMatch(auditModel, /token|digest|nome|email|telefone/i);
});
