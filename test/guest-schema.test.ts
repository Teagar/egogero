import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';

const migrationPath = new URL('../prisma/migrations/0004_link_convidado_to_morador/migration.sql', import.meta.url);
const schemaPath = new URL('../prisma/schema.prisma', import.meta.url);

test('guest ownership migration preserves legacy guests and enforces condominium-scoped relations', async () => {
  const [migration, schema] = await Promise.all([
    readFile(migrationPath, 'utf8'),
    readFile(schemaPath, 'utf8')
  ]);

  assert.match(migration, /ADD COLUMN "moradorId" TEXT;/);
  assert.doesNotMatch(migration, /ADD COLUMN "moradorId" TEXT NOT NULL/);
  assert.match(migration, /^BEGIN;/);
  assert.match(migration, /cross-tenant rows exist/);
  assert.match(migration, /COMMIT;\s*$/);
  assert.match(migration, /UNIQUE \("id", "condominioId"\)/);
  assert.match(migration, /FOREIGN KEY \("moradorId", "condominioId"\) REFERENCES "Morador"\("id", "condominioId"\)/);
  assert.match(migration, /FOREIGN KEY \("convidadoId", "condominioId"\) REFERENCES "Convidado"\("id", "condominioId"\)/);
  assert.match(schema, /moradorId\s+String\?/);
  assert.match(schema, /PC-7 records this when it generates a Convite/);
});
