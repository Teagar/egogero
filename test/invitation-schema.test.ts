import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';

const migrationPath = new URL('../prisma/migrations/0005_add_invitation_token/migration.sql', import.meta.url);
const schemaPath = new URL('../prisma/schema.prisma', import.meta.url);

test('invitation migration preserves legacy rows and enforces token shape and uniqueness in PostgreSQL', async () => {
  const [migration, schema] = await Promise.all([
    readFile(migrationPath, 'utf8'),
    readFile(schemaPath, 'utf8')
  ]);

  assert.match(migration, /^BEGIN;/);
  assert.match(migration, /CREATE TABLE "SecurityKey"/);
  assert.match(migration, /PRIMARY KEY \("name"\)/);
  assert.match(migration, /ADD COLUMN "tipo" "TipoConvite",/);
  assert.doesNotMatch(migration, /ADD COLUMN "(?:tipo|expiresAt|usedAt|tokenDigest)"[^,;]*NOT NULL/);
  assert.match(migration, /CHECK \("tokenDigest" IS NULL OR "tokenDigest" ~ '\^\[0-9a-f\]\{64\}\$'\)/);
  assert.match(migration, /"tokenDigest" IS NULL OR \(\s+"tipo" IS NOT NULL/);
  assert.match(migration, /"convidadoId" IS NOT NULL\s+AND "usedAt" IS NULL/);
  assert.match(migration, /CREATE UNIQUE INDEX "Convite_tokenDigest_key" ON "Convite"\("tokenDigest"\)/);
  assert.match(migration, /COMMIT;\s*$/);
  assert.match(schema, /tokenDigest\s+String\?\s+@unique @db\.Char\(64\)/);
  assert.doesNotMatch(schema, /^\s+token\s/m);
  assert.match(schema, /enum TipoConvite \{\s+visitante\s+prestador\s+entregador\s+\}/);
});
