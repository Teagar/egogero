import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';

const migrationPath = new URL('../prisma/migrations/0016_add_condominium_timezone_and_timestamptz/migration.sql', import.meta.url);
const schemaPath = new URL('../prisma/schema.prisma', import.meta.url);

test('timezone migration backfills condominiums and converts every persisted instant explicitly from UTC', async () => {
  const [migration, schema] = await Promise.all([readFile(migrationPath, 'utf8'), readFile(schemaPath, 'utf8')]);
  assert.match(migration, /^BEGIN;/);
  assert.match(migration, /UPDATE "Condominio" SET "timezone" = 'America\/Sao_Paulo'/);
  assert.match(migration, /ALTER COLUMN "timezone" SET NOT NULL/);
  assert.match(migration, /FROM pg_timezone_names WHERE name = NEW\.timezone/);
  assert.match(migration, /USING "createdAt" AT TIME ZONE 'UTC'/);
  assert.match(migration, /USING "entrouEm" AT TIME ZONE 'UTC'/);
  assert.match(migration, /value AT TIME ZONE 'UTC'/);
  assert.match(migration, /COMMIT;\s*$/);
  for (const line of schema.split('\n').filter((candidate) => candidate.includes('DateTime'))) {
    assert.match(line, /@db\.Timestamptz\(3\)/, `missing native TIMESTAMPTZ: ${line.trim()}`);
  }
});
