import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';

const migrationPath = new URL('../prisma/migrations/0010_add_entry_notifications/migration.sql', import.meta.url);

test('entry notifications are transactional and tenant-consistent', async () => {
  const migration = await readFile(migrationPath, 'utf8');
  assert.match(migration, /^BEGIN;/);
  assert.match(migration, /FOREIGN KEY \("moradorId", "condominioId"\)/);
  assert.match(migration, /FOREIGN KEY \("convidadoId", "condominioId"\)/);
  assert.match(migration, /FOREIGN KEY \("conviteId", "condominioId", "moradorId", "convidadoId"\)/);
  assert.match(migration, /COMMIT;\s*$/);
});
