import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';

const migration = new URL('../prisma/migrations/0024_add_reauthentication_start_intent/migration.sql', import.meta.url);

test('reauthentication start intents are digest-only, bounded, single-use records with cleanup support', async () => {
  const sql = await readFile(migration, 'utf8');
  assert.match(sql, /"tokenDigest" BYTEA NOT NULL/);
  assert.match(sql, /UNIQUE \("tokenDigest"\)/);
  assert.match(sql, /"familyId" UUID NOT NULL/);
  assert.match(sql, /"accountId" UUID NOT NULL/);
  assert.match(sql, /interval '5 minutes'/);
  assert.match(sql, /"consumedAt"/);
  assert.match(sql, /ReauthenticationStartIntent_cleanup_idx/);
  assert.doesNotMatch(sql, /authorizationUrl|providerToken|token" TEXT/i);
});
