import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';

const migrationPath = new URL('../prisma/migrations/0015_add_invitation_idempotency_outbox/migration.sql', import.meta.url);
const schemaPath = new URL('../prisma/schema.prisma', import.meta.url);

test('idempotency and outbox schema enforce transactional uniqueness without plaintext payloads', async () => {
  const [migration, schema] = await Promise.all([readFile(migrationPath, 'utf8'), readFile(schemaPath, 'utf8')]);
  assert.match(migration, /^BEGIN;/);
  assert.match(migration, /CREATE UNIQUE INDEX "IdempotencyRecord_scope_key"/);
  assert.match(migration, /"actorId", "condominioId", "method", "route", "keyDigest"/);
  assert.match(migration, /CREATE UNIQUE INDEX "DeliveryIntent_conviteId_channel_key"/);
  assert.match(migration, /DEFERRABLE INITIALLY DEFERRED/);
  assert.match(migration, /idempotency record must be confirmed in its insertion transaction/);
  assert.match(migration, /"responseCiphertext" BYTEA/);
  assert.match(migration, /"payloadCiphertext" BYTEA NOT NULL/);
  assert.doesNotMatch(migration, /"(?:token|recipient|message|subject|body)" TEXT/i);
  assert.match(migration, /COMMIT;\s*$/);
  const idempotencyModel = schema.match(/model IdempotencyRecord \{[\s\S]*?\n\}/)?.[0] ?? '';
  const deliveryModel = schema.match(/model DeliveryIntent \{[\s\S]*?\n\}/)?.[0] ?? '';
  assert.ok(idempotencyModel);
  assert.ok(deliveryModel);
  assert.doesNotMatch(`${idempotencyModel}\n${deliveryModel}`, /^\s+(?:token|recipient|message|subject|body)\s+String/m);
});
