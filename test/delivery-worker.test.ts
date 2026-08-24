import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';

import {
  createUnavailableDeliveryProvider,
  deliveryWorkerConfig,
  DeliveryProviderUnavailableError,
  retryDelayMs
} from '../src/jobs/deliver-invitations.js';

const migrationPath = new URL('../prisma/migrations/0016_add_delivery_worker_leases/migration.sql', import.meta.url);

test('delivery migration models leases, retries, terminal states, and claim indexes', async () => {
  const migration = await readFile(migrationPath, 'utf8');
  assert.match(migration, /^BEGIN;/);
  assert.match(migration, /CREATE TYPE "DeliveryStatus" AS ENUM \('pending', 'processing', 'retry', 'delivered', 'dead_letter'\)/);
  assert.match(migration, /"leaseOwner" TEXT/);
  assert.match(migration, /"leaseToken" UUID/);
  assert.match(migration, /"leaseExpiresAt" TIMESTAMPTZ/);
  assert.match(migration, /"nextAttemptAt" TIMESTAMPTZ/);
  assert.match(migration, /"lastError" TEXT/);
  assert.match(migration, /DeliveryIntent_worker_claim_idx/);
  assert.match(migration, /DeliveryIntent_expired_lease_idx/);
  assert.match(migration, /DeliveryIntent_state_check/);
  assert.match(migration, /attempts_exhausted/);
  assert.match(migration, /COMMIT;\s*$/);
});

test('production placeholder provider fails explicitly instead of acknowledging delivery', async () => {
  await assert.rejects(
    createUnavailableDeliveryProvider().send({
      channel: 'email',
      idempotencyKey: 'intent-1',
      payload: { intentId: 'intent-1', invitationId: 'invitation-1', to: 'hidden', subject: 'hidden', body: 'hidden' },
      signal: new AbortController().signal
    }),
    DeliveryProviderUnavailableError
  );
});

test('delivery worker configuration rejects unsafe bounds', () => {
  assert.deepEqual(deliveryWorkerConfig({}), {
    batchSize: 50,
    concurrency: 5,
    leaseMs: 60_000,
    pollMs: 1_000,
    maxAttempts: 8,
    providerTimeoutMs: 30_000,
    baseBackoffMs: 1_000,
    maxBackoffMs: 300_000
  });
  assert.throws(() => deliveryWorkerConfig({ DELIVERY_BATCH_SIZE: '0' }), /DELIVERY_BATCH_SIZE/);
  assert.throws(() => deliveryWorkerConfig({ DELIVERY_BATCH_SIZE: '2', DELIVERY_CONCURRENCY: '3' }), /must not exceed/);
  assert.throws(() => deliveryWorkerConfig({ DELIVERY_LEASE_MS: '999' }), /DELIVERY_LEASE_MS/);
  assert.throws(() => deliveryWorkerConfig({ DELIVERY_PROVIDER_TIMEOUT_MS: '999' }), /DELIVERY_PROVIDER_TIMEOUT_MS/);
  assert.throws(() => deliveryWorkerConfig({ DELIVERY_BASE_BACKOFF_MS: '2000', DELIVERY_MAX_BACKOFF_MS: '1000' }), /must not be less/);
});

test('retry delay applies capped exponential backoff with bounded jitter', () => {
  const config = { baseBackoffMs: 1_000, maxBackoffMs: 5_000 };
  assert.equal(retryDelayMs(1, config, () => 0), 800);
  assert.equal(retryDelayMs(2, config, () => 0.5), 2_000);
  assert.equal(retryDelayMs(20, config, () => 1), 5_000);
});
