import assert from 'node:assert/strict';
import { readdir } from 'node:fs/promises';
import test from 'node:test';

const migrationsPath = new URL('../prisma/migrations/', import.meta.url);

test('feature migrations form one immutable sequence after invitation tokens', async () => {
  const migrations = (await readdir(migrationsPath)).sort();
  const immutableSequence = [
    '0005_add_invitation_token',
    '0006_add_invitation_revocation',
    '0007_add_daily_invitation_limits',
    '0008_add_guest_contacts',
    '0009_add_immutable_access_audit',
    '0010_add_entry_notifications',
    '0011_add_guest_anonymization',
    '0012_index_pending_guest_anonymization',
    '0013_add_gatehouse_devices',
    '0016_add_condominium_timezone_and_timestamptz',
    '0017_add_invitation_idempotency_outbox'
  ];
  let previousIndex = -1;
  for (const migration of immutableSequence) {
    const index = migrations.indexOf(migration);
    assert.ok(index > previousIndex, `${migration} must follow the existing immutable sequence`);
    previousIndex = index;
  }
});
