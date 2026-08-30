import assert from 'node:assert/strict';
import { readFile, readdir } from 'node:fs/promises';
import test from 'node:test';

const migrationsPath = new URL('../prisma/migrations/', import.meta.url);

test('migrations form one exact contiguous immutable sequence', async () => {
  const migrations = (await readdir(migrationsPath)).sort();
  assert.deepEqual(migrations, [
    '0001_initial',
    '0002_add_condominio_responsavel_tipo',
    '0003_add_morador_endereco',
    '0004_link_convidado_to_morador',
    '0005_add_invitation_token',
    '0006_add_invitation_revocation',
    '0007_add_daily_invitation_limits',
    '0008_add_guest_contacts',
    '0009_add_immutable_access_audit',
    '0010_add_entry_notifications',
    '0011_add_guest_anonymization',
    '0012_index_pending_guest_anonymization',
    '0013_add_gatehouse_devices',
    '0014_add_condominium_timezone_and_timestamptz',
    '0015_add_invitation_idempotency_outbox',
    '0016_add_delivery_worker_leases',
    '0017_add_human_authentication_schema',
    '0018_add_oidc_validated_handoff',
    '0019_add_oidc_reauthentication_intent',
    '0020_add_human_provisioning_mfa_recovery',
    '0021_add_distributed_auth_rate_limits',
    '0022_add_callback_reservations_and_intent_checks',
    '0023_add_human_gatehouse_access_audit',
    '0024_add_reauthentication_start_intent',
    '0025_add_human_auth_rollout',
    '0026_add_rollout_deployment_authorization'
  ]);
});

test('reauthentication migration binds trusted intent to a UUID family in both handoff stages', async () => {
  const sql = await readFile(new URL(
    '../prisma/migrations/0019_add_oidc_reauthentication_intent/migration.sql',
    import.meta.url
  ), 'utf8');
  assert.equal((sql.match(/"reauthenticationFamilyId" UUID/g) ?? []).length, 2);
  assert.equal((sql.match(/"reauthenticationIntent" = \("reauthenticationFamilyId" IS NOT NULL\)/g) ?? []).length, 2);
});
