import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';

const migrationPath = new URL(
  '../prisma/migrations/0017_add_human_authentication_schema/migration.sql',
  import.meta.url
);
const schemaPath = new URL('../prisma/schema.prisma', import.meta.url);

test('human authentication schema is additive, encrypted, indexed, and immutable', async () => {
  const [migration, schema] = await Promise.all([
    readFile(migrationPath, 'utf8'),
    readFile(schemaPath, 'utf8')
  ]);

  for (const model of [
    'HumanAccount',
    'ExternalIdentity',
    'HumanMembership',
    'OidcLoginTransaction',
    'BrowserSession',
    'AuthenticationAuditEvent'
  ]) {
    assert.match(schema, new RegExp(`model ${model} \\{`));
    assert.match(migration, new RegExp(`CREATE TABLE "${model}"`));
  }

  assert.match(migration, /CREATE UNIQUE INDEX "ExternalIdentity_issuer_subject_key"/);
  assert.match(migration, /HumanMembership_active_provider_key[\s\S]*WHERE "status" = 'active'/);
  assert.match(migration, /HumanMembership_active_tenant_role_key[\s\S]*WHERE "status" = 'active'/);
  assert.match(migration, /FOREIGN KEY \("residentId", "condominioId"\)/);
  assert.match(migration, /FOREIGN KEY \("activeMembershipId", "accountId"\)/);
  assert.match(migration, /octet_length\("tokenDigest"\) = 32/);
  assert.match(migration, /octet_length\("csrfNonce"\) = 12/);
  assert.match(migration, /octet_length\("csrfAuthTag"\) = 16/);
  assert.match(migration, /octet_length\("csrfCiphertext"\) = 32/);
  assert.match(migration, /octet_length\("pkceVerifierCiphertext"\) BETWEEN 43 AND 128/);
  assert.match(migration, /octet_length\("pkceVerifierNonce"\) = 12/);
  assert.match(migration, /octet_length\("pkceVerifierAuthTag"\) = 16/);
  assert.match(migration, /BEFORE UPDATE OR DELETE ON "AuthenticationAuditEvent"/);
  assert.match(migration, /BEFORE TRUNCATE ON "AuthenticationAuditEvent"/);
  assert.match(migration, /CREATE ROLE egogero_application NOLOGIN/);
  assert.match(migration, /REVOKE UPDATE, DELETE, TRUNCATE ON "AuthenticationAuditEvent" FROM egogero_application, PUBLIC/);
  assert.match(migration, /RAISE EXCEPTION 'authentication audit rows are immutable'/);
  assert.match(migration, /HumanMembership_enforce_live_scope/);
  assert.match(migration, /BrowserSession_enforce_active_scope/);
  assert.match(migration, /SET search_path = pg_catalog, public/);
  assert.match(migration, /FROM public\."HumanAccount"/);
  assert.match(migration, /FOR SHARE OF account, membership/);
  assert.match(migration, /REVOKE ALL PRIVILEGES ON "_prisma_migrations" FROM egogero_application/);
  assert.match(migration, /BrowserSession_retention_idx/);
  assert.match(migration, /OidcLoginTransaction_retention_idx/);
  assert.match(migration, /^BEGIN;/);
  assert.match(migration, /COMMIT;\s*$/);
  assert.doesNotMatch(migration, /\bDROP\s+(?:TABLE|COLUMN|TYPE)\b/i);

  const loginTransaction = schema.match(/model OidcLoginTransaction \{[\s\S]*?\n\}/)?.[0] ?? '';
  const browserSession = schema.match(/model BrowserSession \{[\s\S]*?\n\}/)?.[0] ?? '';
  assert.doesNotMatch(loginTransaction, /^\s*(pkceVerifier|authorizationCode|accessToken|idToken)\s/m);
  assert.doesNotMatch(browserSession, /^\s*(sessionToken|csrfToken)\s/m);
  assert.match(loginTransaction, /pkceVerifierCiphertext\s+Bytes/);
  assert.match(loginTransaction, /pkceKeyVersion\s+Int/);
  assert.match(browserSession, /tokenDigest\s+Bytes/);
  assert.match(browserSession, /csrfCiphertext\s+Bytes/);
  assert.match(browserSession, /csrfKeyVersion\s+Int/);
});
