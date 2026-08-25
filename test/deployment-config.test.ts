import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import test from 'node:test';

import { getEnv } from '../src/env.js';

const policy = JSON.stringify({
  provedor: { amr: ['webauthn'], acr: ['urn:mfa'] },
  sindico: { amr: ['webauthn'], acr: ['urn:mfa'] },
  morador: { amr: ['totp'], acr: [] },
  portaria: { amr: ['webauthn'], acr: ['urn:mfa'] }
});

function key() { return randomBytes(32).toString('base64url'); }

function baseEnvironment(): NodeJS.ProcessEnv {
  return {
    NODE_ENV: 'staging',
    HUMAN_AUTH_ENABLED: 'true',
    DATABASE_URL: 'postgresql://office:password@database.internal/office?schema=public',
    INVITATION_TOKEN_SECRET: 'invitation-token-material-with-sufficient-length',
    IDEMPOTENCY_CACHE_SECRET: 'idempotency-cache-material-with-sufficient-length',
    DEVICE_API_KEY_SECRET: 'device-api-key-material-with-sufficient-length',
    TRUST_PROXY: '10.20.0.0/16,2001:db8::/64',
    PUBLIC_APPLICATION_ORIGIN: 'https://staging.office.example',
    OIDC_ISSUER: 'https://identity.example',
    OIDC_AUTHORIZATION_ENDPOINT: 'https://identity.example/oauth/authorize',
    OIDC_TOKEN_ENDPOINT: 'https://identity.example/oauth/token',
    OIDC_JWKS_URI: 'https://identity.example/.well-known/jwks.json',
    OIDC_CLIENT_ID: 'office-staging',
    OIDC_CLIENT_SECRET: '7eQp9-Mv2xK4rT8yN6sW3aD5fG1hJ0cL',
    OIDC_REDIRECT_URI: 'https://staging.office.example/auth/callback',
    OIDC_ID_TOKEN_SIGNING_ALG: 'RS256',
    OIDC_PKCE_KEYS: JSON.stringify({ 1: key() }),
    OIDC_PKCE_CURRENT_KEY_VERSION: '1',
    SESSION_CSRF_KEYS: JSON.stringify({ 1: key() }),
    SESSION_CSRF_CURRENT_KEY_VERSION: '1',
    OIDC_RECOVERY_URL: 'https://identity.example/recovery',
    RECOVERY_WEBHOOK_ISSUERS: 'https://identity.example',
    RECOVERY_WEBHOOK_SECRET: '3hW8mQ2zL9vN5rK7xC1fT6sP0aD4jG8b',
    HUMAN_MFA_ROLE_POLICY: policy
  };
}

test('deployed environments require an explicit coherent human-auth state', () => {
  const base = baseEnvironment();
  const valid = getEnv(base);
  assert.equal(valid.humanAuthEnabled, true);
  assert.equal(valid.secureValidationTransport, true);

  assert.throws(() => getEnv({ ...base, HUMAN_AUTH_ENABLED: undefined }), /explicitly true or false/);
  assert.throws(() => getEnv({ ...base, OIDC_CLIENT_SECRET: undefined }), /OIDC_CLIENT_SECRET is required/);
  assert.throws(() => getEnv({ ...base, OIDC_CLIENT_SECRET: 'weak' }), /adequate entropy/);
  assert.throws(() => getEnv({ ...base, OIDC_REDIRECT_URI: 'https://other.example/auth/callback' }), /PUBLIC_APPLICATION_ORIGIN/);
  assert.throws(() => getEnv({ ...base, RECOVERY_WEBHOOK_ISSUERS: 'https://other-identity.example' }), /include OIDC_ISSUER/);
  assert.throws(() => getEnv({ ...base, TRUST_PROXY: undefined }), /HTTPS proxy allowlist/);
  assert.throws(() => getEnv({ ...base, TRUST_PROXY: '0.0.0.0/0' }), /IP\/CIDR allowlist/);
  assert.throws(() => getEnv({ ...base, DATABASE_URL: 'mysql://database/office' }), /PostgreSQL URL/);
});

test('disabled human auth is an exact secret-free rollback state', () => {
  const common = baseEnvironment();
  for (const name of Object.keys(common)) {
    if (name.startsWith('OIDC_') || name.startsWith('SESSION_CSRF_') || name.startsWith('RECOVERY_')
      || name === 'PUBLIC_APPLICATION_ORIGIN' || name === 'HUMAN_MFA_ROLE_POLICY') delete common[name];
  }
  common.HUMAN_AUTH_ENABLED = 'false';
  delete common.TRUST_PROXY;
  assert.equal(getEnv(common).humanAuthEnabled, false);
  assert.throws(
    () => getEnv({ ...common, OIDC_CLIENT_SECRET: 'stray-secret-that-must-not-be-accepted' }),
    /must be absent when HUMAN_AUTH_ENABLED=false/
  );
});

test('PKCE and CSRF keyrings allow only current plus immediately previous versions', () => {
  const base = baseEnvironment();
  const previous = key();
  const current = key();
  const valid = getEnv({
    ...base,
    OIDC_PKCE_KEYS: JSON.stringify({ 6: previous, 7: current }),
    OIDC_PKCE_CURRENT_KEY_VERSION: '7',
    SESSION_CSRF_KEYS: JSON.stringify({ 6: previous, 7: current }),
    SESSION_CSRF_CURRENT_KEY_VERSION: '7'
  });
  assert.deepEqual([...valid.oidc!.pkceKeys.keys()], [6, 7]);
  assert.deepEqual([...valid.sessions!.csrfKeys.keys()], [6, 7]);

  assert.throws(() => getEnv({
    ...base,
    OIDC_PKCE_KEYS: JSON.stringify({ 5: key(), 6: previous, 7: current }),
    OIDC_PKCE_CURRENT_KEY_VERSION: '7'
  }), /current and immediately previous/);
  assert.throws(() => getEnv({
    ...base,
    SESSION_CSRF_KEYS: JSON.stringify({ 5: previous, 7: current }),
    SESSION_CSRF_CURRENT_KEY_VERSION: '7'
  }), /current and immediately previous/);
});
