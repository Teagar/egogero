import assert from 'node:assert/strict';
import { createHmac, createHash, randomBytes } from 'node:crypto';
import test from 'node:test';

import { humanAdministrationConfigFromEnvironment, verifyRecoveryWebhookSignature } from '../src/human-administration.js';
import { oidcConfigFromEnvironment } from '../src/oidc.js';

const policy = JSON.stringify({
  provedor: { amr: ['webauthn'], acr: ['urn:mfa'] },
  sindico: { amr: ['webauthn'], acr: ['urn:mfa'] },
  morador: { amr: ['totp'], acr: [] },
  portaria: { amr: ['webauthn'], acr: ['urn:mfa'] }
});

function environment(clientSecret: string, webhookSecret: string): NodeJS.ProcessEnv {
  return {
    HUMAN_AUTH_ENABLED: 'true',
    PUBLIC_APPLICATION_ORIGIN: 'https://app.example.test',
    OIDC_ISSUER: 'https://identity.example.test',
    OIDC_AUTHORIZATION_ENDPOINT: 'https://identity.example.test/authorize',
    OIDC_TOKEN_ENDPOINT: 'https://identity.example.test/token',
    OIDC_JWKS_URI: 'https://identity.example.test/jwks',
    OIDC_CLIENT_ID: 'rotation-client',
    OIDC_CLIENT_SECRET: clientSecret,
    OIDC_REDIRECT_URI: 'https://app.example.test/auth/callback',
    OIDC_ID_TOKEN_SIGNING_ALG: 'RS256',
    OIDC_PKCE_KEYS: JSON.stringify({ 1: randomBytes(32).toString('base64url') }),
    OIDC_PKCE_CURRENT_KEY_VERSION: '1',
    OIDC_RECOVERY_URL: 'https://identity.example.test/recovery',
    RECOVERY_WEBHOOK_ISSUERS: 'https://identity.example.test',
    RECOVERY_WEBHOOK_SECRET: webhookSecret,
    HUMAN_MFA_ROLE_POLICY: policy
  };
}

test('credential and webhook cutover rehearsal validates overlap and the external atomic boundary', () => {
  const oldClientSecret = randomBytes(32).toString('base64url');
  const newClientSecret = randomBytes(32).toString('base64url');
  const oldWebhookSecret = randomBytes(32).toString('base64url');
  const newWebhookSecret = randomBytes(32).toString('base64url');
  const oldEnvironment = environment(oldClientSecret, oldWebhookSecret);
  const newEnvironment = environment(newClientSecret, newWebhookSecret);
  const oldOidc = oidcConfigFromEnvironment(oldEnvironment)!;
  const nextOidc = oidcConfigFromEnvironment(newEnvironment)!;
  assert.notEqual(oldOidc.clientSecret, nextOidc.clientSecret);

  const providerCredentials = new Set([createHash('sha256').update(oldOidc.clientSecret).digest('hex')]);
  const providerAccepts = (secret: string) => providerCredentials.has(createHash('sha256').update(secret).digest('hex'));
  assert.equal(providerAccepts(oldOidc.clientSecret), true);
  providerCredentials.add(createHash('sha256').update(nextOidc.clientSecret).digest('hex'));
  assert.equal(providerAccepts(oldOidc.clientSecret), true);
  assert.equal(providerAccepts(nextOidc.clientSecret), true);
  providerCredentials.delete(createHash('sha256').update(oldOidc.clientSecret).digest('hex'));
  assert.equal(providerAccepts(oldOidc.clientSecret), false);
  assert.equal(providerAccepts(nextOidc.clientSecret), true);

  const oldWebhook = humanAdministrationConfigFromEnvironment(oldEnvironment)!;
  const nextWebhook = humanAdministrationConfigFromEnvironment(newEnvironment)!;
  const timestamp = Math.floor(Date.now() / 1000);
  const event = { eventId: 'rotation-event', issuer: oldOidc.issuer, subject: 'rotation-subject', timestamp };
  const sign = (secret: Buffer) => createHmac('sha256', secret)
    .update(`${timestamp}.${event.eventId}.${event.issuer}.${event.subject}`).digest('hex');
  const oldSigned = { ...event, signature: sign(oldWebhook.recoveryWebhookSecret) };
  const newSigned = { ...event, signature: sign(nextWebhook.recoveryWebhookSecret) };
  assert.equal(verifyRecoveryWebhookSignature(oldWebhook, oldSigned), true);
  assert.equal(verifyRecoveryWebhookSignature(oldWebhook, newSigned), false);
  assert.equal(verifyRecoveryWebhookSignature(nextWebhook, oldSigned), false);
  assert.equal(verifyRecoveryWebhookSignature(nextWebhook, newSigned), true);
});
