import assert from 'node:assert/strict';
import { createHmac, randomBytes } from 'node:crypto';
import test from 'node:test';

import {
  evidenceSatisfiesRole,
  humanAdministrationConfigFromEnvironment,
  normalizeProvisioningEmail
} from '../src/human-administration.js';

const policy = {
  provedor: { amr: ['webauthn'], acr: ['urn:phishing-resistant'] },
  sindico: { amr: ['webauthn'], acr: ['urn:phishing-resistant'] },
  morador: { amr: ['webauthn', 'otp'], acr: [] },
  portaria: { amr: ['webauthn'], acr: ['urn:phishing-resistant'] }
} as const;

test('provisioning email normalization and MFA policy fail closed', () => {
  assert.equal(normalizeProvisioningEmail(' Person@Example.TEST '), 'person@example.test');
  assert.equal(normalizeProvisioningEmail('invalid'), null);
  assert.equal(evidenceSatisfiesRole(policy, 'provedor', { amr: [], acr: null }), false);
  assert.equal(evidenceSatisfiesRole(policy, 'provedor', { amr: ['otp'], acr: 'urn:phishing-resistant' }), false);
  assert.equal(evidenceSatisfiesRole(policy, 'provedor', { amr: ['webauthn'], acr: null }), false);
  assert.equal(evidenceSatisfiesRole(policy, 'provedor', { amr: ['webauthn'], acr: 'urn:phishing-resistant' }), true);
  assert.equal(evidenceSatisfiesRole(policy, 'morador', { amr: ['otp'], acr: null }), true);
  assert.equal(evidenceSatisfiesRole(policy, 'morador', { amr: ['sms'], acr: null }), false);
});

test('human administration environment requires exact recovery, webhook, and complete role policy configuration', () => {
  const secret = randomBytes(32).toString('base64url');
  const base = {
    HUMAN_AUTH_ENABLED: 'true',
    PUBLIC_APPLICATION_ORIGIN: 'https://app.example.test',
    OIDC_RECOVERY_URL: 'https://identity.example.test/recovery',
    RECOVERY_WEBHOOK_ISSUERS: 'https://identity.example.test',
    RECOVERY_WEBHOOK_SECRET: secret,
    HUMAN_MFA_ROLE_POLICY: JSON.stringify(policy)
  };
  const config = humanAdministrationConfigFromEnvironment(base)!;
  assert.equal(config.recoveryUrl, base.OIDC_RECOVERY_URL);
  assert.equal(config.recoveryWebhookSecret.toString(), secret);
  assert.throws(() => humanAdministrationConfigFromEnvironment({ ...base, RECOVERY_WEBHOOK_SECRET: 'short' }), /at least 32 bytes/);
  assert.throws(() => humanAdministrationConfigFromEnvironment({ ...base, OIDC_RECOVERY_URL: 'http://identity.test/recovery' }), /HTTPS/);
  assert.throws(() => humanAdministrationConfigFromEnvironment({ ...base, HUMAN_MFA_ROLE_POLICY: '{}' }), /every role/);
  assert.deepEqual(
    [...humanAdministrationConfigFromEnvironment({ ...base,
      RECOVERY_WEBHOOK_ISSUERS: 'https://identity.example.test/,https://identity.example.test'
    })!.recoveryWebhookIssuers],
    ['https://identity.example.test/', 'https://identity.example.test']
  );
  assert.throws(() => humanAdministrationConfigFromEnvironment({ ...base,
    HUMAN_MFA_ROLE_POLICY: JSON.stringify({ ...policy, provedor: { amr: ['otp'], acr: ['strong'] } })
  }), /unsafe method/);

  const timestamp = Math.floor(Date.now() / 1000);
  const canonical = `${timestamp}.event-id.https://identity.example.test.subject`;
  assert.equal(createHmac('sha256', config.recoveryWebhookSecret).update(canonical).digest('hex').length, 64);
});
