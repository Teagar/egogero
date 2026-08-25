import assert from 'node:assert/strict';
import test from 'node:test';

import { ARTIFACT_CANARY, hasCredentialLeak } from './e2e/artifacts.js';

test('artifact credential verification accepts terminated markers and rejects residual values', () => {
  assert.equal(hasCredentialLeak('?state=[REDACTED]), __Host-eg_session=[REDACTED],'), false);
  assert.equal(hasCredentialLeak('?state=still-present'), true);
  assert.equal(hasCredentialLeak('__Host-eg_session=still-present;'), true);
  assert.equal(hasCredentialLeak(ARTIFACT_CANARY), true);
});
