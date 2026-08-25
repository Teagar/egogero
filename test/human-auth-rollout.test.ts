import assert from 'node:assert/strict';
import test from 'node:test';

import {
  HUMAN_AUTH_COHORT_ALGORITHM,
  humanAuthTenantCohort,
  registerHumanAuthRolloutRoutes
} from '../src/human-auth-rollout.js';
import { createApp } from '../src/app.js';

test('tenant cohorts use a fixed, stable and auditable SHA-256 mapping', () => {
  assert.equal(HUMAN_AUTH_COHORT_ALGORITHM, 'sha256-tenant-v1');
  assert.equal(humanAuthTenantCohort('00000000-0000-4000-8000-000000000001'), 42);
  assert.equal(humanAuthTenantCohort('00000000-0000-4000-8000-000000000002'), 55);
  assert.equal(humanAuthTenantCohort('00000000-0000-4000-8000-000000000001'), 42);
});

test('rollout admin endpoint is provider-only and validates an exact secret-free payload', async () => {
  const calls: unknown[] = [];
  const providerId = '00000000-0000-4000-8000-000000000010';
  const app = createApp({
    authenticator: { async authenticate() { return { principalType: 'human', authMethod: 'oidc-session',
      id: providerId, accountId: providerId, sessionId: providerId, role: 'provedor', condominioIds: null } as const; } },
    authRateLimiter: { async check() { return { allowed: true, retryAfterSeconds: 0, repeatedExcess: false }; },
      async reserveFailure() { return { allowed: true, retryAfterSeconds: 0, repeatedExcess: false,
        reservationId: providerId }; }, async finalizeFailure() {} },
    humanAuthRolloutService: {
      async getPolicies() { return []; },
      async setPolicy(input: unknown) { calls.push(input); return { scope: 'global', state: 'enabled',
        cohortPercentage: null, version: 2, revokedSessions: 0 }; }
    } as never
  });
  try {
    assert.equal((await app.inject({ method: 'PUT', url: '/admin/human-auth/rollout',
      payload: { condominioId: null, state: 'enabled', cohortPercentage: null, extra: true } })).statusCode, 400);
    assert.equal((await app.inject({ method: 'PUT', url: '/admin/human-auth/rollout',
      payload: { condominioId: null, state: 'pilot', cohortPercentage: 25 } })).statusCode, 400);
    const response = await app.inject({ method: 'PUT', url: '/admin/human-auth/rollout',
      payload: { condominioId: null, state: 'enabled' } });
    assert.equal(response.statusCode, 200);
    assert.equal(calls.length, 1);
    assert.equal(JSON.stringify(response.json()).includes('token'), false);
  } finally { await app.close(); }
});

// Compile-time coverage keeps the standalone registrar part of the public module contract.
void registerHumanAuthRolloutRoutes;
