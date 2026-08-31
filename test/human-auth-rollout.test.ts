import assert from 'node:assert/strict';
import test from 'node:test';

import {
  HUMAN_AUTH_COHORT_ALGORITHM,
  humanAuthTenantCohort,
  registerHumanAuthRolloutRoutes
} from '../src/human-auth-rollout.js';
import { createApp } from '../src/app.js';
import { createPrismaOidcLoginStore } from '../src/oidc.js';
import { createPrismaBrowserSessionStore } from '../src/sessions.js';
import type { PrismaClient } from '@prisma/client';

test('tenant cohorts use a fixed, stable and auditable SHA-256 mapping', () => {
  assert.equal(HUMAN_AUTH_COHORT_ALGORITHM, 'sha256-tenant-v1');
  assert.equal(humanAuthTenantCohort('00000000-0000-4000-8000-000000000001'), 42);
  assert.equal(humanAuthTenantCohort('00000000-0000-4000-8000-000000000002'), 55);
  assert.equal(humanAuthTenantCohort('00000000-0000-4000-8000-000000000001'), 42);
});

test('OIDC and session stores reject missing rollout gates at construction', () => {
  assert.throws(() => createPrismaOidcLoginStore({} as PrismaClient, undefined as never),
    /requires a HumanAuthRolloutGate/);
  assert.throws(() => createPrismaBrowserSessionStore({} as PrismaClient, {
    currentCsrfKeyVersion: 1,
    csrfKeys: new Map([[1, Buffer.alloc(32)]]),
    publicApplicationOrigin: 'https://app.example.test'
  }, {} as never), /requires a HumanAuthRolloutGate/);
});

test('rollout admin endpoint is provider-only and validates an exact secret-free payload', async () => {
  const calls: unknown[] = [];
  const providerId = '00000000-0000-4000-8000-000000000010';
  const app = createApp({
    authenticator: { async authenticate(request) { request.browserSessionSnapshot = {
      authenticatedAt: new Date(), csrfDigest: Buffer.alloc(32)
    } as never; return { principalType: 'human', authMethod: 'oidc-session',
      id: providerId, accountId: providerId, sessionId: providerId, role: 'provedor', condominioIds: null } as const; } },
    authRateLimiter: { async check() { return { allowed: true, retryAfterSeconds: 0, repeatedExcess: false }; },
      async reserve() { return { allowed: true, retryAfterSeconds: 0, repeatedExcess: false,
        reservationId: providerId }; }, async finalize() {} },
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
    const staleApp = createApp({
      authenticator: { async authenticate(request) { request.browserSessionSnapshot = {
        authenticatedAt: new Date(Date.now() - 10 * 60_000 - 1), csrfDigest: Buffer.alloc(32)
      } as never; return { principalType: 'human', authMethod: 'oidc-session', id: providerId, accountId: providerId,
        sessionId: providerId, role: 'provedor', condominioIds: null } as const; } },
      authRateLimiter: { async check() { return { allowed: true, retryAfterSeconds: 0, repeatedExcess: false }; },
        async reserve() { return { allowed: true, retryAfterSeconds: 0, repeatedExcess: false,
          reservationId: providerId }; }, async finalize() {} },
      humanAuthRolloutService: { async getPolicies() { return []; }, async setPolicy() { calls.push('stale'); return null; } } as never
    });
    const stale = await staleApp.inject({ method: 'PUT', url: '/admin/human-auth/rollout',
      payload: { condominioId: null, state: 'disabled' } });
    assert.equal(stale.statusCode, 403);
    assert.deepEqual(stale.json(), { error: 'reauthentication_required' });
    assert.equal(calls.length, 2);
    await staleApp.close();
  } finally { await app.close(); }
});

// Compile-time coverage keeps the standalone registrar part of the public module contract.
void registerHumanAuthRolloutRoutes;
