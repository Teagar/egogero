import assert from 'node:assert/strict';
import { createHash, randomUUID } from 'node:crypto';
import test from 'node:test';

import Fastify from 'fastify';

import type { AppStore } from '../src/app.js';
import type { Authenticator, HumanSessionIdentity } from '../src/auth.js';
import { registerConviteRoutes } from '../src/convites.js';
import type { InvitationStore } from '../src/convites.js';

test('human gatehouse uses its own tenant/operator audit contract and leaves the device route closed', async () => {
  const condominiumId = randomUUID();
  const accountId = randomUUID();
  const membershipId = randomUUID();
  const identity: HumanSessionIdentity = {
    principalType: 'human', authMethod: 'oidc-session', role: 'portaria', accountId,
    sessionId: randomUUID(), id: accountId, condominioIds: [condominiumId]
  };
  let humanCalls = 0;
  let deviceCalls = 0;
  const authenticator: Authenticator = {
    async authenticate(request) {
      request.browserSessionSnapshot = {
        identity, familyId: randomUUID(), account: { id: accountId, displayName: 'Operator' },
        memberships: [], activeMembershipId: membershipId, activeTenantId: condominiumId,
        csrfToken: 'c'.repeat(43), csrfDigest: createHash('sha256').update('csrf').digest(),
        expiresAt: new Date(Date.now() + 60_000), idleExpiresAt: new Date(Date.now() + 60_000),
        authenticatedAt: new Date()
      };
      return identity;
    }
  };
  const store: InvitationStore = {
    async createActive() { throw new Error('not used'); },
    async createBatchActive() { throw new Error('not used'); },
    async validateActive() { deviceCalls += 1; throw new Error('device route reached storage'); },
    async validateHumanActive(args) {
      humanCalls += 1;
      assert.deepEqual(args, { token: '123456', condominiumId, accountId, membershipId, accessType: 'pedestre' });
      return { allowed: false, reason: 'invalid_or_unavailable' };
    },
    async listHumanAudits(args) {
      assert.deepEqual(args, { condominiumId, accountId, limit: 25 });
      return [{ id: randomUUID(), createdAt: new Date('2026-08-24T10:00:00Z'), accessType: 'pedestre',
        result: 'negado', invitationType: null, guestName: null }];
    },
    async listOwnedAudits() { return []; },
    async revokeActive() { return 'unavailable'; }
  };
  const app = Fastify({ logger: false });
  registerConviteRoutes(app, {} as AppStore, store, authenticator, undefined, undefined, undefined, undefined, false, {
    async check() { return { allowed: true, retryAfterSeconds: 0, repeatedExcess: false }; },
    async reserve() { return { allowed: true, retryAfterSeconds: 0, repeatedExcess: false, reservationId: randomUUID() }; },
    async finalize() {}
  });
  const human = await app.inject({ method: 'POST', url: '/portaria/human/convites/validar', payload: { token: '123456', tipoAcesso: 'pedestre' } });
  assert.equal(human.statusCode, 200);
  assert.deepEqual(human.json(), { allowed: false, reason: 'invalid_or_unavailable' });
  const recent = await app.inject({ method: 'GET', url: '/portaria/human/validacoes-recentes' });
  assert.equal(recent.statusCode, 200);
  assert.equal(recent.json()[0].guestName, null);
  assert.equal(JSON.stringify(recent.json()).includes('morador'), false);
  const legacy = await app.inject({ method: 'POST', url: '/portaria/convites/validar', payload: { token: '123456', tipoAcesso: 'pedestre' } });
  assert.equal(legacy.statusCode, 403);
  assert.equal(humanCalls, 1);
  assert.equal(deviceCalls, 0);
  await app.close();
});
