import assert from 'node:assert/strict';
import { randomBytes, randomUUID } from 'node:crypto';
import test from 'node:test';

import { PrismaClient } from '@prisma/client';

import { createPrismaOidcLoginStore } from '../src/oidc.js';
import type { OidcLoginStore } from '../src/oidc.js';

const runDatabaseTests = process.env.RUN_DATABASE_TESTS === 'true';

test(
  'PostgreSQL consumes each OIDC state once and persists only a provisioned validated identity handoff',
  { skip: !runDatabaseTests },
  async () => {
    const prisma = new PrismaClient();
    const store = createPrismaOidcLoginStore(prisma);
    const accountId = randomUUID();
    const externalIdentityId = randomUUID();
    const transactionId = randomUUID();
    const stateDigest = randomBytes(32);
    const nonceDigest = randomBytes(32);
    const createInput: Parameters<OidcLoginStore['createTransaction']>[0] = {
      id: transactionId,
      expiresAt: new Date(Date.now() + 600_000),
      stateDigest,
      nonceDigest,
      pkceVerifierCiphertext: randomBytes(43),
      pkceVerifierNonce: randomBytes(12),
      pkceVerifierAuthTag: randomBytes(16),
      pkceKeyVersion: 1,
      issuer: 'https://identity.example.test',
      clientId: 'egogero-client',
      redirectUri: 'https://app.example.test/auth/callback',
      returnTo: '/',
      recoveryIntent: false,
      audit: {
        eventType: 'oidc_login_started',
        outcome: 'success',
        requestCorrelationId: randomUUID()
      }
    };

    try {
      await prisma.humanAccount.create({
        data: { id: accountId, displayName: 'OIDC Test', status: 'active' }
      });
      await prisma.externalIdentity.create({
        data: {
          id: externalIdentityId,
          accountId,
          issuer: createInput.issuer,
          subject: 'provisioned-subject'
        }
      });
      await store.createTransaction(createInput);

      const attempts = await Promise.all([
        store.consumeTransaction(stateDigest),
        store.consumeTransaction(stateDigest)
      ]);
      assert.equal(attempts.filter(Boolean).length, 1);
      assert.equal(attempts.find(Boolean)?.id, transactionId);

      const stored = await prisma.oidcLoginTransaction.findUniqueOrThrow({ where: { id: transactionId } });
      assert.deepEqual(Buffer.from(stored.stateDigest), stateDigest);
      assert.deepEqual(Buffer.from(stored.nonceDigest), nonceDigest);
      assert.ok(stored.consumedAt);
      assert.equal('state' in stored, false);
      assert.equal('nonce' in stored, false);
      assert.equal('pkceVerifier' in stored, false);

      const handoff = await store.completeIdentity({
        loginTransactionId: transactionId,
        issuer: createInput.issuer,
        subject: 'provisioned-subject',
        email: 'updated@example.test',
        emailVerified: true,
        authenticatedAt: new Date(),
        handoffId: randomUUID(),
        handoffDigest: randomBytes(32),
        handoffExpiresAt: new Date(Date.now() + 300_000),
        audit: {
          eventType: 'oidc_callback_succeeded',
          outcome: 'success',
          requestCorrelationId: randomUUID()
        }
      });
      assert.equal(handoff?.accountId, accountId);
      assert.equal(handoff?.externalIdentityId, externalIdentityId);
      assert.equal((await prisma.externalIdentity.findUniqueOrThrow({ where: { id: externalIdentityId } })).email, 'updated@example.test');
      assert.equal(await prisma.browserSession.count({ where: { accountId } }), 0);
      const persistedHandoff = await prisma.oidcValidatedHandoff.findFirstOrThrow({ where: { accountId } });
      assert.equal(persistedHandoff.externalIdentityId, externalIdentityId);
      assert.equal('handle' in persistedHandoff, false);
      const consumedHandoffs = await Promise.all([
        store.consumeHandoff(Buffer.from(persistedHandoff.handleDigest)),
        store.consumeHandoff(Buffer.from(persistedHandoff.handleDigest))
      ]);
      assert.equal(consumedHandoffs.filter(Boolean).length, 1);

      const events = await prisma.authenticationAuditEvent.findMany({
        where: { accountId },
        select: { eventType: true, outcome: true, metadata: true }
      });
      assert.deepEqual(events, [{ eventType: 'oidc_callback_succeeded', outcome: 'success', metadata: {} }]);
    } finally {
      await prisma.oidcValidatedHandoff.deleteMany({ where: { accountId } });
      await prisma.oidcLoginTransaction.deleteMany({ where: { id: transactionId } });
      await prisma.externalIdentity.deleteMany({ where: { id: externalIdentityId } });
      await prisma.humanAccount.deleteMany({ where: { id: accountId } });
      await prisma.$disconnect();
    }
  }
);
