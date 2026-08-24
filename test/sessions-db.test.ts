import assert from 'node:assert/strict';
import { createHash, randomBytes, randomUUID } from 'node:crypto';
import test from 'node:test';

import { PrismaClient } from '@prisma/client';

import {
  createPrismaBrowserSessionStore,
  generateSessionToken
} from '../src/sessions.js';
import type { SessionRuntimeConfig } from '../src/sessions.js';

const runDatabaseTests = process.env.RUN_DATABASE_TESTS === 'true' && Boolean(process.env.DATABASE_URL);

function digest(value: string) {
  return createHash('sha256').update(value).digest();
}

test(
  'PostgreSQL sessions consume handoffs once, map live roles, rotate atomically, and revoke without persisting secrets',
  { skip: !runDatabaseTests },
  async () => {
    const prisma = new PrismaClient();
    const csrfKey = randomBytes(32);
    const nextCsrfKey = randomBytes(32);
    const config: SessionRuntimeConfig = {
      currentCsrfKeyVersion: 1,
      csrfKeys: new Map([[1, csrfKey], [2, nextCsrfKey]]),
      publicApplicationOrigin: 'https://app.example.test'
    };
    const store = createPrismaBrowserSessionStore(prisma, config);
    const accountId = randomUUID();
    const externalIdentityId = randomUUID();
    const otherAccountId = randomUUID();
    const otherExternalIdentityId = randomUUID();
    const otherMembershipId = randomUUID();
    const condominioA = randomUUID();
    const condominioB = randomUUID();
    const residentId = randomUUID();
    const providerMembershipId = randomUUID();
    const managerMembershipId = randomUUID();
    const residentMembershipId = randomUUID();
    const gatehouseMembershipId = randomUUID();
    const loginTransactionIds: string[] = [];

    async function createHandoff(
      reauthenticationFamilyId?: string,
      targetAccountId = accountId,
      targetExternalIdentityId = externalIdentityId
    ) {
      const reauthenticationIntent = reauthenticationFamilyId !== undefined;
      const loginTransactionId = randomUUID();
      const handoffToken = generateSessionToken();
      loginTransactionIds.push(loginTransactionId);
      await prisma.oidcLoginTransaction.create({
        data: {
          id: loginTransactionId,
          expiresAt: new Date(Date.now() + 600_000),
          stateDigest: randomBytes(32),
          nonceDigest: randomBytes(32),
          pkceVerifierCiphertext: randomBytes(43),
          pkceVerifierNonce: randomBytes(12),
          pkceVerifierAuthTag: randomBytes(16),
          pkceKeyVersion: 1,
          issuer: 'https://identity.example.test',
          clientId: 'session-tests',
          redirectUri: 'https://app.example.test/auth/callback',
          returnTo: '/',
          reauthenticationIntent,
          reauthenticationFamilyId
        }
      });
      await prisma.oidcValidatedHandoff.create({
        data: {
          id: randomUUID(),
          expiresAt: new Date(Date.now() + 300_000),
          handleDigest: digest(handoffToken),
          loginTransactionId,
          accountId: targetAccountId,
          externalIdentityId: targetExternalIdentityId,
          authenticatedAt: new Date(),
          reauthenticationIntent,
          reauthenticationFamilyId
        }
      });
      return handoffToken;
    }

    async function issue(handoffToken: string, oldSessionToken?: string) {
      return store.issueFromHandoff({
        handoffToken,
        oldSessionToken,
        requestCorrelationId: randomUUID(),
        ipPrefix: '192.0.2.0/24',
        userAgent: 'session-db-test-agent'
      });
    }

    try {
      await prisma.condominio.createMany({
        data: [
          { id: condominioA, nome: 'Session A', responsavel: 'A', tipo: 'residencial', timezone: 'UTC' },
          { id: condominioB, nome: 'Session B', responsavel: 'B', tipo: 'residencial', timezone: 'UTC' }
        ]
      });
      await prisma.morador.create({
        data: { id: residentId, nome: 'Resident Session', condominioId: condominioA }
      });
      await prisma.humanAccount.create({
        data: { id: accountId, displayName: 'Session Account', status: 'active' }
      });
      await prisma.externalIdentity.create({
        data: {
          id: externalIdentityId,
          accountId,
          issuer: 'https://identity.example.test',
          subject: `session-${accountId}`
        }
      });
      await prisma.humanAccount.create({
        data: { id: otherAccountId, displayName: 'Other Session Account', status: 'active' }
      });
      await prisma.externalIdentity.create({
        data: {
          id: otherExternalIdentityId,
          accountId: otherAccountId,
          issuer: 'https://identity.example.test',
          subject: `session-${otherAccountId}`
        }
      });
      await prisma.humanMembership.create({
        data: { id: otherMembershipId, accountId: otherAccountId, role: 'provedor', status: 'active' }
      });
      const membershipBase = Date.now() - 10_000;
      await prisma.humanMembership.createMany({
        data: [
          {
            id: providerMembershipId,
            accountId,
            role: 'provedor',
            status: 'active',
            createdAt: new Date(membershipBase)
          },
          {
            id: managerMembershipId,
            accountId,
            condominioId: condominioA,
            role: 'sindico',
            status: 'active',
            createdAt: new Date(membershipBase + 1)
          },
          {
            id: residentMembershipId,
            accountId,
            condominioId: condominioA,
            residentId,
            role: 'morador',
            status: 'active',
            createdAt: new Date(membershipBase + 2)
          },
          {
            id: gatehouseMembershipId,
            accountId,
            condominioId: condominioB,
            role: 'portaria',
            status: 'active',
            createdAt: new Date(membershipBase + 3)
          }
        ]
      });

      const oneTimeHandoff = await createHandoff();
      const concurrentIssues = await Promise.all([issue(oneTimeHandoff), issue(oneTimeHandoff)]);
      assert.equal(concurrentIssues.filter(Boolean).length, 1);
      const first = concurrentIssues.find((candidate) => candidate !== null)!;
      assert.equal(first.identity.role, 'provedor');
      assert.equal(first.identity.id, accountId);
      assert.equal(first.identity.accountId, accountId);
      assert.equal(first.identity.condominioIds, null);
      assert.match(first.sessionToken, /^[A-Za-z0-9_-]{43}$/);
      assert.match(first.csrfToken, /^[A-Za-z0-9_-]{43}$/);

      const firstStored = await prisma.browserSession.findUniqueOrThrow({
        where: { id: first.identity.sessionId }
      });
      assert.deepEqual(Buffer.from(firstStored.tokenDigest), digest(first.sessionToken));
      assert.notDeepEqual(Buffer.from(firstStored.tokenDigest), Buffer.from(first.sessionToken));
      assert.deepEqual(
        Buffer.from(firstStored.csrfDigest),
        createHash('sha256').update(Buffer.from(first.csrfToken, 'base64url')).digest()
      );
      assert.notDeepEqual(Buffer.from(firstStored.csrfCiphertext), Buffer.from(first.csrfToken, 'base64url'));
      assert.equal(Buffer.from(firstStored.csrfNonce).length, 12);
      assert.equal(Buffer.from(firstStored.csrfAuthTag).length, 16);

      const idleCap = new Date(Date.now() + 10 * 60_000);
      await prisma.browserSession.update({
        where: { id: first.identity.sessionId },
        data: {
          createdAt: new Date(Date.now() - 10 * 60_000),
          authenticatedAt: new Date(Date.now() - 11 * 60_000),
          lastSeenAt: new Date(Date.now() - 6 * 60_000),
          idleExpiresAt: new Date(Date.now() + 60_000),
          absoluteExpiresAt: idleCap
        }
      });
      const touched = await store.inspect({ sessionToken: first.sessionToken, requestCorrelationId: 'idle-touch' });
      assert.ok(touched);
      assert.ok(Math.abs(touched.idleExpiresAt.getTime() - idleCap.getTime()) < 1_000);
      const touchedStored = await prisma.browserSession.findUniqueOrThrow({ where: { id: first.identity.sessionId } });
      assert.equal(touched.idleExpiresAt.getTime(), touchedStored.idleExpiresAt.getTime());
      await prisma.browserSession.update({
        where: { id: first.identity.sessionId },
        data: {
          createdAt: firstStored.createdAt,
          authenticatedAt: firstStored.authenticatedAt,
          lastSeenAt: firstStored.lastSeenAt,
          idleExpiresAt: firstStored.idleExpiresAt,
          absoluteExpiresAt: firstStored.absoluteExpiresAt
        }
      });

      const rotatedKeyStore = createPrismaBrowserSessionStore(prisma, {
        currentCsrfKeyVersion: 2,
        csrfKeys: new Map([[1, csrfKey], [2, nextCsrfKey]]),
        publicApplicationOrigin: 'https://app.example.test'
      });
      assert.equal((await rotatedKeyStore.inspect({
        sessionToken: first.sessionToken,
        requestCorrelationId: 'csrf-key-rotation'
      }))?.csrfToken, first.csrfToken);
      const reencrypted = await prisma.browserSession.findUniqueOrThrow({ where: { id: first.identity.sessionId } });
      assert.equal(reencrypted.csrfKeyVersion, 2);
      assert.notDeepEqual(Buffer.from(reencrypted.csrfNonce), Buffer.from(firstStored.csrfNonce));
      assert.equal((await store.inspect({
        sessionToken: first.sessionToken,
        requestCorrelationId: 'csrf-key-old-process-read'
      }))?.csrfToken, first.csrfToken);
      assert.equal(
        (await prisma.browserSession.findUniqueOrThrow({ where: { id: first.identity.sessionId } })).csrfKeyVersion,
        2,
        'an old process must not downgrade a newer row'
      );

      assert.deepEqual(await store.authenticate(first.sessionToken, 'authenticate-provider'), first.identity);
      const otherSession = await issue(await createHandoff(undefined, otherAccountId, otherExternalIdentityId));
      assert.ok(otherSession);
      const switchedAccount = await issue(await createHandoff(), otherSession.sessionToken);
      assert.ok(switchedAccount);
      assert.equal(switchedAccount.identity.accountId, accountId);
      assert.equal(await store.authenticate(otherSession.sessionToken, 'cross-account-session-replaced'), null);
      assert.equal(await store.revoke({
        sessionToken: switchedAccount.sessionToken,
        requestCorrelationId: 'cleanup-cross-account-switch'
      }), 'revoked');
      const rotations = await Promise.all([
        store.rotate({
          sessionToken: first.sessionToken,
          targetMembershipId: managerMembershipId,
          requestCorrelationId: 'rotate-winner-a'
        }),
        store.rotate({
          sessionToken: first.sessionToken,
          targetMembershipId: managerMembershipId,
          requestCorrelationId: 'rotate-winner-b'
        })
      ]);
      assert.equal(rotations.filter((result) => result.status === 'rotated').length, 1);
      assert.equal(rotations.filter((result) => result.status === 'stale').length, 1);
      const manager = rotations.find((result) => result.status === 'rotated')!;
      assert.equal(manager.identity.role, 'sindico');
      assert.equal(manager.identity.id, accountId);
      assert.deepEqual(manager.identity.condominioIds, [condominioA]);
      assert.equal(manager.csrfToken, first.csrfToken);

      const managerStored = await prisma.browserSession.findUniqueOrThrow({
        where: { id: manager.identity.sessionId }
      });
      assert.equal(managerStored.familyId, firstStored.familyId);
      assert.deepEqual(Buffer.from(managerStored.csrfDigest), Buffer.from(firstStored.csrfDigest));
      assert.notDeepEqual(Buffer.from(managerStored.csrfNonce), Buffer.from(firstStored.csrfNonce));
      assert.equal(managerStored.absoluteExpiresAt.getTime(), firstStored.absoluteExpiresAt.getTime());
      assert.equal(managerStored.authenticatedAt.getTime(), firstStored.authenticatedAt.getTime());

      await prisma.morador.update({ where: { id: residentId }, data: { deletedAt: new Date() } });
      assert.deepEqual(await store.rotate({
        sessionToken: manager.sessionToken,
        targetMembershipId: residentMembershipId,
        requestCorrelationId: 'rotate-deleted-resident'
      }), { status: 'denied' });
      await prisma.morador.update({ where: { id: residentId }, data: { deletedAt: null } });
      const resident = await store.rotate({
        sessionToken: manager.sessionToken,
        targetMembershipId: residentMembershipId,
        requestCorrelationId: 'rotate-resident'
      });
      assert.equal(resident.status, 'rotated');
      if (resident.status !== 'rotated') throw new Error('resident rotation failed');
      assert.equal(resident.identity.role, 'morador');
      assert.equal(resident.identity.id, residentId);
      assert.deepEqual(resident.identity.condominioIds, [condominioA]);

      const gatehouse = await store.rotate({
        sessionToken: resident.sessionToken,
        targetMembershipId: gatehouseMembershipId,
        requestCorrelationId: 'rotate-gatehouse'
      });
      assert.equal(gatehouse.status, 'rotated');
      if (gatehouse.status !== 'rotated') throw new Error('gatehouse rotation failed');
      assert.equal(gatehouse.identity.role, 'portaria');
      assert.equal(gatehouse.identity.id, accountId);
      assert.deepEqual(gatehouse.identity.condominioIds, [condominioB]);

      const invalidTarget = await store.rotate({
        sessionToken: gatehouse.sessionToken,
        targetMembershipId: randomUUID(),
        requestCorrelationId: 'invalid-target'
      });
      assert.deepEqual(invalidTarget, { status: 'denied' });

      assert.equal(await issue(await createHandoff(randomUUID()), gatehouse.sessionToken), null);
      assert.deepEqual(await store.authenticate(gatehouse.sessionToken, 'cross-family-reauthentication'), gatehouse.identity);
      const reauthenticated = await issue(await createHandoff(firstStored.familyId), gatehouse.sessionToken);
      assert.ok(reauthenticated);
      assert.equal(reauthenticated.csrfToken, gatehouse.csrfToken);
      assert.equal(
        (await prisma.browserSession.findUniqueOrThrow({ where: { id: reauthenticated.identity.sessionId } })).familyId,
        firstStored.familyId
      );
      assert.equal(
        (await prisma.browserSession.findUniqueOrThrow({ where: { id: gatehouse.identity.sessionId } })).revokeReason,
        'reauthenticated'
      );

      const oldFamilyId = firstStored.familyId;
      const [nextLogin, racingRotation] = await Promise.all([
        issue(await createHandoff(), reauthenticated.sessionToken),
        store.rotate({
          sessionToken: reauthenticated.sessionToken,
          targetMembershipId: managerMembershipId,
          requestCorrelationId: 'ordinary-login-racing-rotation'
        })
      ]);
      assert.ok(nextLogin);
      assert.equal(nextLogin.identity.role, racingRotation.status === 'rotated' ? 'sindico' : 'portaria');
      const nextCondominiumId = nextLogin.identity.role === 'sindico' ? condominioA : condominioB;
      const nextMembershipId = nextLogin.identity.role === 'sindico' ? managerMembershipId : gatehouseMembershipId;
      assert.notEqual(nextLogin.csrfToken, gatehouse.csrfToken);
      assert.notEqual(
        (await prisma.browserSession.findUniqueOrThrow({ where: { id: nextLogin.identity.sessionId } })).familyId,
        firstStored.familyId
      );
      assert.equal(await prisma.browserSession.count({ where: { familyId: oldFamilyId, revokedAt: null } }), 0);
      assert.ok(await prisma.browserSession.count({
        where: { familyId: oldFamilyId, revokeReason: 'login_replaced' }
      }) >= 1);
      assert.equal(await prisma.browserSession.count({
        where: {
          accountId,
          revokedAt: null,
          familyId: (await prisma.browserSession.findUniqueOrThrow({ where: { id: nextLogin.identity.sessionId } })).familyId
        }
      }), 1);
      if (racingRotation.status === 'rotated') {
        assert.equal(await store.authenticate(racingRotation.sessionToken, 'racing-replacement-revoked'), null);
      } else {
        assert.equal(racingRotation.status, 'stale');
      }

      await prisma.condominio.update({ where: { id: nextCondominiumId }, data: { deletedAt: new Date() } });
      assert.equal(await store.authenticate(nextLogin.sessionToken, 'deleted-condominium'), null);
      await prisma.condominio.update({ where: { id: nextCondominiumId }, data: { deletedAt: null } });
      assert.deepEqual(await store.authenticate(nextLogin.sessionToken, 'restored-condominium'), nextLogin.identity);

      await prisma.humanMembership.update({
        where: { id: nextMembershipId },
        data: { status: 'disabled', disabledAt: new Date() }
      });
      assert.equal(await store.authenticate(nextLogin.sessionToken, 'disabled-membership'), null);
      await prisma.humanMembership.update({
        where: { id: nextMembershipId },
        data: { status: 'active', disabledAt: null }
      });
      await prisma.humanAccount.update({ where: { id: accountId }, data: { status: 'suspended' } });
      assert.equal(await store.authenticate(nextLogin.sessionToken, 'suspended-account'), null);
      await prisma.humanAccount.update({ where: { id: accountId }, data: { status: 'active' } });

      await prisma.humanAccount.update({ where: { id: accountId }, data: { sessionVersion: { increment: 1 } } });
      assert.equal(await store.authenticate(nextLogin.sessionToken, 'version-mismatch'), null);
      await prisma.humanAccount.update({ where: { id: accountId }, data: { sessionVersion: { decrement: 1 } } });

      const beforeExpiry = await prisma.browserSession.findUniqueOrThrow({ where: { id: nextLogin.identity.sessionId } });
      const expiredBase = Date.now() - 20 * 60_000;
      await prisma.$executeRaw`
        UPDATE "BrowserSession"
        SET "authenticatedAt" = ${new Date(expiredBase - 60_000)},
            "createdAt" = ${new Date(expiredBase)},
            "lastSeenAt" = ${new Date(expiredBase + 60_000)},
            "idleExpiresAt" = ${new Date(Date.now() - 60_000)},
            "absoluteExpiresAt" = ${new Date(Date.now() + 60_000)}
        WHERE id = ${nextLogin.identity.sessionId}::uuid
      `;
      assert.equal(await store.authenticate(nextLogin.sessionToken, 'idle-expired'), null);
      await prisma.$executeRaw`
        UPDATE "BrowserSession"
        SET "authenticatedAt" = ${new Date(expiredBase - 180_000)},
            "createdAt" = ${new Date(expiredBase - 120_000)},
            "lastSeenAt" = ${new Date(expiredBase - 60_000)},
            "idleExpiresAt" = ${new Date(Date.now() - 120_000)},
            "absoluteExpiresAt" = ${new Date(Date.now() - 60_000)}
        WHERE id = ${nextLogin.identity.sessionId}::uuid
      `;
      assert.equal(await store.authenticate(nextLogin.sessionToken, 'absolute-expired'), null);
      await prisma.browserSession.update({
        where: { id: nextLogin.identity.sessionId },
        data: {
          createdAt: beforeExpiry.createdAt,
          authenticatedAt: beforeExpiry.authenticatedAt,
          lastSeenAt: beforeExpiry.lastSeenAt,
          idleExpiresAt: beforeExpiry.idleExpiresAt,
          absoluteExpiresAt: beforeExpiry.absoluteExpiresAt
        }
      });

      const storedBeforeTamper = await prisma.browserSession.findUniqueOrThrow({
        where: { id: nextLogin.identity.sessionId }
      });
      await prisma.browserSession.update({
        where: { id: nextLogin.identity.sessionId },
        data: { csrfAuthTag: randomBytes(16) }
      });
      assert.deepEqual(await store.rotate({
        sessionToken: nextLogin.sessionToken,
        requestCorrelationId: 'csrf-tampered'
      }), { status: 'denied' });
      await prisma.browserSession.update({
        where: { id: nextLogin.identity.sessionId },
        data: { csrfAuthTag: storedBeforeTamper.csrfAuthTag }
      });
      await prisma.browserSession.update({
        where: { id: nextLogin.identity.sessionId },
        data: { csrfDigest: randomBytes(32) }
      });
      assert.equal(await store.inspect({
        sessionToken: nextLogin.sessionToken,
        requestCorrelationId: 'csrf-digest-tampered'
      }), null);
      await prisma.browserSession.update({
        where: { id: nextLogin.identity.sessionId },
        data: { csrfDigest: storedBeforeTamper.csrfDigest, csrfCiphertext: randomBytes(32) }
      });
      assert.equal(await store.inspect({
        sessionToken: nextLogin.sessionToken,
        requestCorrelationId: 'csrf-ciphertext-tampered'
      }), null);
      await prisma.browserSession.update({
        where: { id: nextLogin.identity.sessionId },
        data: { csrfCiphertext: storedBeforeTamper.csrfCiphertext }
      });
      const missingKeyStore = createPrismaBrowserSessionStore(prisma, {
        currentCsrfKeyVersion: 2,
        csrfKeys: new Map([[2, randomBytes(32)]]),
        publicApplicationOrigin: 'https://app.example.test'
      });
      assert.deepEqual(await missingKeyStore.rotate({
        sessionToken: nextLogin.sessionToken,
        requestCorrelationId: 'csrf-key-missing'
      }), { status: 'denied' });

      assert.equal(await store.revoke({
        sessionToken: nextLogin.sessionToken,
        requestCorrelationId: 'revoke-one'
      }), 'revoked');
      assert.equal(await store.revoke({
        sessionToken: nextLogin.sessionToken,
        requestCorrelationId: 'revoke-one-again'
      }), 'already-revoked');
      assert.equal(await store.authenticate(nextLogin.sessionToken, 'revoked-session'), null);

      const beforeAll = await issue(await createHandoff());
      assert.ok(beforeAll);
      const accountBeforeAll = await prisma.humanAccount.findUniqueOrThrow({ where: { id: accountId } });
      const beforeAllStored = await prisma.browserSession.findUniqueOrThrow({ where: { id: beforeAll.identity.sessionId } });
      await prisma.browserSession.update({
        where: { id: beforeAll.identity.sessionId },
        data: { authenticatedAt: new Date(Date.now() - 11 * 60_000) }
      });
      assert.equal(await store.revokeAll({
        sessionToken: beforeAll.sessionToken,
        requestCorrelationId: 'revoke-all-stale-authentication'
      }), 'reauthentication-required');
      await prisma.browserSession.update({
        where: { id: beforeAll.identity.sessionId },
        data: { authenticatedAt: beforeAllStored.authenticatedAt }
      });
      const revokedAll = await store.revokeAll({ sessionToken: beforeAll.sessionToken, requestCorrelationId: 'revoke-all' });
      assert.equal(revokedAll, 'revoked');
      const accountAfterAll = await prisma.humanAccount.findUniqueOrThrow({ where: { id: accountId } });
      assert.equal(accountAfterAll.sessionVersion, accountBeforeAll.sessionVersion + 1);
      assert.equal(await store.authenticate(beforeAll.sessionToken, 'after-revoke-all'), null);

      const recentCount = await prisma.browserSession.count({
        where: { accountId, createdAt: { gt: new Date(Date.now() - 15 * 60_000) } }
      });
      for (let index = recentCount; index < 10; index += 1) {
        assert.ok(await issue(await createHandoff()));
      }
      assert.equal(await issue(await createHandoff()), null);
      assert.equal(await prisma.browserSession.count({
        where: { accountId, createdAt: { gt: new Date(Date.now() - 15 * 60_000) } }
      }), 10);

      const sessions = await prisma.browserSession.findMany({ where: { accountId } });
      const audits = await prisma.authenticationAuditEvent.findMany({ where: { accountId } });
      const persistence = JSON.stringify({ sessions, audits });
      for (const secret of [
        first.sessionToken,
        first.csrfToken,
        manager.sessionToken,
        resident.sessionToken,
        gatehouse.sessionToken,
        reauthenticated.sessionToken,
        nextLogin.sessionToken,
        nextLogin.csrfToken,
        beforeAll.sessionToken,
        beforeAll.csrfToken
      ]) {
        assert.equal(persistence.includes(secret), false);
      }
      assert.ok(audits.some((audit) => audit.eventType === 'session_issued'));
      assert.ok(audits.some((audit) => audit.eventType === 'session_rotated'));
      assert.ok(audits.some((audit) => audit.eventType === 'session_revoked'));
      assert.ok(audits.some((audit) => audit.outcome === 'denied'));
      assert.ok(audits.every((audit) => {
        const metadata = JSON.stringify(audit.metadata).toLowerCase();
        return !metadata.includes('token') && !metadata.includes('digest')
          && !metadata.includes('ciphertext') && !metadata.includes('csrf');
      }));
    } finally {
      await prisma.oidcValidatedHandoff.deleteMany({
        where: { accountId: { in: [accountId, otherAccountId] } }
      }).catch(() => undefined);
      await prisma.oidcLoginTransaction.deleteMany({ where: { id: { in: loginTransactionIds } } }).catch(() => undefined);
      await prisma.browserSession.deleteMany({ where: { accountId } }).catch(() => undefined);
      await prisma.browserSession.deleteMany({ where: { accountId: otherAccountId } }).catch(() => undefined);
      await prisma.humanMembership.deleteMany({ where: { accountId } }).catch(() => undefined);
      await prisma.humanMembership.deleteMany({ where: { accountId: otherAccountId } }).catch(() => undefined);
      await prisma.externalIdentity.deleteMany({ where: { accountId } }).catch(() => undefined);
      await prisma.externalIdentity.deleteMany({ where: { accountId: otherAccountId } }).catch(() => undefined);
      await prisma.humanAccount.deleteMany({ where: { id: accountId } }).catch(() => undefined);
      await prisma.humanAccount.deleteMany({ where: { id: otherAccountId } }).catch(() => undefined);
      await prisma.morador.deleteMany({ where: { id: residentId } }).catch(() => undefined);
      await prisma.condominio.deleteMany({ where: { id: { in: [condominioA, condominioB] } } }).catch(() => undefined);
      await prisma.$disconnect();
    }
  }
);
