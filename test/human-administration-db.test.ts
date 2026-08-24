import assert from 'node:assert/strict';
import { createHash, createHmac, randomBytes, randomUUID } from 'node:crypto';
import test from 'node:test';

import { PrismaClient } from '@prisma/client';

import { createHumanAdministrationService } from '../src/human-administration.js';
import { createPrismaOidcLoginStore } from '../src/oidc.js';
import { createPrismaBrowserSessionStore, generateSessionToken } from '../src/sessions.js';

const run = process.env.RUN_DATABASE_TESTS === 'true' && Boolean(process.env.DATABASE_URL);
const issuer = 'https://identity.example.test';
const policy = {
  provedor: { amr: ['webauthn'], acr: ['strong'] }, sindico: { amr: ['webauthn'], acr: ['strong'] },
  morador: { amr: ['webauthn', 'otp'], acr: [] }, portaria: { amr: ['webauthn'], acr: ['strong'] }
} as const;

test('PostgreSQL invitation binding is one-time, email-exact, concurrent, tenant-scoped, and secret-free', { skip: !run }, async () => {
  const prisma = new PrismaClient();
  const service = createHumanAdministrationService(prisma, {
    publicApplicationOrigin: 'https://app.example.test', recoveryUrl: `${issuer}/recovery`,
    recoveryWebhookIssuers: new Set([issuer]), recoveryWebhookSecret: randomBytes(32), mfaPolicy: policy
  });
  const oidc = createPrismaOidcLoginStore(prisma);
  const providerId = randomUUID();
  const condominiumId = randomUUID();
  const actor = { principalType: 'human', authMethod: 'oidc-session', id: providerId, accountId: providerId,
    sessionId: randomUUID(), role: 'provedor', condominioIds: null } as const;
  const transactionIds: string[] = [];
  try {
    await prisma.condominio.create({ data: { id: condominiumId, nome: 'PC27', responsavel: 'Owner', tipo: 'residencial', timezone: 'UTC' } });
    await prisma.humanAccount.create({ data: { id: providerId, displayName: 'Provider', status: 'active' } });
    const invitation = await service.createInvitation({ email: ' Invited@Example.Test ', displayName: 'Invited', role: 'sindico',
      condominioId: condominiumId, residentId: null, actor, requestCorrelationId: 'create-invitation' });
    assert.ok(invitation);
    assert.match(invitation.token, /^[A-Za-z0-9_-]{43}$/);
    assert.equal(Buffer.from(invitation.token, 'base64url').length, 32);
    const stored = await prisma.humanProvisioningInvitation.findUniqueOrThrow({ where: { id: invitation.id } });
    assert.deepEqual(Buffer.from(stored.tokenDigest), createHash('sha256').update(invitation.token).digest());
    assert.equal(JSON.stringify(stored).includes(invitation.token), false);
    assert.equal(stored.expectedEmail, 'invited@example.test');

    async function callback(email: string, digest = Buffer.from(stored.tokenDigest)) {
      const transactionId = randomUUID(); transactionIds.push(transactionId);
      await oidc.createTransaction({ id: transactionId, expiresAt: new Date(Date.now() + 60_000), stateDigest: randomBytes(32),
        nonceDigest: randomBytes(32), pkceVerifierCiphertext: randomBytes(43), pkceVerifierNonce: randomBytes(12),
        pkceVerifierAuthTag: randomBytes(16), pkceKeyVersion: 1, issuer, clientId: 'pc27',
        redirectUri: 'https://app.example.test/auth/callback', returnTo: '/', recoveryIntent: false,
        invitationTokenDigest: digest, audit: { eventType: 'oidc_login_started', outcome: 'success', requestCorrelationId: randomUUID() } });
      return oidc.completeIdentity({ loginTransactionId: transactionId, issuer, subject: 'invited-subject', email,
        emailVerified: true, authenticatedAt: new Date(), authenticationMethods: ['webauthn'], assuranceContext: 'strong',
        invitationTokenDigest: digest, handoffId: randomUUID(), handoffDigest: randomBytes(32),
        handoffExpiresAt: new Date(Date.now() + 60_000), audit: { eventType: 'oidc_callback_succeeded', outcome: 'success', requestCorrelationId: randomUUID() } });
    }
    assert.equal(await callback('other@example.test'), null);
    const expired = await service.createInvitation({ email: 'expired@example.test', displayName: 'Expired', role: 'portaria',
      condominioId: condominiumId, residentId: null, actor, requestCorrelationId: 'expired-invitation' });
    assert.ok(expired);
    await prisma.humanProvisioningInvitation.update({ where: { id: expired.id }, data: {
      createdAt: new Date(Date.now() - 25 * 60 * 60 * 1000), expiresAt: new Date(Date.now() - 60 * 60 * 1000)
    } });
    assert.equal(await callback('expired@example.test', createHash('sha256').update(expired.token).digest()), null);
    assert.equal((await prisma.humanProvisioningInvitation.findUniqueOrThrow({ where: { id: expired.id } })).consumedAt, null);
    const scopedManager = { ...actor, role: 'sindico', condominioIds: [condominiumId] } as const;
    assert.equal(await service.createInvitation({ email: 'cross@example.test', displayName: 'Cross', role: 'portaria',
      condominioId: randomUUID(), residentId: null, actor: scopedManager, requestCorrelationId: 'cross-tenant' }), null);
    const concurrent = await Promise.all([callback('INVITED@example.test'), callback('invited@example.test')]);
    assert.equal(concurrent.filter(Boolean).length, 1);
    assert.equal((await prisma.humanAccount.findUniqueOrThrow({ where: { id: invitation.accountId } })).status, 'active');
    assert.equal((await prisma.humanMembership.findUniqueOrThrow({ where: { id: invitation.membershipId } })).status, 'active');
    assert.equal(await prisma.externalIdentity.count({ where: { issuer, subject: 'invited-subject' } }), 1);
    assert.ok(await prisma.authenticationAuditEvent.count({ where: { eventType: { in: ['account_invitation_created', 'account_invitation_accepted', 'account_invitation_accept_failed'] } } }) >= 3);
  } finally {
    await prisma.oidcValidatedHandoff.deleteMany({ where: { loginTransactionId: { in: transactionIds } } });
    await prisma.oidcLoginTransaction.deleteMany({ where: { id: { in: transactionIds } } });
    await prisma.externalIdentity.deleteMany({ where: { issuer, subject: 'invited-subject' } });
    const invitedAccounts = await prisma.humanProvisioningInvitation.findMany({
      where: { createdByAccountId: providerId }, select: { accountId: true }
    });
    const invitedAccountIds = invitedAccounts.map(({ accountId }) => accountId);
    await prisma.humanProvisioningInvitation.deleteMany({ where: { createdByAccountId: providerId } });
    await prisma.humanMembership.deleteMany({ where: { accountId: { in: invitedAccountIds } } });
    await prisma.humanAccount.deleteMany({ where: { id: { in: invitedAccountIds } } });
    await prisma.humanAccount.deleteMany({ where: { id: providerId } });
    await prisma.condominio.deleteMany({ where: { id: condominiumId } });
    await prisma.$disconnect();
  }
});

test('signed recovery webhook validates issuer, timestamp, signature, and replay before global revocation', { skip: !run }, async () => {
  const prisma = new PrismaClient();
  const secret = randomBytes(32);
  const service = createHumanAdministrationService(prisma, {
    publicApplicationOrigin: 'https://app.example.test', recoveryUrl: `${issuer}/recovery`,
    recoveryWebhookIssuers: new Set([issuer]), recoveryWebhookSecret: secret, mfaPolicy: policy
  });
  const accountId = randomUUID();
  const membershipId = randomUUID();
  const externalIdentityId = randomUUID();
  const sessionId = randomUUID();
  const eventId = randomUUID();
  const subject = `recovery-${accountId}`;
  try {
    await prisma.humanAccount.create({ data: { id: accountId, displayName: 'Recovery', status: 'active' } });
    await prisma.externalIdentity.create({ data: { id: externalIdentityId, accountId, issuer, subject } });
    await prisma.humanMembership.create({ data: { id: membershipId, accountId, role: 'provedor', status: 'active' } });
    const now = new Date();
    await prisma.browserSession.create({ data: {
      id: sessionId, familyId: randomUUID(), createdAt: now, lastSeenAt: now,
      idleExpiresAt: new Date(now.getTime() + 60_000), absoluteExpiresAt: new Date(now.getTime() + 120_000),
      authenticatedAt: now, authenticationMethods: ['webauthn'],
      assuranceContext: 'strong', tokenDigest: randomBytes(32), csrfDigest: randomBytes(32), csrfCiphertext: randomBytes(32),
      csrfNonce: randomBytes(12), csrfAuthTag: randomBytes(16), csrfKeyVersion: 1, accountId,
      accountSessionVersion: 0, activeMembershipId: membershipId
    } });
    const timestamp = Math.floor(Date.now() / 1000);
    const signature = createHmac('sha256', secret).update(`${timestamp}.${eventId}.${issuer}.${subject}`).digest('hex');
    const request = { eventId, issuer, subject, timestamp, signature, requestCorrelationId: randomUUID() };
    assert.equal(await service.processRecoveryWebhook({ ...request, signature: '0'.repeat(64) }), false);
    assert.equal(await service.processRecoveryWebhook({ ...request, timestamp: timestamp - 301,
      signature: createHmac('sha256', secret).update(`${timestamp - 301}.${eventId}.${issuer}.${subject}`).digest('hex') }), false);
    assert.equal(await service.processRecoveryWebhook({ ...request, issuer: 'https://other.example.test',
      signature: createHmac('sha256', secret).update(`${timestamp}.${eventId}.https://other.example.test.${subject}`).digest('hex') }), false);
    assert.equal(await service.processRecoveryWebhook(request), true);
    assert.equal(await service.processRecoveryWebhook(request), true);
    assert.equal((await prisma.humanAccount.findUniqueOrThrow({ where: { id: accountId } })).sessionVersion, 1);
    assert.equal((await prisma.browserSession.findUniqueOrThrow({ where: { id: sessionId } })).revokeReason, 'provider_recovery_event');
    const event = await prisma.recoveryWebhookEvent.findUniqueOrThrow({ where: { eventId } });
    assert.equal(event.accountId, accountId);
    assert.equal(Buffer.from(event.eventDigest).length, 32);
    assert.equal(JSON.stringify(event).includes(signature), false);
  } finally {
    await prisma.recoveryWebhookEvent.deleteMany({ where: { eventId } });
    await prisma.browserSession.deleteMany({ where: { accountId } });
    await prisma.humanMembership.deleteMany({ where: { accountId } });
    await prisma.externalIdentity.deleteMany({ where: { accountId } });
    await prisma.humanAccount.deleteMany({ where: { id: accountId } });
    await prisma.$disconnect();
  }
});

test('MFA evidence fails closed and trusted reauthentication is required before a stronger role switch', { skip: !run }, async () => {
  const prisma = new PrismaClient();
  const store = createPrismaBrowserSessionStore(prisma, {
    currentCsrfKeyVersion: 1, csrfKeys: new Map([[1, randomBytes(32)]]),
    publicApplicationOrigin: 'https://app.example.test', mfaPolicy: policy
  });
  const accountId = randomUUID();
  const externalIdentityId = randomUUID();
  const condominiumId = randomUUID();
  const residentId = randomUUID();
  const residentMembershipId = randomUUID();
  const providerMembershipId = randomUUID();
  const transactionIds: string[] = [];
  async function handoff(amr: string[], acr: string | null, familyId?: string, recoveryIntent = false) {
    const transactionId = randomUUID(); transactionIds.push(transactionId);
    const token = generateSessionToken();
    await prisma.oidcLoginTransaction.create({ data: { id: transactionId, expiresAt: new Date(Date.now() + 60_000),
      stateDigest: randomBytes(32), nonceDigest: randomBytes(32), pkceVerifierCiphertext: randomBytes(43),
      pkceVerifierNonce: randomBytes(12), pkceVerifierAuthTag: randomBytes(16), pkceKeyVersion: 1,
      issuer, clientId: 'mfa', redirectUri: 'https://app.example.test/auth/callback', returnTo: '/',
      recoveryIntent, reauthenticationIntent: familyId !== undefined, reauthenticationFamilyId: familyId } });
    await prisma.oidcValidatedHandoff.create({ data: { id: randomUUID(), expiresAt: new Date(Date.now() + 60_000),
      handleDigest: createHash('sha256').update(token).digest(), loginTransactionId: transactionId,
      accountId, externalIdentityId, authenticatedAt: new Date(), authenticationMethods: amr,
      assuranceContext: acr, recoveryIntent, reauthenticationIntent: familyId !== undefined,
      reauthenticationFamilyId: familyId } });
    return token;
  }
  try {
    await prisma.condominio.create({ data: { id: condominiumId, nome: 'MFA', responsavel: 'Owner', tipo: 'residencial', timezone: 'UTC' } });
    await prisma.morador.create({ data: { id: residentId, nome: 'Resident', condominioId: condominiumId } });
    await prisma.humanAccount.create({ data: { id: accountId, displayName: 'MFA account', status: 'active' } });
    await prisma.externalIdentity.create({ data: { id: externalIdentityId, accountId, issuer, subject: `mfa-${accountId}` } });
    await prisma.humanMembership.create({ data: { id: residentMembershipId, accountId, role: 'morador',
      condominioId: condominiumId, residentId, status: 'active', createdAt: new Date(Date.now() - 1000) } });
    assert.equal(await store.issueFromHandoff({ handoffToken: await handoff([], null), requestCorrelationId: 'absent' }), null);
    assert.equal(await store.issueFromHandoff({ handoffToken: await handoff(['sms'], null), requestCorrelationId: 'weak' }), null);
    const residentSession = await store.issueFromHandoff({ handoffToken: await handoff(['otp'], null), requestCorrelationId: 'resident' });
    assert.ok(residentSession);
    await prisma.humanMembership.create({ data: { id: providerMembershipId, accountId, role: 'provedor', status: 'active' } });
    assert.deepEqual(await store.rotate({ sessionToken: residentSession.sessionToken,
      targetMembershipId: providerMembershipId, requestCorrelationId: 'elevation-denied' }), { status: 'denied' });
    const snapshot = await store.inspect({ sessionToken: residentSession.sessionToken, requestCorrelationId: 'snapshot' });
    assert.ok(snapshot);
    const reauthenticated = await store.issueFromHandoff({ handoffToken: await handoff(['webauthn'], 'strong', snapshot.familyId),
      oldSessionToken: residentSession.sessionToken, requestCorrelationId: 'reauthenticated' });
    assert.ok(reauthenticated);
    const elevated = await store.rotate({ sessionToken: reauthenticated.sessionToken,
      targetMembershipId: providerMembershipId, requestCorrelationId: 'elevated' });
    assert.equal(elevated.status, 'rotated');
    assert.equal(elevated.status === 'rotated' ? elevated.identity.role : null, 'provedor');
    if (elevated.status !== 'rotated') throw new Error('expected elevation');
    const elevatedSnapshot = await store.inspect({ sessionToken: elevated.sessionToken, requestCorrelationId: 'elevated-snapshot' });
    assert.ok(elevatedSnapshot);
    const recovered = await store.issueFromHandoff({ handoffToken: await handoff(['webauthn'], 'strong', undefined, true),
      oldSessionToken: elevated.sessionToken, requestCorrelationId: 'recovery' });
    assert.ok(recovered);
    const recoveredSnapshot = await store.inspect({ sessionToken: recovered.sessionToken, requestCorrelationId: 'recovered-snapshot' });
    assert.ok(recoveredSnapshot);
    assert.notEqual(recoveredSnapshot.familyId, elevatedSnapshot.familyId);
    assert.notEqual(recovered.csrfToken, elevated.csrfToken);
    assert.equal(await store.authenticate(elevated.sessionToken, 'old-family-revoked'), null);
    assert.equal((await prisma.humanAccount.findUniqueOrThrow({ where: { id: accountId } })).sessionVersion, 1);
  } finally {
    await prisma.browserSession.deleteMany({ where: { accountId } });
    await prisma.oidcValidatedHandoff.deleteMany({ where: { loginTransactionId: { in: transactionIds } } });
    await prisma.oidcLoginTransaction.deleteMany({ where: { id: { in: transactionIds } } });
    await prisma.humanMembership.deleteMany({ where: { accountId } });
    await prisma.externalIdentity.deleteMany({ where: { accountId } });
    await prisma.humanAccount.deleteMany({ where: { id: accountId } });
    await prisma.morador.deleteMany({ where: { id: residentId } });
    await prisma.condominio.deleteMany({ where: { id: condominiumId } });
    await prisma.$disconnect();
  }
});
