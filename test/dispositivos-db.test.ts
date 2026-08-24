import assert from 'node:assert/strict';
import { createHmac, randomUUID } from 'node:crypto';
import test from 'node:test';

import { PrismaClient } from '@prisma/client';

import {
  createPrismaDeviceRateLimiter,
  createPrismaDeviceStore,
  DeviceSecretMismatchError
} from '../src/dispositivos.js';
import { createInvitation, createPrismaInvitationStore } from '../src/convites.js';

const runDatabaseTests = process.env.RUN_DATABASE_TESTS === 'true';
const secret = 'database-e2e-device-api-key-secret-32-bytes-minimum';

test('PostgreSQL device credentials are tenant-scoped, revocable, and never stored in plaintext', { skip: !runDatabaseTests }, async () => {
  const prisma = new PrismaClient();
  const store = createPrismaDeviceStore(prisma, secret);
  const condominiumId = randomUUID();
  const otherCondominiumId = randomUUID();
  const residentId = randomUUID();
  const guestId = randomUUID();

  try {
    await prisma.securityKey.deleteMany({ where: { name: 'device-api-key' } });
    await prisma.condominio.createMany({
      data: [
        { id: condominiumId, nome: 'Principal', responsavel: 'Owner', tipo: 'residencial' },
        { id: otherCondominiumId, nome: 'Other', responsavel: 'Owner', tipo: 'residencial' }
      ]
    });
    await prisma.morador.create({ data: { id: residentId, nome: 'Resident', condominioId: condominiumId } });
    await prisma.convidado.create({ data: { id: guestId, nome: 'Guest', condominioId: condominiumId, moradorId: residentId } });

    const created = await store.create({ condominiumId, name: 'Tablet portaria' });
    assert.ok(created);
    assert.match(created.apiKey, /^egdev_[A-Za-z0-9_-]{43}$/);
    const persisted = await prisma.dispositivo.findUniqueOrThrow({ where: { id: created.device.id } });
    assert.equal(
      persisted.apiKeyDigest?.trim(),
      createHmac('sha256', secret).update('device-api-key\0').update(created.apiKey).digest('hex')
    );
    assert.equal(JSON.stringify(persisted).includes(created.apiKey), false);

    assert.deepEqual(await store.authenticate(created.apiKey, new Date()), {
      id: created.device.id,
      condominiumId
    });
    assert.equal(await store.authenticate(`egdev_${'z'.repeat(43)}`, new Date()), null);
    assert.equal((await store.list({ condominiumId })).length, 1);
    assert.equal((await store.list({ condominiumId: otherCondominiumId })).length, 0);

    const mismatchedStore = createPrismaDeviceStore(
      prisma,
      'different-database-device-key-secret-32-bytes-minimum'
    );
    await assert.rejects(
      mismatchedStore.authenticate(created.apiKey, new Date()),
      DeviceSecretMismatchError
    );

    assert.equal(await store.revoke({ id: created.device.id, condominiumId: otherCondominiumId }), 'unavailable');
    assert.ok(await store.authenticate(created.apiKey, new Date()));

    const invitationStore = createPrismaInvitationStore(
      prisma,
      'database-e2e-invitation-secret-32-bytes-minimum'
    );
    const invitation = await createInvitation(invitationStore, {
      condominioId: condominiumId,
      moradorId: residentId,
      convidadoId: guestId,
      tipo: 'visitante',
      expiresAt: new Date(Date.now() + 60_000)
    }, { generateToken: () => '123456' });
    assert.ok(invitation);

    const authenticatedBeforeRevocation = await store.authenticate(created.apiKey, new Date());
    assert.ok(authenticatedBeforeRevocation);
    let releaseValidation!: () => void;
    const validationGate = new Promise<void>((resolve) => { releaseValidation = resolve; });
    const pendingValidation = (async () => {
      await validationGate;
      return invitationStore.validateActive({
        token: invitation.token,
        condominiumId,
        deviceId: authenticatedBeforeRevocation.id,
        accessType: 'pedestre',
        requireActiveDevice: true
      }, new Date());
    })();
    assert.equal(await store.revoke({ id: created.device.id, condominiumId }), 'revoked');
    releaseValidation();
    assert.deepEqual(await pendingValidation, { allowed: false, reason: 'invalid_or_unavailable' });
    assert.equal((await prisma.convite.findUniqueOrThrow({ where: { id: invitation.convite.id } })).usedAt, null);

    assert.equal(await store.revoke({ id: created.device.id, condominiumId }), 'already-revoked');
    assert.equal(await store.authenticate(created.apiKey, new Date()), null);
    const revoked = await prisma.dispositivo.findUniqueOrThrow({ where: { id: created.device.id } });
    assert.equal(revoked.apiKeyDigest, null);
    assert.equal(revoked.status, 'revogado');
  } finally {
    await prisma.notificacao.deleteMany({ where: { condominioId: { in: [condominiumId, otherCondominiumId] } } });
    await prisma.convite.deleteMany({ where: { condominioId: { in: [condominiumId, otherCondominiumId] } } });
    await prisma.convidado.deleteMany({ where: { condominioId: { in: [condominiumId, otherCondominiumId] } } });
    await prisma.morador.deleteMany({ where: { condominioId: { in: [condominiumId, otherCondominiumId] } } });
    await prisma.dispositivo.deleteMany({ where: { condominioId: { in: [condominiumId, otherCondominiumId] } } });
    await prisma.condominio.deleteMany({ where: { id: { in: [condominiumId, otherCondominiumId] } } });
    await prisma.securityKey.deleteMany({ where: { name: 'device-api-key' } });
    await prisma.$disconnect();
  }
});

test('PostgreSQL rate limiter serializes concurrent replicas at exactly 20 attempts', { skip: !runDatabaseTests }, async () => {
  const prisma = new PrismaClient();
  const store = createPrismaDeviceStore(prisma, secret);
  const limiter = createPrismaDeviceRateLimiter(prisma);
  const condominiumId = randomUUID();

  try {
    await prisma.securityKey.deleteMany({ where: { name: 'device-api-key' } });
    await prisma.condominio.create({
      data: { id: condominiumId, nome: 'Concurrent', responsavel: 'Owner', tipo: 'residencial' }
    });
    const created = await store.create({ condominiumId, name: 'Concurrent tablet' });
    assert.ok(created);
    const now = new Date();
    const decisions = await Promise.all(
      Array.from({ length: 30 }, () => limiter.consume(created.device.id, now))
    );
    assert.equal(decisions.filter((decision) => decision.allowed).length, 20);
    assert.equal(decisions.filter((decision) => !decision.allowed).length, 10);
    const state = await prisma.dispositivoRateLimit.findUniqueOrThrow({
      where: { dispositivoId: created.device.id }
    });
    assert.equal(state.attempts.length, 20);
    assert.ok(state.blockedUntil && state.blockedUntil > now);
  } finally {
    await prisma.dispositivo.deleteMany({ where: { condominioId: condominiumId } });
    await prisma.condominio.deleteMany({ where: { id: condominiumId } });
    await prisma.securityKey.deleteMany({ where: { name: 'device-api-key' } });
    await prisma.$disconnect();
  }
});
