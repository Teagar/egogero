import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import test from 'node:test';

import { PrismaClient } from '@prisma/client';
import pg from 'pg';

import { createPrismaInvitationStore } from '../src/convites.js';

const databaseUrl = process.env.DATABASE_URL;
const enabled = process.env.RUN_DATABASE_TESTS === 'true' && Boolean(databaseUrl);
const secret = 'database-e2e-invitation-secret-32-bytes-minimum';

test('concurrent membership or account disable wins before human validation can consume an invitation', { skip: !enabled }, async () => {
  const prisma = new PrismaClient();
  const locker = new pg.Client({ connectionString: databaseUrl });
  const store = createPrismaInvitationStore(prisma, secret);
  const condominiumId = randomUUID();
  const residentId = randomUUID();
  const guestId = randomUUID();
  const secondGuestId = randomUUID();
  const accountId = randomUUID();
  const secondAccountId = randomUUID();
  const membershipId = randomUUID();
  const secondMembershipId = randomUUID();
  await locker.connect();
  try {
    await prisma.condominio.create({ data: {
      id: condominiumId, nome: 'Human gatehouse race', responsavel: 'Test', tipo: 'residencial', timezone: 'UTC'
    } });
    await prisma.morador.create({ data: { id: residentId, nome: 'Resident', condominioId: condominiumId } });
    await prisma.convidado.createMany({ data: [
      { id: guestId, nome: 'Guest one', condominioId: condominiumId, moradorId: residentId },
      { id: secondGuestId, nome: 'Guest two', condominioId: condominiumId, moradorId: residentId }
    ] });
    await prisma.humanAccount.createMany({ data: [
      { id: accountId, displayName: 'Operator one', status: 'active' },
      { id: secondAccountId, displayName: 'Operator two', status: 'active' }
    ] });
    await prisma.humanMembership.createMany({ data: [
      { id: membershipId, accountId, condominioId: condominiumId, role: 'portaria', status: 'active' },
      { id: secondMembershipId, accountId: secondAccountId, condominioId: condominiumId, role: 'portaria', status: 'active' }
    ] });
    const first = await store.createActive({
      token: '314159', now: new Date(), condominioId: condominiumId, moradorId: residentId,
      convidadoId: guestId, tipo: 'visitante', expiresAt: new Date(Date.now() + 60_000)
    });
    const second = await store.createActive({
      token: '271828', now: new Date(), condominioId: condominiumId, moradorId: residentId,
      convidadoId: secondGuestId, tipo: 'visitante', expiresAt: new Date(Date.now() + 60_000)
    });
    assert.ok(first && second);

    await locker.query('BEGIN');
    await locker.query(`UPDATE "HumanMembership" SET status = 'disabled', "disabledAt" = clock_timestamp() WHERE id = $1`, [membershipId]);
    const membershipValidation = store.validateHumanActive!({
      token: '314159', condominiumId, accountId, membershipId, accessType: 'pedestre'
    }, new Date());
    assert.equal(await Promise.race([membershipValidation.then(() => 'finished'),
      new Promise((resolve) => setTimeout(() => resolve('blocked'), 50))]), 'blocked');
    await locker.query('COMMIT');
    assert.deepEqual(await membershipValidation, { allowed: false, reason: 'invalid_or_unavailable' });
    assert.equal((await prisma.convite.findUniqueOrThrow({ where: { id: first.id } })).usedAt, null);

    await locker.query('BEGIN');
    await locker.query(`UPDATE "HumanAccount" SET status = 'disabled', "disabledAt" = clock_timestamp(),
      "sessionVersion" = "sessionVersion" + 1 WHERE id = $1`, [secondAccountId]);
    const accountValidation = store.validateHumanActive!({
      token: '271828', condominiumId, accountId: secondAccountId,
      membershipId: secondMembershipId, accessType: 'pedestre'
    }, new Date());
    assert.equal(await Promise.race([accountValidation.then(() => 'finished'),
      new Promise((resolve) => setTimeout(() => resolve('blocked'), 50))]), 'blocked');
    await locker.query('COMMIT');
    assert.deepEqual(await accountValidation, { allowed: false, reason: 'invalid_or_unavailable' });
    assert.equal((await prisma.convite.findUniqueOrThrow({ where: { id: second.id } })).usedAt, null);
  } finally {
    await locker.query('ROLLBACK').catch(() => undefined);
    await locker.end();
    await prisma.convite.deleteMany({ where: { condominioId: condominiumId } }).catch(() => undefined);
    await prisma.convidado.deleteMany({ where: { condominioId: condominiumId } }).catch(() => undefined);
    await prisma.humanMembership.deleteMany({ where: { accountId: { in: [accountId, secondAccountId] } } }).catch(() => undefined);
    await prisma.humanAccount.deleteMany({ where: { id: { in: [accountId, secondAccountId] } } }).catch(() => undefined);
    await prisma.morador.deleteMany({ where: { id: residentId } }).catch(() => undefined);
    await prisma.condominio.deleteMany({ where: { id: condominiumId } }).catch(() => undefined);
    await prisma.$disconnect();
  }
});
