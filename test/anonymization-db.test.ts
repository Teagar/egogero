import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import test from 'node:test';

import { PrismaClient } from '@prisma/client';

import {
  ANONYMIZED_ENTRY_MESSAGE,
  ANONYMIZED_GUEST_NAME,
  anonymizeOldGuestData,
  runAnonymizationJob,
  subtractUtcMonths
} from '../src/jobs/anonymize-old-guests.js';
import { createInvitation, createPrismaInvitationStore } from '../src/convites.js';

const runDatabaseTests = process.env.RUN_DATABASE_TESTS === 'true';

test('PostgreSQL anonymization removes old PII without changing immutable audits', { skip: !runDatabaseTests }, async () => {
  const prisma = new PrismaClient();
  const now = new Date('2026-08-24T18:20:00.000Z');
  const cutoff = subtractUtcMonths(now, 12);
  const oldExpiration = subtractUtcMonths(now, 13);
  const recentExpiration = subtractUtcMonths(now, 11);
  const condominiumId = randomUUID();
  const residentId = randomUUID();
  const guestIds = {
    old: randomUUID(),
    oldActive: randomUUID(),
    recent: randomUUID(),
    mixed: randomUUID(),
    unknownExpiration: randomUUID(),
    withoutInvitation: randomUUID()
  };
  const oldInvitationId = randomUUID();
  const auditDeviceId = `anonymization-test-${randomUUID()}`;

  try {
    await prisma.condominio.create({
      data: { id: condominiumId, nome: 'Retention Test', responsavel: 'Owner', tipo: 'residencial', timezone: 'America/Sao_Paulo' }
    });
    await prisma.morador.create({ data: { id: residentId, nome: 'Resident', condominioId: condominiumId } });
    await prisma.convidado.createMany({
      data: Object.entries(guestIds).map(([label, id]) => ({
        id,
        nome: `Guest ${label}`,
        email: `${label}@example.test`,
        telefone: '+5511999999999',
        createdAt: label === 'withoutInvitation' ? oldExpiration : now,
        condominioId: condominiumId,
        moradorId: residentId,
        deletedAt: label === 'old' ? new Date('2025-07-01T00:00:00.000Z') : null
      }))
    });
    await prisma.convite.createMany({
      data: [
        { id: oldInvitationId, condominioId: condominiumId, moradorId: residentId, convidadoId: guestIds.old, tipo: 'visitante', expiresAt: oldExpiration },
        { id: randomUUID(), condominioId: condominiumId, moradorId: residentId, convidadoId: guestIds.oldActive, tipo: 'visitante', expiresAt: oldExpiration },
        { id: randomUUID(), condominioId: condominiumId, moradorId: residentId, convidadoId: guestIds.recent, tipo: 'visitante', expiresAt: recentExpiration },
        { id: randomUUID(), condominioId: condominiumId, moradorId: residentId, convidadoId: guestIds.mixed, tipo: 'visitante', expiresAt: oldExpiration },
        { id: randomUUID(), condominioId: condominiumId, moradorId: residentId, convidadoId: guestIds.mixed, tipo: 'visitante', expiresAt: recentExpiration },
        { id: randomUUID(), condominioId: condominiumId, moradorId: residentId, convidadoId: guestIds.unknownExpiration, tipo: 'visitante', expiresAt: null }
      ]
    });
    await prisma.notificacao.create({
      data: {
        tipo: 'entrada_visitante',
        mensagem: 'Guest old entrou no condomínio',
        nomeConvidado: 'Guest old',
        entrouEm: oldExpiration,
        condominioId: condominiumId,
        moradorId: residentId,
        convidadoId: guestIds.old,
        conviteId: oldInvitationId
      }
    });
    await prisma.auditoriaAcesso.create({
      data: {
        condominioId: condominiumId,
        dispositivoId: auditDeviceId,
        conviteId: oldInvitationId,
        moradorId: residentId,
        convidadoId: guestIds.old,
        tipoAcesso: 'pedestre',
        resultado: 'permitido'
      }
    });
    const auditsBefore = await prisma.auditoriaAcesso.findMany({ where: { dispositivoId: auditDeviceId } });

    await prisma.$executeRawUnsafe(`
      CREATE FUNCTION delay_anonymization_for_test() RETURNS trigger
      LANGUAGE plpgsql AS $$
      BEGIN
        IF OLD."anonymizedAt" IS NULL AND NEW."anonymizedAt" IS NOT NULL THEN
          PERFORM pg_sleep(0.25);
        END IF;
        RETURN NEW;
      END;
      $$
    `);
    await prisma.$executeRawUnsafe(`
      CREATE TRIGGER delay_anonymization_for_test
      BEFORE UPDATE ON "Convidado"
      FOR EACH ROW EXECUTE FUNCTION delay_anonymization_for_test()
    `);
    const anonymization = anonymizeOldGuestData(prisma, { cutoff, batchSize: 10, anonymizedAt: now });
    await new Promise((resolve) => setTimeout(resolve, 100));
    const invitationStore = createPrismaInvitationStore(prisma, 'database-e2e-invitation-secret-32-bytes-minimum');
    const concurrentIssuance = createInvitation(invitationStore, {
      condominioId: condominiumId,
      moradorId: residentId,
      convidadoId: guestIds.oldActive,
      tipo: 'visitante',
      expiresAt: new Date(now.getTime() + 60 * 60 * 1000)
    }, { generateToken: () => '919191', now: () => now });
    assert.deepEqual(await anonymization, { count: 3 });
    assert.equal(await concurrentIssuance, null, 'issuance waiting on anonymization cannot reactivate the guest');
    await prisma.$executeRawUnsafe('DROP TRIGGER delay_anonymization_for_test ON "Convidado"');
    await prisma.$executeRawUnsafe('DROP FUNCTION delay_anonymization_for_test()');

    const oldGuest = await prisma.convidado.findUniqueOrThrow({ where: { id: guestIds.old } });
    assert.equal(oldGuest.nome, ANONYMIZED_GUEST_NAME);
    assert.equal(oldGuest.email, null);
    assert.equal(oldGuest.telefone, null);
    assert.equal(oldGuest.anonymizedAt?.toISOString(), now.toISOString());
    assert.ok(oldGuest.deletedAt, 'soft-deleted records remain subject to retention');

    const oldActiveGuest = await prisma.convidado.findUniqueOrThrow({ where: { id: guestIds.oldActive } });
    assert.equal(oldActiveGuest.anonymizedAt?.toISOString(), now.toISOString());

    assert.equal(await createInvitation(invitationStore, {
      condominioId: condominiumId,
      moradorId: residentId,
      convidadoId: guestIds.oldActive,
      tipo: 'visitante',
      expiresAt: new Date(now.getTime() + 60 * 60 * 1000)
    }, { generateToken: () => '919191', now: () => now }), null, 'anonymized guests cannot receive new invitations');

    const oldNotification = await prisma.notificacao.findUniqueOrThrow({ where: { conviteId: oldInvitationId } });
    assert.equal(oldNotification.nomeConvidado, ANONYMIZED_GUEST_NAME);
    assert.equal(oldNotification.mensagem, ANONYMIZED_ENTRY_MESSAGE);

    const unusedGuest = await prisma.convidado.findUniqueOrThrow({ where: { id: guestIds.withoutInvitation } });
    assert.equal(unusedGuest.anonymizedAt?.toISOString(), now.toISOString());

    for (const id of [guestIds.recent, guestIds.mixed, guestIds.unknownExpiration]) {
      const guest = await prisma.convidado.findUniqueOrThrow({ where: { id } });
      assert.equal(guest.anonymizedAt, null);
      assert.ok(guest.email, `${id} must retain PII`);
    }

    assert.deepEqual(await prisma.auditoriaAcesso.findMany({ where: { dispositivoId: auditDeviceId } }), auditsBefore);
    assert.deepEqual(
      await anonymizeOldGuestData(prisma, { cutoff, batchSize: 10, anonymizedAt: now }),
      { count: 0 },
      'rerunning the same retention window is idempotent'
    );
  } finally {
    await prisma.$executeRawUnsafe('DROP TRIGGER IF EXISTS delay_anonymization_for_test ON "Convidado"');
    await prisma.$executeRawUnsafe('DROP FUNCTION IF EXISTS delay_anonymization_for_test()');
    await prisma.$disconnect();
  }
});

test('job fails for locked eligible rows so the scheduler retries them', { skip: !runDatabaseTests }, async () => {
  const prisma = new PrismaClient();
  const now = new Date('2026-08-24T18:20:00.000Z');
  const condominiumId = randomUUID();
  const residentId = randomUUID();
  const guestId = randomUUID();
  let releaseLock!: () => void;
  let reportLocked!: () => void;
  const release = new Promise<void>((resolve) => { releaseLock = resolve; });
  const locked = new Promise<void>((resolve) => { reportLocked = resolve; });

  try {
    await prisma.condominio.create({ data: { id: condominiumId, nome: 'Lock Test', responsavel: 'Owner', tipo: 'residencial', timezone: 'America/Sao_Paulo' } });
    await prisma.morador.create({ data: { id: residentId, nome: 'Resident', condominioId: condominiumId } });
    await prisma.convidado.create({ data: { id: guestId, nome: 'Locked PII', email: 'locked@example.test', condominioId: condominiumId, moradorId: residentId } });
    await prisma.convite.create({ data: { condominioId: condominiumId, moradorId: residentId, convidadoId: guestId, tipo: 'visitante', expiresAt: subtractUtcMonths(now, 13) } });

    const lockTransaction = prisma.$transaction(async (transaction) => {
      await transaction.$queryRaw`SELECT id FROM "Convidado" WHERE id = ${guestId} FOR UPDATE`;
      reportLocked();
      await release;
    });
    await locked;
    await assert.rejects(
      runAnonymizationJob({ ANONYMIZATION_RETENTION_MONTHS: '12', ANONYMIZATION_BATCH_SIZE: '10' }, now, prisma),
      /left 1 eligible guests locked/
    );
    releaseLock();
    await lockTransaction;
    assert.equal((await runAnonymizationJob({ ANONYMIZATION_RETENTION_MONTHS: '12', ANONYMIZATION_BATCH_SIZE: '10' }, now, prisma)).count, 1);
  } finally {
    releaseLock?.();
    await prisma.$disconnect();
  }
});
