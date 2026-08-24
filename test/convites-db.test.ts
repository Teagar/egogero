import assert from 'node:assert/strict';
import { createHmac } from 'node:crypto';
import test from 'node:test';

import { PrismaClient } from '@prisma/client';

import { createApp } from '../src/app.js';
import { createDevelopmentHeaderAuthenticator } from '../src/auth.js';
import {
  DailyInvitationLimitError,
  consumeInvitationToken,
  createInvitation,
  createInvitations,
  createPrismaInvitationStore
} from '../src/convites.js';

const runDatabaseTests = process.env.RUN_DATABASE_TESTS === 'true';
const secret = 'database-e2e-invitation-secret-32-bytes-minimum';
const uuid = (n: number) => `10000000-0000-4000-8000-${String(n).padStart(12, '0')}`;

test('PostgreSQL invitation creation is secure, atomic, scoped, and one-use', { skip: !runDatabaseTests }, async () => {
  const prisma = new PrismaClient();
  const store = createPrismaInvitationStore(prisma, secret);
  const condominioId = uuid(1);
  const otherCondominioId = uuid(2);
  const moradorId = uuid(101);
  const otherMoradorId = uuid(102);
  const guestIds = [uuid(201), uuid(202), uuid(203), uuid(204), uuid(205), uuid(206), uuid(207)];
  const expiresAt = new Date(Date.now() + 60 * 60 * 1000);

  try {
    await prisma.convite.deleteMany();
    await prisma.convidado.deleteMany();
    await prisma.morador.deleteMany();
    await prisma.condominio.deleteMany();
    await prisma.securityKey.deleteMany();

    await prisma.condominio.createMany({
      data: [
        { id: condominioId, nome: 'Principal', responsavel: 'Owner', tipo: 'residencial' },
        { id: otherCondominioId, nome: 'Other', responsavel: 'Other', tipo: 'residencial' }
      ]
    });
    await prisma.morador.createMany({
      data: [
        { id: moradorId, nome: 'Resident', condominioId },
        { id: otherMoradorId, nome: 'Other resident', condominioId: otherCondominioId }
      ]
    });
    await prisma.convidado.createMany({
      data: [
        ...guestIds.map((id) => ({ id, nome: id, condominioId, moradorId })),
        { id: uuid(299), nome: 'Other guest', condominioId: otherCondominioId, moradorId: otherMoradorId }
      ]
    });

    const app = createApp({
      authenticator: createDevelopmentHeaderAuthenticator(true),
      invitationTokenSecret: secret
    });
    const headers = {
      'x-development-user-id': moradorId,
      'x-development-user-role': 'morador',
      'x-development-condominio-id': condominioId
    };
    const singleResponse = await app.inject({
      method: 'POST',
      url: `/condominios/${condominioId}/moradores/${moradorId}/convidados/${guestIds[0]}/convites`,
      headers,
      payload: { tipo: 'prestador', expiresAt: expiresAt.toISOString() }
    });
    assert.equal(singleResponse.statusCode, 201);
    assert.equal(singleResponse.headers['cache-control'], 'no-store');
    const single = singleResponse.json() as { id: string; token: string };
    const persistedSingle = await prisma.convite.findUniqueOrThrow({ where: { id: single.id } });
    assert.notEqual(persistedSingle.tokenDigest?.trim(), single.token);
    assert.equal(
      persistedSingle.tokenDigest?.trim(),
      createHmac('sha256', secret).update(single.token).digest('hex')
    );

    const batchResponse = await app.inject({
      method: 'POST',
      url: `/condominios/${condominioId}/moradores/${moradorId}/convites/multiplos`,
      headers,
      payload: { convidadoIds: [guestIds[1], guestIds[2]] }
    });
    assert.equal(batchResponse.statusCode, 201);
    assert.equal(batchResponse.headers['cache-control'], 'no-store');
    const batch = batchResponse.json() as { convites: Array<{ id: string; token: string }> };
    assert.equal(batch.convites.length, 2);
    const persistedBatch = await prisma.convite.findMany({
      where: { id: { in: batch.convites.map((convite) => convite.id) } }
    });
    assert.equal(persistedBatch.length, 2);
    assert.ok(persistedBatch.every((convite) => !batch.convites.some((item) => item.token === convite.tokenDigest?.trim())));

    const forbidden = await app.inject({
      method: 'POST',
      url: `/condominios/${otherCondominioId}/moradores/${otherMoradorId}/convites/multiplos`,
      headers,
      payload: { convidadoIds: [uuid(299)] }
    });
    assert.equal(forbidden.statusCode, 403);

    const beforeInvalidGuestBatch = await prisma.convite.count();
    const invalidGuestBatch = await createInvitations(store, [
      { condominioId, moradorId, convidadoId: guestIds[3], tipo: 'visitante', expiresAt },
      { condominioId, moradorId, convidadoId: uuid(299), tipo: 'visitante', expiresAt }
    ]);
    assert.equal(invalidGuestBatch, null);
    assert.equal(
      await prisma.convite.count(),
      beforeInvalidGuestBatch,
      'an invalid guest must prevent every insert in the transaction'
    );

    const occupied = await createInvitation(
      store,
      { condominioId, moradorId, convidadoId: guestIds[3], tipo: 'visitante', expiresAt },
      { generateToken: () => '111111' }
    );
    assert.ok(occupied);
    const beforeRollback = await prisma.convite.count();
    const failedCandidates = ['222222', '111111'];
    await assert.rejects(
      createInvitations(
        store,
        [
          { condominioId, moradorId, convidadoId: guestIds[4], tipo: 'visitante', expiresAt },
          { condominioId, moradorId, convidadoId: guestIds[5], tipo: 'visitante', expiresAt }
        ],
        { generateToken: () => failedCandidates.shift()!, maxAttempts: 1 }
      ),
      /Could not allocate/
    );
    assert.equal(await prisma.convite.count(), beforeRollback, 'late collision must roll back earlier inserts');

    const retryCandidates = ['222222', '111111', '333333', '444444'];
    const retried = await createInvitations(
      store,
      [
        { condominioId, moradorId, convidadoId: guestIds[4], tipo: 'visitante', expiresAt },
        { condominioId, moradorId, convidadoId: guestIds[5], tipo: 'visitante', expiresAt }
      ],
      { generateToken: () => retryCandidates.shift()! }
    );
    assert.deepEqual(retried?.map((result) => result.token), ['333333', '444444']);

    assert.equal(await consumeInvitationToken(store, single.token), true);
    assert.equal(await consumeInvitationToken(store, single.token), false);
    const consumed = await prisma.convite.findUniqueOrThrow({ where: { id: single.id } });
    assert.equal(consumed.tokenDigest, null);
    assert.ok(consumed.usedAt);

    const revoked = await app.inject({
      method: 'DELETE',
      url: `/condominios/${condominioId}/moradores/${moradorId}/convites/${batch.convites[0]!.id}`,
      headers
    });
    assert.equal(revoked.statusCode, 204);
    assert.equal(
      (await app.inject({
        method: 'DELETE',
        url: `/condominios/${condominioId}/moradores/${moradorId}/convites/${batch.convites[0]!.id}`,
        headers
      })).statusCode,
      204,
      'repeating a successful revocation is idempotent'
    );
    assert.equal(await consumeInvitationToken(store, batch.convites[0]!.token), false, 'revocation denies consumption immediately');
    const revokedRecord = await prisma.convite.findUniqueOrThrow({ where: { id: batch.convites[0]!.id } });
    assert.equal(revokedRecord.tokenDigest, null);
    assert.equal(revokedRecord.usedAt, null);
    assert.ok(revokedRecord.revokedAt);

    const race = await createInvitation(
      store,
      { condominioId, moradorId, convidadoId: guestIds[6]!, tipo: 'visitante', expiresAt }
    );
    assert.ok(race);
    const [raceConsumed, raceRevoked] = await Promise.all([
      consumeInvitationToken(store, race.token),
      store.revokeActive({ id: race.convite.id, condominioId, moradorId }, new Date())
    ]);
    assert.equal(Number(raceConsumed) + Number(raceRevoked === 'revoked'), 1, 'consume and revoke cannot both win');
    const racedRecord = await prisma.convite.findUniqueOrThrow({ where: { id: race.convite.id } });
    assert.equal(Boolean(racedRecord.usedAt) && Boolean(racedRecord.revokedAt), false);

    assert.equal(
      (await app.inject({
        method: 'DELETE',
        url: `/condominios/${otherCondominioId}/moradores/${otherMoradorId}/convites/${batch.convites[1]!.id}`,
        headers
      })).statusCode,
      403,
      'cross-tenant revocation is denied before reaching the store'
    );

    await prisma.morador.update({ where: { id: moradorId }, data: { deletedAt: new Date() } });
    assert.equal(
      (await app.inject({
        method: 'DELETE',
        url: `/condominios/${condominioId}/moradores/${moradorId}/convites/${race.convite.id}`,
        headers
      })).statusCode,
      404,
      'an inactive resident prevents revocation'
    );
    await prisma.morador.update({ where: { id: moradorId }, data: { deletedAt: null } });
    await prisma.condominio.update({ where: { id: condominioId }, data: { deletedAt: new Date() } });
    assert.equal(
      (await app.inject({
        method: 'DELETE',
        url: `/condominios/${condominioId}/moradores/${moradorId}/convites/${race.convite.id}`,
        headers
      })).statusCode,
      404,
      'an inactive condominium prevents revocation'
    );
    await prisma.condominio.update({ where: { id: condominioId }, data: { deletedAt: null } });

    await prisma.convidado.update({ where: { id: guestIds[1] }, data: { deletedAt: new Date() } });
    assert.equal(await consumeInvitationToken(store, batch.convites[0]!.token), false);
    await app.close();
  } finally {
    await prisma.$disconnect();
  }
});

test('PostgreSQL daily limits use resident precedence, UTC days, and serialized batch issuance', { skip: !runDatabaseTests }, async () => {
  const prisma = new PrismaClient();
  const store = createPrismaInvitationStore(prisma, secret);
  const condominioId = uuid(10);
  const moradorId = uuid(110);
  const guestIds = Array.from({ length: 16 }, (_, index) => uuid(300 + index));
  const expiresAt = new Date(Date.now() + 60 * 60 * 1000);
  const invitation = (convidadoId: string) => ({ condominioId, moradorId, convidadoId, tipo: 'visitante' as const, expiresAt });

  try {
    await prisma.convite.deleteMany();
    await prisma.convidado.deleteMany();
    await prisma.morador.deleteMany();
    await prisma.condominio.deleteMany();
    await prisma.securityKey.deleteMany();
    await prisma.condominio.create({ data: { id: condominioId, nome: 'Principal', responsavel: 'Owner', tipo: 'residencial', dailyInvitationLimit: 10 } });
    await prisma.morador.create({ data: { id: moradorId, nome: 'Resident', condominioId } });
    await prisma.convidado.createMany({ data: guestIds.map((id) => ({ id, nome: id, condominioId, moradorId })) });

    for (const guestId of guestIds.slice(0, 10)) {
      assert.ok(await createInvitation(store, invitation(guestId)));
    }
    await assert.rejects(createInvitation(store, invitation(guestIds[10]!)), DailyInvitationLimitError);
    assert.equal(await prisma.convite.count(), 10, 'the eleventh invitation is not persisted');

    await prisma.convite.deleteMany();
    for (const guestId of guestIds.slice(0, 9)) {
      assert.ok(await createInvitation(store, invitation(guestId)));
    }
    await assert.rejects(
      createInvitations(store, [invitation(guestIds[9]!), invitation(guestIds[10]!)]),
      DailyInvitationLimitError
    );
    assert.equal(await prisma.convite.count(), 9, 'a batch over the remaining allowance rolls back entirely');

    await prisma.convite.deleteMany();
    const yesterday = new Date(Date.now() - 24 * 60 * 60 * 1000);
    await prisma.convite.create({ data: { ...invitation(guestIds[0]!), createdAt: yesterday, tokenDigest: createHmac('sha256', secret).update('999999').digest('hex') } });
    for (const guestId of guestIds.slice(1, 11)) {
      assert.ok(await createInvitation(store, invitation(guestId)));
    }
    assert.equal(await prisma.convite.count(), 11, 'an invitation before the UTC day boundary does not consume today allowance');

    await prisma.convite.deleteMany();
    await prisma.morador.update({ where: { id: moradorId }, data: { dailyInvitationLimit: 1 } });
    const simultaneous = await Promise.allSettled([
      createInvitation(store, invitation(guestIds[0]!)),
      createInvitation(store, invitation(guestIds[1]!))
    ]);
    assert.equal(simultaneous.filter((result) => result.status === 'fulfilled').length, 1);
    assert.equal(simultaneous.filter((result) => result.status === 'rejected').length, 1);
    assert.equal(await prisma.convite.count(), 1, 'concurrent issuance cannot exceed the resident limit');

    await prisma.convite.deleteMany();
    const used = await createInvitation(store, invitation(guestIds[0]!));
    assert.ok(used);
    assert.equal(await consumeInvitationToken(store, used.token), true);
    await assert.rejects(createInvitation(store, invitation(guestIds[1]!)), DailyInvitationLimitError);
    await prisma.convite.update({ where: { id: used.convite.id }, data: { deletedAt: new Date() } });
    const revocable = await createInvitation(store, invitation(guestIds[1]!));
    assert.ok(revocable, 'soft-deleted invitations no longer count');
    assert.equal(
      await store.revokeActive({ id: revocable.convite.id, condominioId, moradorId }, new Date()),
      'revoked'
    );
    await assert.rejects(
      createInvitation(store, invitation(guestIds[2]!)),
      DailyInvitationLimitError,
      'revoked invitations still count toward the daily limit'
    );

    await prisma.convite.deleteMany();
    await prisma.morador.update({ where: { id: moradorId }, data: { dailyInvitationLimit: null } });
    await prisma.condominio.update({ where: { id: condominioId }, data: { dailyInvitationLimit: null } });
    for (const guestId of guestIds.slice(0, 12)) {
      assert.ok(await createInvitation(store, invitation(guestId)));
    }
    assert.equal(await prisma.convite.count(), 12, 'null at both levels represents an unlimited default');
  } finally {
    await prisma.$disconnect();
  }
});
