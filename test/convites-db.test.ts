import assert from 'node:assert/strict';
import { createHmac } from 'node:crypto';
import test from 'node:test';

import { PrismaClient } from '@prisma/client';

import { createApp } from '../src/app.js';
import { createDevelopmentHeaderAuthenticator } from '../src/auth.js';
import {
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
  const guestIds = [uuid(201), uuid(202), uuid(203), uuid(204), uuid(205), uuid(206)];
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

    await prisma.convidado.update({ where: { id: guestIds[1] }, data: { deletedAt: new Date() } });
    assert.equal(await consumeInvitationToken(store, batch.convites[0]!.token), false);
    await app.close();
  } finally {
    await prisma.$disconnect();
  }
});
