import assert from 'node:assert/strict';
import test from 'node:test';

import { PrismaClient } from '@prisma/client';

import { createApp } from '../src/app.js';
import { createDevelopmentHeaderAuthenticator } from '../src/auth.js';
import { canonicalRequestHash, createPrismaInvitationStore } from '../src/convites.js';
import { cleanupExpiredIdempotencyRecords } from '../src/jobs/cleanup-idempotency.js';

const runDatabaseTests = process.env.RUN_DATABASE_TESTS === 'true';
const tokenSecret = 'idempotency-db-invitation-token-secret-minimum-32-bytes';
const cacheSecret = 'idempotency-db-cache-secret-minimum-32-bytes';
const uuid = (n: number) => `70000000-0000-4000-8000-${String(n).padStart(12, '0')}`;

test('PostgreSQL serializes idempotent invitation issuance, rollback, replay, outbox, and cleanup', { skip: !runDatabaseTests }, async () => {
  const prisma = new PrismaClient();
  const condominioId = uuid(1);
  const moradorId = uuid(2);
  const guestIds = [uuid(3), uuid(4), uuid(5)];
  const authenticator = createDevelopmentHeaderAuthenticator(true);
  const headers = (key: string) => ({
    'x-development-user-id': moradorId,
    'x-development-user-role': 'morador',
    'x-development-condominio-id': condominioId,
    'idempotency-key': key
  });
  const singleUrl = `/condominios/${condominioId}/moradores/${moradorId}/convidados/${guestIds[0]}/convites`;
  const payload = { expiresAt: new Date(Date.now() + 60 * 60 * 1000).toISOString(), tipo: 'visitante' };

  try {
    await prisma.deliveryIntent.deleteMany();
    await prisma.idempotencyRecord.deleteMany();
    await prisma.convite.deleteMany();
    await prisma.convidado.deleteMany();
    await prisma.morador.deleteMany();
    await prisma.condominio.deleteMany();
    await prisma.securityKey.deleteMany();
    await prisma.condominio.create({
      data: { id: condominioId, nome: 'Principal', responsavel: 'Owner', tipo: 'residencial', timezone: 'America/Sao_Paulo' }
    });
    await prisma.morador.create({ data: { id: moradorId, nome: 'Resident', condominioId } });
    await prisma.convidado.createMany({
      data: [
        { id: guestIds[0]!, nome: 'Both', email: 'both@example.test', telefone: '+5511999990001', condominioId, moradorId },
        { id: guestIds[1]!, nome: 'Email', email: 'email@example.test', condominioId, moradorId },
        { id: guestIds[2]!, nome: 'SMS', telefone: '+5511999990002', condominioId, moradorId }
      ]
    });

    const app = createApp({
      authenticator,
      invitationTokenSecret: tokenSecret,
      idempotencyCacheSecret: cacheSecret
    });
    const simultaneous = await Promise.all([
      app.inject({ method: 'POST', url: singleUrl, headers: headers('same-single-request-key'), payload }),
      app.inject({ method: 'POST', url: singleUrl, headers: headers('same-single-request-key'), payload: { tipo: 'visitante', expiresAt: payload.expiresAt } })
    ]);
    assert.deepEqual(simultaneous.map((response) => response.statusCode), [201, 201]);
    assert.equal(simultaneous[0]!.body, simultaneous[1]!.body);
    assert.equal(await prisma.convite.count(), 1);
    assert.equal(await prisma.idempotencyRecord.count(), 1);
    assert.equal(await prisma.deliveryIntent.count(), 2);
    assert.equal(simultaneous.filter((response) => response.headers['idempotency-replayed'] === 'true').length, 1);

    const replay = await app.inject({ method: 'POST', url: singleUrl, headers: headers('same-single-request-key'), payload });
    assert.equal(replay.statusCode, 201);
    assert.equal(replay.body, simultaneous[0]!.body);
    const conflict = await app.inject({
      method: 'POST', url: singleUrl, headers: headers('same-single-request-key'),
      payload: { ...payload, expiresAt: new Date(Date.now() + 2 * 60 * 60 * 1000).toISOString() }
    });
    assert.equal(conflict.statusCode, 409);
    assert.equal(await prisma.convite.count(), 1);
    assert.equal(await prisma.deliveryIntent.count(), 2);

    const responseToken = replay.json().token as string;
    const replayRow = await prisma.idempotencyRecord.findFirstOrThrow();
    assert.ok(replayRow.confirmedAt && replayRow.expiresAt);
    const defaultTtlMs = replayRow.expiresAt.getTime() - replayRow.confirmedAt.getTime();
    assert.ok(defaultTtlMs >= 24 * 60 * 60 * 1000 - 1000 && defaultTtlMs <= 24 * 60 * 60 * 1000 + 1000);
    const intents = await prisma.deliveryIntent.findMany();
    const persisted = JSON.stringify({
      replay: Buffer.from(replayRow.responseCiphertext!).toString('base64'),
      intents: intents.map((intent) => Buffer.from(intent.payloadCiphertext).toString('base64'))
    });
    for (const plaintext of [responseToken, 'both@example.test', '+5511999990001', 'Seu código']) {
      assert.equal(persisted.includes(plaintext), false);
    }
    assert.match(replayRow.keyDigest.trim(), /^[0-9a-f]{64}$/);
    assert.notEqual(replayRow.keyDigest.trim(), 'same-single-request-key');

    const batchUrl = `/condominios/${condominioId}/moradores/${moradorId}/convites/multiplos`;
    const batchPayload = { convidadoIds: [guestIds[1], guestIds[2]] };
    const batchResponses = await Promise.all([
      app.inject({ method: 'POST', url: batchUrl, headers: headers('same-batch-request-key-01'), payload: batchPayload }),
      app.inject({ method: 'POST', url: batchUrl, headers: headers('same-batch-request-key-01'), payload: batchPayload })
    ]);
    assert.equal(batchResponses[0]!.body, batchResponses[1]!.body);
    assert.equal(await prisma.convite.count(), 3);
    assert.equal(await prisma.deliveryIntent.count(), 4);

    const mismatchApp = createApp({
      authenticator,
      invitationTokenSecret: tokenSecret,
      idempotencyCacheSecret: 'different-idempotency-cache-secret-minimum-32-bytes'
    });
    const mismatch = await mismatchApp.inject({
      method: 'POST', url: singleUrl, headers: headers('different-secret-key-0001'), payload
    });
    assert.equal(mismatch.statusCode, 503);
    assert.equal(await prisma.convite.count(), 3);
    await mismatchApp.close();

    const rollbackStore = createPrismaInvitationStore(prisma, tokenSecret, cacheSecret);
    let releaseWinner!: () => void;
    let winnerEntered!: () => void;
    const entered = new Promise<void>((resolve) => { winnerEntered = resolve; });
    const release = new Promise<void>((resolve) => { releaseWinner = resolve; });
    const rollbackArgs = {
      key: 'rollback-concurrency-key-01',
      actorId: moradorId,
      condominioId,
      method: 'POST' as const,
      route: '/rollback-test',
      requestHash: canonicalRequestHash({ guest: guestIds[0] }),
      invitations: [{ condominioId, moradorId, convidadoId: guestIds[0]!, tipo: 'visitante' as const, expiresAt: new Date(Date.now() + 60 * 60 * 1000) }]
    };
    const winner = rollbackStore.issueIdempotent!({
      ...rollbackArgs,
      async buildResponse() {
        winnerEntered();
        await release;
        throw new Error('forced winner rollback');
      }
    });
    await entered;
    const successor = rollbackStore.issueIdempotent!({
      ...rollbackArgs,
      async buildResponse(results) { return { token: results[0]!.token }; }
    });
    releaseWinner();
    await assert.rejects(winner, /forced winner rollback/);
    assert.equal((await successor)?.statusCode, 201);
    assert.equal(await prisma.idempotencyRecord.count({ where: { route: '/rollback-test' } }), 1);
    assert.equal(await prisma.convite.count(), 4);

    await prisma.idempotencyRecord.updateMany({ data: { expiresAt: new Date(Date.now() - 1000) } });
    const intentsBeforeCleanup = await prisma.deliveryIntent.count();
    assert.ok(await cleanupExpiredIdempotencyRecords(prisma, 100) >= 3);
    assert.equal(await prisma.idempotencyRecord.count(), 0);
    assert.equal(await prisma.deliveryIntent.count(), intentsBeforeCleanup);
    const afterCleanup = await app.inject({ method: 'POST', url: singleUrl, headers: headers('same-single-request-key'), payload });
    assert.equal(afterCleanup.statusCode, 201);
    assert.equal(await prisma.convite.count(), 5);

    const shortTtlStore = createPrismaInvitationStore(prisma, tokenSecret, cacheSecret, 60_000);
    const shortTtl = await shortTtlStore.issueIdempotent!({
      ...rollbackArgs,
      key: 'configured-short-ttl-key-01',
      route: '/ttl-test',
      requestHash: canonicalRequestHash({ ttl: 60 }),
      async buildResponse(results) { return { token: results[0]!.token }; }
    });
    assert.equal(shortTtl?.statusCode, 201);
    const shortTtlRow = await prisma.idempotencyRecord.findFirstOrThrow({ where: { route: '/ttl-test' } });
    assert.ok(shortTtlRow.confirmedAt && shortTtlRow.expiresAt);
    const configuredTtlMs = shortTtlRow.expiresAt.getTime() - shortTtlRow.confirmedAt.getTime();
    assert.ok(configuredTtlMs >= 59_000 && configuredTtlMs <= 61_000);

    await app.close();
  } finally {
    await prisma.$disconnect();
  }
});

test('PostgreSQL releases single and batch idempotency claims after an intended 404', { skip: !runDatabaseTests }, async () => {
  const prisma = new PrismaClient();
  const condominioId = uuid(101);
  const moradorId = uuid(102);
  const validGuestId = uuid(103);
  const missingSingleId = uuid(104);
  const missingBatchId = uuid(105);
  const authenticator = createDevelopmentHeaderAuthenticator(true);
  const headers = (key: string) => ({
    'x-development-user-id': moradorId,
    'x-development-user-role': 'morador',
    'x-development-condominio-id': condominioId,
    'idempotency-key': key
  });
  const payload = { tipo: 'visitante', expiresAt: new Date(Date.now() + 60 * 60 * 1000).toISOString() };

  try {
    await prisma.deliveryIntent.deleteMany();
    await prisma.idempotencyRecord.deleteMany();
    await prisma.convite.deleteMany();
    await prisma.convidado.deleteMany();
    await prisma.morador.deleteMany();
    await prisma.condominio.deleteMany();
    await prisma.securityKey.deleteMany();
    await prisma.condominio.create({
      data: { id: condominioId, nome: 'Principal', responsavel: 'Owner', tipo: 'residencial', timezone: 'America/Sao_Paulo' }
    });
    await prisma.morador.create({ data: { id: moradorId, nome: 'Resident', condominioId } });
    await prisma.convidado.create({ data: { id: validGuestId, nome: 'Valid', condominioId, moradorId } });

    const app = createApp({
      authenticator,
      invitationTokenSecret: tokenSecret,
      idempotencyCacheSecret: cacheSecret
    });
    const singleUrl = `/condominios/${condominioId}/moradores/${moradorId}/convidados/${missingSingleId}/convites`;
    const single404 = await app.inject({
      method: 'POST', url: singleUrl, headers: headers('missing-single-idempotency-key'), payload
    });
    assert.equal(single404.statusCode, 404);
    assert.equal(await prisma.idempotencyRecord.count(), 0);
    assert.equal(await prisma.convite.count(), 0);

    await prisma.convidado.create({ data: { id: missingSingleId, nome: 'Now active', condominioId, moradorId } });
    const singleRetry = await app.inject({
      method: 'POST', url: singleUrl, headers: headers('missing-single-idempotency-key'), payload
    });
    assert.equal(singleRetry.statusCode, 201);
    assert.equal(await prisma.idempotencyRecord.count(), 1);
    assert.equal(await prisma.convite.count(), 1);

    const batchUrl = `/condominios/${condominioId}/moradores/${moradorId}/convites/multiplos`;
    const batchPayload = { convidadoIds: [validGuestId, missingBatchId] };
    const batch404 = await app.inject({
      method: 'POST', url: batchUrl, headers: headers('missing-batch-idempotency-key'), payload: batchPayload
    });
    assert.equal(batch404.statusCode, 404);
    assert.equal(await prisma.idempotencyRecord.count(), 1);
    assert.equal(await prisma.convite.count(), 1);

    await prisma.convidado.create({ data: { id: missingBatchId, nome: 'Now active', condominioId, moradorId } });
    const batchRetry = await app.inject({
      method: 'POST', url: batchUrl, headers: headers('missing-batch-idempotency-key'), payload: batchPayload
    });
    assert.equal(batchRetry.statusCode, 201);
    assert.equal(await prisma.idempotencyRecord.count(), 2);
    assert.equal(await prisma.convite.count(), 3);
    await app.close();
  } finally {
    await prisma.$disconnect();
  }
});
