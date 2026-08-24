import assert from 'node:assert/strict';
import { createDecipheriv, createHash, createHmac, randomUUID } from 'node:crypto';
import test from 'node:test';

import { PrismaClient } from '@prisma/client';

import { createApp } from '../src/app.js';
import { createDevelopmentHeaderAuthenticator } from '../src/auth.js';
import {
  DailyInvitationLimitError,
  createInvitation,
  createInvitations,
  createPrismaInvitationStore,
  invitationMessage
} from '../src/convites.js';
import type { NotificationSender } from '../src/convites.js';

const runDatabaseTests = process.env.RUN_DATABASE_TESTS === 'true';
const secret = 'database-e2e-invitation-secret-32-bytes-minimum';
const idempotencySecret = 'database-e2e-idempotency-secret-32-bytes-minimum';
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
    await prisma.deliveryIntent.deleteMany();
    await prisma.idempotencyRecord.deleteMany();
    await prisma.convite.deleteMany();
    await prisma.convidado.deleteMany();
    await prisma.morador.deleteMany();
    await prisma.condominio.deleteMany();
    await prisma.securityKey.deleteMany();

    await prisma.condominio.createMany({
      data: [
        { id: condominioId, nome: 'Principal', responsavel: 'Owner', tipo: 'residencial', timezone: 'America/Sao_Paulo' },
        { id: otherCondominioId, nome: 'Other', responsavel: 'Other', tipo: 'residencial', timezone: 'America/Manaus' }
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
      invitationTokenSecret: secret,
      idempotencyCacheSecret: idempotencySecret
    });
    const headers = {
      'x-development-user-id': moradorId,
      'x-development-user-role': 'morador',
      'x-development-condominio-id': condominioId,
      'idempotency-key': 'database-invitation-key-0001'
    };
    const validate = (token: string) => store.validateActive({
      token,
      condominiumId: condominioId,
      deviceId: `database-test-${randomUUID()}`,
      accessType: 'pedestre'
    }, new Date());
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

    assert.equal((await validate(single.token)).allowed, true);
    assert.equal((await validate(single.token)).allowed, false);
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
    assert.equal((await validate(batch.convites[0]!.token)).allowed, false, 'revocation denies consumption immediately');
    const revokedRecord = await prisma.convite.findUniqueOrThrow({ where: { id: batch.convites[0]!.id } });
    assert.equal(revokedRecord.tokenDigest, null);
    assert.equal(revokedRecord.usedAt, null);
    assert.ok(revokedRecord.revokedAt);

    const race = await createInvitation(
      store,
      { condominioId, moradorId, convidadoId: guestIds[6]!, tipo: 'visitante', expiresAt }
    );
    assert.ok(race);
    const [raceValidation, raceRevoked] = await Promise.all([
      validate(race.token),
      store.revokeActive({ id: race.convite.id, condominioId, moradorId }, new Date())
    ]);
    assert.equal(Number(raceValidation.allowed) + Number(raceRevoked === 'revoked'), 1, 'consume and revoke cannot both win');
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
    assert.equal((await validate(batch.convites[0]!.token)).allowed, false);
    await app.close();
  } finally {
    await prisma.$disconnect();
  }
});

test('PostgreSQL gatehouse validation is tenant-scoped, one-use, and fail-closed', { skip: !runDatabaseTests }, async () => {
  const prisma = new PrismaClient();
  const store = createPrismaInvitationStore(prisma, secret);
  const condominioId = uuid(20);
  const otherCondominioId = uuid(21);
  const moradorId = uuid(120);
  const otherMoradorId = uuid(121);
  const guestIds = Array.from({ length: 8 }, (_, index) => uuid(420 + index));
  const deviceRunId = randomUUID();
  const future = new Date(Date.now() + 60 * 60 * 1000);
  const create = (guestId: string, token: string, tenant = condominioId, resident = moradorId) => createInvitation(
    store,
    { condominioId: tenant, moradorId: resident, convidadoId: guestId, tipo: 'visitante', expiresAt: future },
    { generateToken: () => token }
  );
  const headers = (tenant: string) => ({
    'x-development-user-id': `gatehouse-${tenant}-${deviceRunId}`,
    'x-development-user-role': 'portaria',
    'x-development-condominio-id': tenant
  });

  try {
    await prisma.deliveryIntent.deleteMany();
    await prisma.idempotencyRecord.deleteMany();
    await prisma.convite.deleteMany();
    await prisma.convidado.deleteMany();
    await prisma.morador.deleteMany();
    await prisma.condominio.deleteMany();
    await prisma.securityKey.deleteMany();
    await prisma.condominio.createMany({
      data: [
        { id: condominioId, nome: 'Principal', responsavel: 'Owner', tipo: 'residencial', timezone: 'America/Sao_Paulo' },
        { id: otherCondominioId, nome: 'Other', responsavel: 'Other', tipo: 'residencial', timezone: 'America/Manaus' }
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
        ...guestIds.slice(0, 7).map((id, index) => ({ id, nome: `Guest ${index}`, condominioId, moradorId })),
        { id: guestIds[7]!, nome: 'Other guest', condominioId: otherCondominioId, moradorId: otherMoradorId }
      ]
    });

    const valid = await create(guestIds[0]!, '101010');
    const expired = await create(guestIds[1]!, '202020');
    const revoked = await create(guestIds[2]!, '303030');
    const wrongTenant = await create(guestIds[7]!, '404040', otherCondominioId, otherMoradorId);
    const deletedGuest = await create(guestIds[3]!, '505050');
    const deletedResident = await create(guestIds[4]!, '606060');
    const concurrent = await create(guestIds[5]!, '707070');
    const deletedCondominium = await create(guestIds[6]!, '808080');
    assert.ok(valid && expired && revoked && wrongTenant && deletedGuest && deletedResident && concurrent && deletedCondominium);

    await prisma.convite.update({
      where: { id: expired.convite.id },
      data: {
        createdAt: new Date(Date.now() - 2 * 60 * 60 * 1000),
        expiresAt: new Date(Date.now() - 60 * 60 * 1000)
      }
    });
    assert.equal(await store.revokeActive({ id: revoked.convite.id, condominioId, moradorId }, new Date()), 'revoked');
    await prisma.convidado.update({ where: { id: deletedGuest.convite.convidadoId! }, data: { deletedAt: new Date() } });

    const app = createApp({ authenticator: createDevelopmentHeaderAuthenticator(true), invitationTokenSecret: secret });
    const validate = (token: string, tenant = condominioId) => app.inject({
      method: 'POST',
      url: '/portaria/convites/validar',
      headers: headers(tenant),
      payload: { token, tipoAcesso: 'pedestre' }
    });
    const denied = { allowed: false, reason: 'invalid_or_unavailable' };

    const allowed = await validate(valid.token);
    assert.equal(allowed.statusCode, 200);
    assert.equal(allowed.headers['cache-control'], 'no-store');
    assert.deepEqual(allowed.json(), {
      allowed: true,
      guest: { name: 'Guest 0' },
      invitation: { type: 'visitante' }
    });
    assert.equal(allowed.body.includes(valid.token), false);
    assert.deepEqual((await validate(valid.token)).json(), denied, 'replay is denied');
    const persistedValid = await prisma.convite.findUniqueOrThrow({ where: { id: valid.convite.id } });
    assert.ok(persistedValid.usedAt);
    assert.equal(persistedValid.tokenDigest, null);
    assert.ok((await prisma.convidado.findUniqueOrThrow({ where: { id: guestIds[0]! } })).ultimoUsoEm);
    assert.equal(await prisma.notificacao.count({ where: { conviteId: valid.convite.id, deletedAt: null } }), 1);
    await assert.rejects(
      prisma.$executeRaw`
        INSERT INTO "Notificacao" (
          id, tipo, mensagem, "nomeConvidado", "entrouEm",
          "condominioId", "moradorId", "convidadoId", "conviteId"
        ) VALUES (
          ${randomUUID()}, 'entrada_visitante', 'invalid tenant relation', 'Guest 0', clock_timestamp(),
          ${condominioId}, ${otherMoradorId}, ${guestIds[7]!}, ${wrongTenant.convite.id}
        )
      `,
      /foreign key constraint/i
    );
    const residentNotifications = await app.inject({
      method: 'GET',
      url: `/condominios/${condominioId}/moradores/${moradorId}/notificacoes?unread=true`,
      headers: {
        'x-development-user-id': moradorId,
        'x-development-user-role': 'morador',
        'x-development-condominio-id': condominioId
      }
    });
    assert.equal(residentNotifications.statusCode, 200);
    assert.equal(residentNotifications.headers['cache-control'], 'no-store');
    assert.equal(residentNotifications.headers.pragma, 'no-cache');
    assert.equal(residentNotifications.json().length, 1);
    const notificationId = residentNotifications.json()[0].id as string;
    assert.equal((await app.inject({
      method: 'PATCH',
      url: `/condominios/${condominioId}/moradores/${moradorId}/notificacoes/${notificationId}`,
      headers: {
        'x-development-user-id': moradorId,
        'x-development-user-role': 'morador',
        'x-development-condominio-id': condominioId
      }
    })).statusCode, 200);
    assert.equal((await app.inject({
      method: 'GET',
      url: `/condominios/${condominioId}/moradores/${moradorId}/notificacoes?unread=true`,
      headers: {
        'x-development-user-id': moradorId,
        'x-development-user-role': 'morador',
        'x-development-condominio-id': condominioId
      }
    })).json().length, 0);
    assert.equal((await app.inject({
      method: 'GET',
      url: `/condominios/${condominioId}/moradores/${otherMoradorId}/notificacoes`,
      headers: {
        'x-development-user-id': moradorId,
        'x-development-user-role': 'morador',
        'x-development-condominio-id': condominioId
      }
    })).statusCode, 403);

    assert.deepEqual((await validate(expired.token)).json(), denied);
    assert.deepEqual((await validate(revoked.token)).json(), denied);
    assert.deepEqual((await validate(wrongTenant.token)).json(), denied);
    assert.equal((await prisma.convite.findUniqueOrThrow({ where: { id: wrongTenant.convite.id } })).usedAt, null);
    assert.deepEqual((await validate(deletedGuest.token)).json(), denied);

    await prisma.morador.update({ where: { id: moradorId }, data: { deletedAt: new Date() } });
    const inactiveResidentNotifications = await app.inject({
      method: 'GET',
      url: `/condominios/${condominioId}/moradores/${moradorId}/notificacoes`,
      headers: {
        'x-development-user-id': moradorId,
        'x-development-user-role': 'morador',
        'x-development-condominio-id': condominioId
      }
    });
    assert.equal(inactiveResidentNotifications.statusCode, 200);
    assert.deepEqual(inactiveResidentNotifications.json(), []);
    assert.equal((await app.inject({
      method: 'PATCH',
      url: `/condominios/${condominioId}/moradores/${moradorId}/notificacoes/${notificationId}`,
      headers: {
        'x-development-user-id': moradorId,
        'x-development-user-role': 'morador',
        'x-development-condominio-id': condominioId
      }
    })).statusCode, 404);
    assert.deepEqual((await validate(deletedResident.token)).json(), denied);
    assert.equal(await prisma.notificacao.count({ where: { conviteId: deletedResident.convite.id } }), 0);
    await prisma.morador.update({ where: { id: moradorId }, data: { deletedAt: null } });
    await prisma.condominio.update({ where: { id: condominioId }, data: { deletedAt: new Date() } });
    assert.deepEqual((await validate(deletedCondominium.token)).json(), denied);
    await prisma.condominio.update({ where: { id: condominioId }, data: { deletedAt: null } });

    for (const payload of [
      { token: '12345', tipoAcesso: 'pedestre' },
      { token: 'abcdef', tipoAcesso: 'veiculo' },
      { token: '123456', tipoAcesso: 'pedestre', extra: true }
    ]) {
      assert.deepEqual((await app.inject({ method: 'POST', url: '/portaria/convites/validar', headers: headers(condominioId), payload })).json(), denied);
    }

    const simultaneous = await Promise.all([validate(concurrent.token), validate(concurrent.token)]);
    assert.equal(simultaneous.filter((response) => response.json().allowed === true).length, 1);
    assert.equal(simultaneous.filter((response) => response.json().allowed === false).length, 1);

    const atomic = await create(guestIds[0]!, '909090');
    assert.ok(atomic);
    await prisma.$executeRawUnsafe(`
      CREATE FUNCTION reject_permitted_audit_for_test() RETURNS trigger
      LANGUAGE plpgsql AS $$
      BEGIN
        IF NEW.resultado = 'permitido' THEN
          RAISE EXCEPTION 'forced audit failure';
        END IF;
        RETURN NEW;
      END;
      $$
    `);
    await prisma.$executeRawUnsafe(`
      CREATE TRIGGER reject_permitted_audit_for_test
      BEFORE INSERT ON "AuditoriaAcesso"
      FOR EACH ROW EXECUTE FUNCTION reject_permitted_audit_for_test()
    `);
    const auditFailure = await validate(atomic.token);
    assert.equal(auditFailure.statusCode, 500);
    const afterAuditFailure = await prisma.convite.findUniqueOrThrow({ where: { id: atomic.convite.id } });
    assert.equal(afterAuditFailure.usedAt, null, 'audit failure must roll back token consumption');
    assert.ok(afterAuditFailure.tokenDigest, 'audit failure must leave the token reusable');
    await prisma.$executeRawUnsafe('DROP TRIGGER reject_permitted_audit_for_test ON "AuditoriaAcesso"');
    await prisma.$executeRawUnsafe('DROP FUNCTION reject_permitted_audit_for_test()');
    assert.equal((await validate(atomic.token)).json().allowed, true);

    const mismatchedSecretApp = createApp({
      authenticator: createDevelopmentHeaderAuthenticator(true),
      invitationTokenSecret: 'different-database-e2e-secret-32-bytes-minimum'
    });
    const mismatch = await mismatchedSecretApp.inject({
      method: 'POST',
      url: '/portaria/convites/validar',
      headers: headers(otherCondominioId),
      payload: { token: wrongTenant.token, tipoAcesso: 'pedestre' }
    });
    assert.equal(mismatch.statusCode, 503);
    assert.deepEqual(mismatch.json(), { allowed: false, reason: 'service_unavailable' });
    assert.equal((await prisma.convite.findUniqueOrThrow({ where: { id: wrongTenant.convite.id } })).usedAt, null);

    const mainDeviceId = headers(condominioId)['x-development-user-id'];
    const audits = await prisma.auditoriaAcesso.findMany({
      where: { dispositivoId: mainDeviceId },
      orderBy: { createdAt: 'asc' }
    });
    assert.equal(audits.length, 14, 'every completed validation attempt creates exactly one audit row');
    assert.equal(audits.filter((audit) => audit.resultado === 'permitido').length, 3);
    assert.equal(audits.filter((audit) => audit.resultado === 'negado').length, 11);
    assert.ok(audits.every((audit) => ['pedestre', 'veiculo'].includes(audit.tipoAcesso)));
    assert.ok(audits.every((audit) => audit.condominioId === condominioId));
    assert.ok(audits.every((audit) => audit.dispositivoId === mainDeviceId));
    const serializedAudits = JSON.stringify(audits).toLowerCase();
    for (const forbidden of ['token', 'digest', 'nome', 'email', 'telefone', valid.token, wrongTenant.token]) {
      assert.equal(serializedAudits.includes(forbidden.toLowerCase()), false, `audit leaked ${forbidden}`);
    }

    const allowedAudit = audits.find((audit) => audit.conviteId === valid.convite.id);
    assert.equal(allowedAudit?.resultado, 'permitido');
    assert.equal(allowedAudit?.moradorId, moradorId);
    assert.equal(allowedAudit?.convidadoId, guestIds[0]);
    const crossTenantAudit = audits.find((audit) => audit.resultado === 'negado' && audit.conviteId === null);
    assert.equal(crossTenantAudit?.resultado, 'negado');
    assert.equal(crossTenantAudit?.condominioId, condominioId, 'the authenticated device tenant is preserved');
    assert.equal(
      audits.some((audit) => audit.conviteId === wrongTenant.convite.id),
      false,
      'cross-tenant attempts never attach foreign invitation ownership'
    );

    await assert.rejects(
      prisma.auditoriaAcesso.update({ where: { id: audits[0]!.id }, data: { resultado: 'negado' } }),
      /immutable/
    );
    await assert.rejects(prisma.auditoriaAcesso.delete({ where: { id: audits[0]!.id } }), /immutable/);

    const residentHeaders = {
      'x-development-user-id': moradorId,
      'x-development-user-role': 'morador',
      'x-development-condominio-id': condominioId
    };
    const residentAuditResponse = await app.inject({
      method: 'GET',
      url: `/condominios/${condominioId}/moradores/${moradorId}/auditorias-acesso`,
      headers: residentHeaders
    });
    assert.equal(residentAuditResponse.statusCode, 200);
    assert.equal(residentAuditResponse.headers['cache-control'], 'no-store');
    const residentAudits = (residentAuditResponse.json() as Array<Record<string, unknown>>)
      .filter((audit) => audit.dispositivoId === mainDeviceId);
    assert.equal(residentAudits.length, 7, 'resident sees only attempts tied to invitations they own');
    assert.equal(JSON.stringify(residentAudits).includes(valid.token), false);

    const otherResidentResponse = await app.inject({
      method: 'GET',
      url: `/condominios/${otherCondominioId}/moradores/${otherMoradorId}/auditorias-acesso`,
      headers: {
        'x-development-user-id': otherMoradorId,
        'x-development-user-role': 'morador',
        'x-development-condominio-id': otherCondominioId
      }
    });
    assert.equal(otherResidentResponse.statusCode, 200);
    const otherResidentAudits = (otherResidentResponse.json() as Array<Record<string, unknown>>)
      .filter((audit) => audit.dispositivoId === mainDeviceId);
    assert.equal(otherResidentAudits.length, 0, 'a foreign tenant cannot inject rows into the owner feed');

    for (const role of ['provedor', 'sindico'] as const) {
      const forbiddenQuery = await app.inject({
        method: 'GET',
        url: `/condominios/${condominioId}/moradores/${moradorId}/auditorias-acesso`,
        headers: {
          'x-development-user-id': `${role}-audit-reader`,
          'x-development-user-role': role,
          'x-development-condominio-id': role === 'provedor' ? '*' : condominioId
        }
      });
      assert.equal(forbiddenQuery.statusCode, 403);
    }

    await prisma.morador.update({ where: { id: moradorId }, data: { deletedAt: new Date() } });
    const inactiveParentQuery = await app.inject({
      method: 'GET',
      url: `/condominios/${condominioId}/moradores/${moradorId}/auditorias-acesso`,
      headers: residentHeaders
    });
    assert.equal(inactiveParentQuery.statusCode, 404, 'API keeps active-parent semantics');
    assert.equal(await prisma.auditoriaAcesso.count({ where: { dispositivoId: mainDeviceId } }), 14);
    await prisma.morador.update({ where: { id: moradorId }, data: { deletedAt: null } });

    await mismatchedSecretApp.close();
    await app.close();
  } finally {
    await prisma.$disconnect();
  }
});

test('PostgreSQL daily limits use condominium civil days and serialized batch issuance', { skip: !runDatabaseTests }, async () => {
  const prisma = new PrismaClient();
  const store = createPrismaInvitationStore(prisma, secret);
  const condominioId = uuid(10);
  const moradorId = uuid(110);
  const guestIds = Array.from({ length: 16 }, (_, index) => uuid(300 + index));
  const expiresAt = new Date(Date.now() + 60 * 60 * 1000);
  const invitation = (convidadoId: string) => ({ condominioId, moradorId, convidadoId, tipo: 'visitante' as const, expiresAt });

  try {
    await prisma.deliveryIntent.deleteMany();
    await prisma.idempotencyRecord.deleteMany();
    await prisma.convite.deleteMany();
    await prisma.convidado.deleteMany();
    await prisma.morador.deleteMany();
    await prisma.condominio.deleteMany();
    await prisma.securityKey.deleteMany();
    await prisma.condominio.create({ data: { id: condominioId, nome: 'Principal', responsavel: 'Owner', tipo: 'residencial', timezone: 'America/Sao_Paulo', dailyInvitationLimit: 10 } });
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

    for (const [index, timezone] of ['America/Sao_Paulo', 'America/Manaus'].entries()) {
      await prisma.convite.deleteMany();
      await prisma.condominio.update({ where: { id: condominioId }, data: { timezone, dailyInvitationLimit: 1 } });
      const [{ localStart }] = await prisma.$queryRaw<Array<{ localStart: Date }>>`
        SELECT (((clock_timestamp() AT TIME ZONE ${timezone})::date)::timestamp AT TIME ZONE ${timezone}) AS "localStart"
      `;
      await prisma.convite.create({
        data: {
          ...invitation(guestIds[0]!), createdAt: new Date(localStart.getTime() - 1),
          tokenDigest: createHmac('sha256', secret).update(`99999${index}`).digest('hex')
        }
      });
      assert.ok(await createInvitation(store, invitation(guestIds[1]!)));
      await assert.rejects(createInvitation(store, invitation(guestIds[2]!)), DailyInvitationLimitError);
      assert.equal(await prisma.convite.count(), 2, `${timezone} resets exactly at its local midnight`);
    }

    const [dst] = await prisma.$queryRaw<Array<{ springHours: number; fallHours: number }>>`
      SELECT
        (EXTRACT(EPOCH FROM (
          TIMESTAMP '2026-03-09 00:00:00' AT TIME ZONE 'America/New_York'
          - TIMESTAMP '2026-03-08 00:00:00' AT TIME ZONE 'America/New_York'
        )) / 3600)::double precision AS "springHours",
        (EXTRACT(EPOCH FROM (
          TIMESTAMP '2026-11-02 00:00:00' AT TIME ZONE 'America/New_York'
          - TIMESTAMP '2026-11-01 00:00:00' AT TIME ZONE 'America/New_York'
        )) / 3600)::double precision AS "fallHours"
    `;
    assert.deepEqual(dst, { springHours: 23, fallHours: 25 });

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
    assert.equal((await store.validateActive({
      token: used.token,
      condominiumId: condominioId,
      deviceId: `daily-limit-test-${randomUUID()}`,
      accessType: 'pedestre'
    }, new Date())).allowed, true);
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

test('PostgreSQL quota uses one explicit issuance instant across 23 and 25 hour local days', { skip: !runDatabaseTests }, async () => {
  const prisma = new PrismaClient();
  const condominioId = uuid(50);
  const moradorId = uuid(150);
  const guestIds = [uuid(550), uuid(551), uuid(552)];
  const timeZone = 'America/New_York';

  try {
    await prisma.convite.deleteMany();
    await prisma.convidado.deleteMany();
    await prisma.morador.deleteMany();
    await prisma.condominio.deleteMany();
    await prisma.condominio.create({
      data: { id: condominioId, nome: 'DST', responsavel: 'Owner', tipo: 'residencial', timezone: timeZone, dailyInvitationLimit: 1 }
    });
    await prisma.morador.create({ data: { id: moradorId, nome: 'Resident', condominioId } });
    await prisma.convidado.createMany({ data: guestIds.map((id) => ({ id, nome: id, condominioId, moradorId })) });

    for (const [index, expectedHours, issuanceTime] of [
      [0, 23, new Date('2026-03-08T16:00:00.000Z')],
      [1, 25, new Date('2026-11-01T17:00:00.000Z')]
    ] as const) {
      await prisma.convite.deleteMany();
      const [{ localStart, localEnd }] = await prisma.$queryRaw<Array<{ localStart: Date; localEnd: Date }>>`
        SELECT
          (((${issuanceTime} AT TIME ZONE ${timeZone})::date)::timestamp AT TIME ZONE ${timeZone}) AS "localStart",
          ((((${issuanceTime} AT TIME ZONE ${timeZone})::date + 1)::timestamp) AT TIME ZONE ${timeZone}) AS "localEnd"
      `;
      assert.equal((localEnd.getTime() - localStart.getTime()) / 3_600_000, expectedHours);

      const transactionStart = new Date(localStart.getTime() - 1);
      await prisma.$executeRawUnsafe(
        `ALTER TABLE "Convite" ALTER COLUMN "createdAt" SET DEFAULT '${transactionStart.toISOString()}'::timestamptz`
      );
      await prisma.convite.create({
        data: {
          condominioId,
          moradorId,
          convidadoId: guestIds[0]!,
          createdAt: transactionStart
        }
      });
      const store = createPrismaInvitationStore(prisma, secret, {
        async readDatabaseTime(transaction) {
          const [{ now }] = await transaction.$queryRaw<Array<{ now: Date }>>`SELECT ${issuanceTime}::timestamptz AS now`;
          return now;
        }
      });
      const data = (convidadoId: string) => ({
        condominioId,
        moradorId,
        convidadoId,
        tipo: 'visitante' as const,
        expiresAt: new Date(issuanceTime.getTime() + 366 * 24 * 60 * 60 * 1000)
      });
      const issued = await createInvitation(store, data(guestIds[1]!), {
        now: () => issuanceTime,
        generateToken: () => `80000${index}`
      });
      assert.equal(issued?.convite.createdAt.toISOString(), issuanceTime.toISOString());
      await assert.rejects(
        createInvitation(store, data(guestIds[2]!), { now: () => issuanceTime, generateToken: () => `81000${index}` }),
        DailyInvitationLimitError
      );
      assert.equal(await prisma.convite.count(), 2, 'the pre-midnight default does not hide the explicit post-midnight issuance');
    }
  } finally {
    await prisma.$executeRawUnsafe('ALTER TABLE "Convite" ALTER COLUMN "createdAt" SET DEFAULT CURRENT_TIMESTAMP').catch(() => undefined);
    await prisma.$disconnect();
  }
});

test('issuance returns the timezone snapshot acquired under the condominium lock', { skip: !runDatabaseTests }, async () => {
  const prisma = new PrismaClient();
  const condominioId = uuid(60);
  const moradorId = uuid(160);
  const convidadoId = uuid(560);
  const expiresAt = new Date(Date.now() + 60 * 60 * 1000);
  const sent: string[] = [];
  const notifications: NotificationSender = {
    email: { async send(_to, message) { sent.push(message.body); } },
    sms: { async send() {} }
  };
  let reportLocked!: () => void;
  let releaseLock!: () => void;
  const locked = new Promise<void>((resolve) => { reportLocked = resolve; });
  const release = new Promise<void>((resolve) => { releaseLock = resolve; });

  try {
    await prisma.convite.deleteMany();
    await prisma.convidado.deleteMany();
    await prisma.morador.deleteMany();
    await prisma.condominio.deleteMany();
    await prisma.condominio.create({
      data: { id: condominioId, nome: 'Race', responsavel: 'Owner', tipo: 'residencial', timezone: 'America/Sao_Paulo' }
    });
    await prisma.morador.create({ data: { id: moradorId, nome: 'Resident', condominioId } });
    await prisma.convidado.create({
      data: { id: convidadoId, nome: 'Guest', email: 'guest@example.com', condominioId, moradorId }
    });
    const holder = prisma.$transaction(async (transaction) => {
      await transaction.$queryRaw`SELECT id FROM "Condominio" WHERE id = ${condominioId} FOR UPDATE`;
      reportLocked();
      await release;
      await transaction.condominio.update({ where: { id: condominioId }, data: { timezone: 'America/Manaus' } });
    });
    await locked;

    const app = createApp({
      authenticator: createDevelopmentHeaderAuthenticator(true),
      invitationTokenSecret: secret,
      idempotencyCacheSecret: idempotencySecret,
      notificationSender: notifications
    });
    const responsePromise = app.inject({
      method: 'POST',
      url: `/condominios/${condominioId}/moradores/${moradorId}/convidados/${convidadoId}/convites`,
      headers: {
        'x-development-user-id': moradorId,
        'x-development-user-role': 'morador',
        'x-development-condominio-id': condominioId,
        'idempotency-key': 'timezone-snapshot-request-01'
      },
      payload: { tipo: 'visitante', expiresAt: expiresAt.toISOString() }
    });
    await new Promise((resolve) => setTimeout(resolve, 100));
    releaseLock();
    await holder;
    const response = await responsePromise;
    assert.equal(response.statusCode, 201);
    const result = response.json() as { id: string; createdAt: string; token: string };
    assert.equal(sent.length, 0, 'transactional issuance must not call delivery providers');
    const intent = await prisma.deliveryIntent.findFirstOrThrow({
      where: { conviteId: result.id, channel: 'email' }
    });
    const decipher = createDecipheriv(
      'aes-256-gcm',
      createHash('sha256').update(idempotencySecret).digest(),
      Buffer.from(intent.payloadIv)
    );
    decipher.setAAD(Buffer.from(`delivery:${intent.id}:${intent.conviteId}:${intent.channel}:v${intent.keyVersion}`));
    decipher.setAuthTag(Buffer.from(intent.payloadAuthTag));
    const payload = JSON.parse(Buffer.concat([
      decipher.update(Buffer.from(intent.payloadCiphertext)),
      decipher.final()
    ]).toString('utf8')) as { body: string };
    assert.equal(payload.body, invitationMessage({
      condominiumName: 'Race',
      residentName: 'Resident',
      generatedAt: new Date(result.createdAt),
      expiresAt,
      token: result.token,
      timeZone: 'America/Manaus'
    }).body);
    await app.close();

    await prisma.condominio.update({ where: { id: condominioId }, data: { timezone: 'Factory' } });
    const before = await prisma.convite.count();
    const unavailableApp = createApp({
      authenticator: createDevelopmentHeaderAuthenticator(true),
      invitationTokenSecret: secret,
      idempotencyCacheSecret: idempotencySecret,
      notificationSender: notifications
    });
    const unavailable = await unavailableApp.inject({
      method: 'POST',
      url: `/condominios/${condominioId}/moradores/${moradorId}/convidados/${convidadoId}/convites`,
      headers: {
        'x-development-user-id': moradorId,
        'x-development-user-role': 'morador',
        'x-development-condominio-id': condominioId,
        'idempotency-key': 'timezone-unavailable-request-01'
      },
      payload: { tipo: 'visitante', expiresAt: expiresAt.toISOString() }
    });
    assert.equal(unavailable.statusCode, 503);
    assert.deepEqual(unavailable.json(), { error: 'Condominium timezone unavailable' });
    assert.equal(await prisma.convite.count(), before);
    await unavailableApp.close();
  } finally {
    releaseLock();
    await prisma.$disconnect();
  }
});
