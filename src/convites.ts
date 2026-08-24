import { createHash, createHmac, randomInt } from 'node:crypto';

import { Prisma, type PrismaClient, type TipoConvite } from '@prisma/client';
import type { FastifyInstance } from 'fastify';

import type { AppStore } from './app.js';
import { authorize, isUuid } from './auth.js';
import type { Authenticator } from './auth.js';
import { insertEntryNotification } from './notificacoes.js';

export const INVITATION_TYPES = ['visitante', 'prestador', 'entregador'] as const satisfies readonly TipoConvite[];
const TOKEN_PATTERN = /^[0-9]{6}$/;
const TOKEN_LIMIT = 1_000_000;
const MAX_TOKEN_ATTEMPTS = 32;
const BATCH_EXPIRATION_MS = 24 * 60 * 60 * 1000;

export type InvitationMessage = { subject: string; body: string };
export interface EmailSender { send(to: string, message: InvitationMessage): Promise<void>; }
export interface SmsSender { send(to: string, body: string): Promise<void>; }
export type NotificationSender = { email: EmailSender; sms: SmsSender };
export function createDevelopmentNotificationSender(): NotificationSender {
  return { email: { async send() {} }, sms: { async send() {} } };
}
export function createUnavailableNotificationSender(): NotificationSender {
  const unavailable = async () => { throw new Error('Notification delivery is unavailable'); };
  return { email: { send: unavailable }, sms: { send: unavailable } };
}
function formatDate(date: Date) {
  return new Intl.DateTimeFormat('pt-BR', { dateStyle: 'short', timeZone: 'UTC' }).format(date);
}

function formatTime(date: Date) {
  return new Intl.DateTimeFormat('pt-BR', {
    hour: '2-digit',
    hour12: false,
    minute: '2-digit',
    timeZone: 'UTC'
  }).format(date);
}

export function invitationMessage(input: {
  condominiumName: string;
  residentName: string;
  generatedAt: Date;
  expiresAt: Date;
  token: string;
}): InvitationMessage {
  return {
    subject: `Convite de acesso ao condomínio ${input.condominiumName}`,
    body: `Seu código para a entrada no condomínio ${input.condominiumName} foi gerado por ${input.residentName} às ${formatTime(input.generatedAt)} do dia ${formatDate(input.generatedAt)} e será expirado em ${formatDate(input.expiresAt)} às ${formatTime(input.expiresAt)}.\nSeu código é: ${input.token}`
  };
}

export type InvitationRecord = {
  id: string;
  createdAt: Date;
  deletedAt: Date | null;
  condominioId: string;
  moradorId: string | null;
  convidadoId: string | null;
  tipo: TipoConvite | null;
  expiresAt: Date | null;
  usedAt: Date | null;
  revokedAt: Date | null;
  tokenDigest: string | null;
};

export type InvitationCreateData = {
  condominioId: string;
  moradorId: string;
  convidadoId: string;
  tipo: TipoConvite;
  expiresAt: Date;
};

export type InvitationAllocation = InvitationCreateData & { token: string; now: Date };

export type InvitationValidationEvent = {
  invitationId: string;
  condominiumId: string;
  residentId: string;
  guestId: string;
  invitationType: TipoConvite;
  usedAt: Date;
};

export type InvitationValidationResult =
  | { allowed: false; reason: 'invalid_or_unavailable' }
  | {
      allowed: true;
      guest: { name: string };
      invitation: { type: TipoConvite };
      event: InvitationValidationEvent;
    };

export interface InvitationStore {
  createActive(args: InvitationAllocation): Promise<InvitationRecord | null>;
  createBatchActive(args: readonly InvitationAllocation[]): Promise<readonly InvitationRecord[] | null>;
  consumeActive(token: string, now: Date): Promise<boolean>;
  validateActive(args: { token: string; condominiumId: string }, now: Date): Promise<InvitationValidationResult>;
  revokeActive(args: { id: string; condominioId: string; moradorId: string }, now: Date): Promise<'revoked' | 'already-revoked' | 'unavailable'>;
}

export class InvitationSecretMismatchError extends Error {
  constructor() {
    super('Invitation token secret does not match database configuration');
  }
}

export class ActiveTokenCollisionError extends Error {
  constructor() {
    super('Active invitation token collision');
  }
}

export class TokenGenerationExhaustedError extends Error {
  constructor() {
    super('Could not allocate an invitation token');
  }
}

export class DailyInvitationLimitError extends Error {
  constructor() {
    super('Daily invitation limit reached');
  }
}

export function generateSixDigitToken() {
  return randomInt(TOKEN_LIMIT).toString().padStart(6, '0');
}

export async function createInvitations(
  store: InvitationStore,
  invitations: readonly InvitationCreateData[],
  options: { generateToken?: () => string; now?: () => Date; maxAttempts?: number } = {}
) {
  if (invitations.length === 0) {
    throw new RangeError('At least one invitation is required');
  }

  const now = options.now?.() ?? new Date();
  if (invitations.some((invitation) => invitation.expiresAt.getTime() <= now.getTime())) {
    throw new RangeError('Invitation expiration must be in the future');
  }

  const generateToken = options.generateToken ?? generateSixDigitToken;
  const maxAttempts = options.maxAttempts ?? MAX_TOKEN_ATTEMPTS;

  for (let attempt = 0; attempt < maxAttempts; attempt += 1) {
    const tokens = invitations.map(() => generateToken());
    if (tokens.some((token) => !TOKEN_PATTERN.test(token))) {
      throw new TypeError('Invitation token generator returned an invalid token');
    }

    try {
      const convites = await store.createBatchActive(
        invitations.map((invitation, index) => ({ ...invitation, token: tokens[index]!, now }))
      );
      return convites ? convites.map((convite, index) => ({ convite, token: tokens[index]! })) : null;
    } catch (error) {
      if (!(error instanceof ActiveTokenCollisionError)) {
        throw error;
      }
    }
  }

  throw new TokenGenerationExhaustedError();
}

export async function createInvitation(
  store: InvitationStore,
  data: InvitationCreateData,
  options: { generateToken?: () => string; now?: () => Date; maxAttempts?: number } = {}
) {
  const results = await createInvitations(store, [data], options);
  return results?.[0] ?? null;
}

export function consumeInvitationToken(store: InvitationStore, token: string, now = new Date()) {
  if (!TOKEN_PATTERN.test(token)) {
    return Promise.resolve(false);
  }

  return store.consumeActive(token, now);
}

export function invitationStatus(invitation: Pick<InvitationRecord, 'usedAt' | 'revokedAt' | 'expiresAt'>, now = new Date()) {
  if (invitation.usedAt) return 'used';
  if (invitation.revokedAt) return 'revoked';
  return !invitation.expiresAt || invitation.expiresAt.getTime() <= now.getTime() ? 'expired' : 'active';
}

function isTokenCollision(error: unknown) {
  if (!(error instanceof Prisma.PrismaClientKnownRequestError) || error.code !== 'P2002') {
    return false;
  }

  const target = error.meta?.target;
  return Array.isArray(target)
    ? target.some((field) => String(field).toLowerCase().includes('tokendigest'))
    : String(target).toLowerCase().includes('tokendigest');
}

export function createPrismaInvitationStore(client: PrismaClient, tokenSecret: string): InvitationStore {
  if (Buffer.byteLength(tokenSecret) < 32) {
    throw new Error('Invitation token secret must be at least 32 bytes');
  }

  const digestToken = (token: string) => createHmac('sha256', tokenSecret).update(token).digest('hex');
  const secretFingerprint = createHash('sha256').update(tokenSecret).digest('hex');

  async function verifyTokenSecret(transaction: Prisma.TransactionClient) {
    await transaction.$executeRaw`
      INSERT INTO "SecurityKey" (name, fingerprint)
      VALUES ('invitation-token', ${secretFingerprint})
      ON CONFLICT (name) DO NOTHING
    `;
    const configured = await transaction.$queryRaw<Array<{ fingerprint: string }>>`
      SELECT fingerprint FROM "SecurityKey" WHERE name = 'invitation-token'
    `;
    if (configured[0]?.fingerprint.trim() !== secretFingerprint) {
      throw new InvitationSecretMismatchError();
    }
  }

  async function persistBatch(transaction: Prisma.TransactionClient, allocations: readonly InvitationAllocation[]) {
    await verifyTokenSecret(transaction);
    const withDigests = allocations.map((allocation) => ({
      ...allocation,
      tokenDigest: digestToken(allocation.token)
    }));

    for (const allocation of withDigests) {
      // Terminal, expired, and deleted rows no longer own a candidate digest.
      await transaction.$executeRaw`
        UPDATE "Convite"
        SET "tokenDigest" = NULL
        WHERE "tokenDigest" = ${allocation.tokenDigest}
          AND (
            "expiresAt" <= clock_timestamp()
            OR "usedAt" IS NOT NULL
            OR "revokedAt" IS NOT NULL
            OR "deletedAt" IS NOT NULL
          )
      `;
    }

    const guestIds = allocations.map((allocation) => allocation.convidadoId);
    const first = allocations[0]!;
    const earliestExpiration = new Date(Math.min(...allocations.map((allocation) => allocation.expiresAt.getTime())));
    const activeGuests = await transaction.$queryRaw<Array<{
      id: string;
      residentLimit: number | null;
      condominiumLimit: number | null;
    }>>(Prisma.sql`
      SELECT convidado.id,
             morador."dailyInvitationLimit" AS "residentLimit",
             condominio."dailyInvitationLimit" AS "condominiumLimit"
      FROM "Convidado" AS convidado
      JOIN "Morador" AS morador
        ON morador.id = convidado."moradorId"
       AND morador."condominioId" = convidado."condominioId"
      JOIN "Condominio" AS condominio ON condominio.id = convidado."condominioId"
      WHERE convidado.id IN (${Prisma.join(guestIds)})
        AND convidado."moradorId" = ${first.moradorId}
        AND convidado."condominioId" = ${first.condominioId}
        AND convidado."deletedAt" IS NULL
        AND morador."deletedAt" IS NULL
        AND condominio."deletedAt" IS NULL
        AND ${earliestExpiration} > clock_timestamp()
      ORDER BY convidado.id
      FOR UPDATE OF convidado, morador, condominio
    `);

    if (activeGuests.length !== allocations.length) {
      return null;
    }

    // The resident and condominium locks above serialize all issuance for this resident.
    // A UTC calendar day counts every non-deleted issuance, including used invitations.
    const limit = activeGuests[0]!.residentLimit ?? activeGuests[0]!.condominiumLimit;
    if (limit !== null) {
      const [{ count }] = await transaction.$queryRaw<Array<{ count: bigint }>>`
        SELECT COUNT(*)::bigint AS count
        FROM "Convite"
        WHERE "condominioId" = ${first.condominioId}
          AND "moradorId" = ${first.moradorId}
          AND "deletedAt" IS NULL
          AND "createdAt" >= date_trunc('day', clock_timestamp() AT TIME ZONE 'UTC')
      `;
      if (count + BigInt(allocations.length) > BigInt(limit)) {
        throw new DailyInvitationLimitError();
      }
    }

    const convites: InvitationRecord[] = [];
    for (const allocation of withDigests) {
      convites.push(await transaction.convite.create({
        data: {
          condominioId: allocation.condominioId,
          moradorId: allocation.moradorId,
          convidadoId: allocation.convidadoId,
          tipo: allocation.tipo,
          expiresAt: allocation.expiresAt,
          tokenDigest: allocation.tokenDigest
        }
      }));
    }
    return convites;
  }

  async function inTransaction(allocations: readonly InvitationAllocation[]) {
    try {
      return await client.$transaction((transaction) => persistBatch(transaction, allocations));
    } catch (error) {
      if (isTokenCollision(error)) {
        throw new ActiveTokenCollisionError();
      }
      throw error;
    }
  }

  async function validateActive(token: string, condominiumId: string): Promise<InvitationValidationResult> {
    const tokenDigest = digestToken(token);
    return client.$transaction(async (transaction) => {
      await verifyTokenSecret(transaction);
      const activeInvitations = await transaction.$queryRaw<Array<{
        id: string;
        condominioId: string;
        moradorId: string;
        convidadoId: string;
        tipo: TipoConvite;
        guestName: string;
      }>>`
        SELECT convite.id,
               convite."condominioId",
               convite."moradorId",
               convite."convidadoId",
               convite.tipo,
               convidado.nome AS "guestName"
        FROM "Convite" AS convite
        JOIN "Convidado" AS convidado
          ON convidado.id = convite."convidadoId"
         AND convidado."condominioId" = convite."condominioId"
        JOIN "Morador" AS morador
          ON morador.id = convite."moradorId"
         AND morador."condominioId" = convite."condominioId"
        JOIN "Condominio" AS condominio ON condominio.id = convite."condominioId"
        WHERE convite."tokenDigest" = ${tokenDigest}
          AND convite."condominioId" = ${condominiumId}
          AND convite."deletedAt" IS NULL
          AND convite."usedAt" IS NULL
          AND convite."revokedAt" IS NULL
          AND convite."expiresAt" > clock_timestamp()
          AND convidado."deletedAt" IS NULL
          AND morador."deletedAt" IS NULL
          AND condominio."deletedAt" IS NULL
        FOR UPDATE OF convite, convidado, morador, condominio
      `;

      const invitation = activeInvitations[0];
      if (!invitation) {
        return { allowed: false, reason: 'invalid_or_unavailable' };
      }

      const consumed = await transaction.$queryRaw<Array<{ usedAt: Date }>>`
        UPDATE "Convite"
        SET "tokenDigest" = NULL, "usedAt" = clock_timestamp()
        WHERE id = ${invitation.id}
          AND "tokenDigest" = ${tokenDigest}
          AND "condominioId" = ${condominiumId}
          AND "deletedAt" IS NULL
          AND "usedAt" IS NULL
          AND "revokedAt" IS NULL
          AND "expiresAt" > clock_timestamp()
        RETURNING "usedAt"
      `;
      const usedAt = consumed[0]?.usedAt;
      if (!usedAt) {
        return { allowed: false, reason: 'invalid_or_unavailable' };
      }

      const guestUpdated = await transaction.$executeRaw`
        UPDATE "Convidado"
        SET "ultimoUsoEm" = ${usedAt}
        WHERE id = ${invitation.convidadoId}
          AND "condominioId" = ${condominiumId}
          AND "deletedAt" IS NULL
      `;
      if (guestUpdated !== 1) {
        throw new Error('Invitation guest became unavailable during validation');
      }

      await insertEntryNotification(transaction, {
        invitationId: invitation.id,
        condominiumId,
        residentId: invitation.moradorId,
        guestId: invitation.convidadoId,
        guestName: invitation.guestName,
        enteredAt: usedAt
      });

      return {
        allowed: true,
        guest: { name: invitation.guestName },
        invitation: { type: invitation.tipo },
        event: {
          invitationId: invitation.id,
          condominiumId,
          residentId: invitation.moradorId,
          guestId: invitation.convidadoId,
          invitationType: invitation.tipo,
          usedAt
        }
      };
    });
  }

  return {
    async createActive(data) {
      const records = await inTransaction([data]);
      return records?.[0] ?? null;
    },

    createBatchActive: inTransaction,

    async consumeActive(token) {
      const tokenDigest = digestToken(token);
      return client.$transaction(async (transaction) => {
        await verifyTokenSecret(transaction);
        const activeInvitations = await transaction.$queryRaw<Array<{ id: string }>>`
          SELECT convite.id
          FROM "Convite" AS convite
          JOIN "Convidado" AS convidado
            ON convidado.id = convite."convidadoId"
           AND convidado."condominioId" = convite."condominioId"
          JOIN "Morador" AS morador
            ON morador.id = convite."moradorId"
           AND morador."condominioId" = convite."condominioId"
          JOIN "Condominio" AS condominio ON condominio.id = convite."condominioId"
          WHERE convite."tokenDigest" = ${tokenDigest}
            AND convite."deletedAt" IS NULL
            AND convite."usedAt" IS NULL
            AND convite."revokedAt" IS NULL
            AND convite."expiresAt" > clock_timestamp()
            AND convidado."deletedAt" IS NULL
            AND morador."deletedAt" IS NULL
            AND condominio."deletedAt" IS NULL
          FOR UPDATE OF convite, convidado, morador, condominio
        `;

        const id = activeInvitations[0]?.id;
        if (!id) {
          return false;
        }

        const consumed = await transaction.$executeRaw`
          UPDATE "Convite"
          SET "tokenDigest" = NULL, "usedAt" = clock_timestamp()
          WHERE id = ${id}
            AND "tokenDigest" = ${tokenDigest}
            AND "deletedAt" IS NULL
            AND "usedAt" IS NULL
            AND "revokedAt" IS NULL
            AND "expiresAt" > clock_timestamp()
        `;
        return consumed === 1;
      });
    },

    validateActive({ token, condominiumId }) {
      return validateActive(token, condominiumId);
    },

    async revokeActive({ id, condominioId, moradorId }, _now) {
      return client.$transaction(async (transaction) => {
        const revoked = await transaction.$executeRaw`
          UPDATE "Convite" AS convite
          SET "tokenDigest" = NULL, "revokedAt" = clock_timestamp()
          FROM "Convidado" AS convidado, "Morador" AS morador, "Condominio" AS condominio
          WHERE convite.id = ${id}
            AND convite."condominioId" = ${condominioId}
            AND convite."moradorId" = ${moradorId}
            AND convite."convidadoId" = convidado.id
            AND convidado."condominioId" = convite."condominioId"
            AND morador.id = convite."moradorId"
            AND morador."condominioId" = convite."condominioId"
            AND condominio.id = convite."condominioId"
            AND convite."deletedAt" IS NULL
            AND convite."usedAt" IS NULL
            AND convite."revokedAt" IS NULL
            AND convite."expiresAt" > clock_timestamp()
            AND convidado."deletedAt" IS NULL
            AND morador."deletedAt" IS NULL
            AND condominio."deletedAt" IS NULL
        `;
        if (revoked === 1) return 'revoked';

        const alreadyRevoked = await transaction.$queryRaw<Array<{ id: string }>>`
          SELECT convite.id
          FROM "Convite" AS convite
          JOIN "Convidado" AS convidado
            ON convidado.id = convite."convidadoId"
           AND convidado."condominioId" = convite."condominioId"
          JOIN "Morador" AS morador
            ON morador.id = convite."moradorId"
           AND morador."condominioId" = convite."condominioId"
          JOIN "Condominio" AS condominio ON condominio.id = convite."condominioId"
          WHERE convite.id = ${id}
            AND convite."condominioId" = ${condominioId}
            AND convite."moradorId" = ${moradorId}
            AND convite."deletedAt" IS NULL
            AND convite."revokedAt" IS NOT NULL
            AND convidado."deletedAt" IS NULL
            AND morador."deletedAt" IS NULL
            AND condominio."deletedAt" IS NULL
        `;
        return alreadyRevoked.length === 1 ? 'already-revoked' : 'unavailable';
      });
    }
  };
}

type ConvitesStore = Pick<AppStore, 'condominio' | 'morador' | 'convidado'>;
const activeCondominio = { deletedAt: null } as const;
const activeGuestParents = {
  condominio: activeCondominio,
  morador: { is: { deletedAt: null } }
} as const;

function parseUuidParam(params: unknown, field: string) {
  if (!params || typeof params !== 'object' || Array.isArray(params)) {
    return null;
  }

  const value = (params as Record<string, unknown>)[field];
  return isUuid(value) ? value : null;
}

function parseInvitationBody(body: unknown) {
  if (!body || typeof body !== 'object' || Array.isArray(body)) {
    return null;
  }

  const payload = body as Record<string, unknown>;
  const tipo = INVITATION_TYPES.find((candidate) => candidate === payload.tipo);
  const isTimestamp = typeof payload.expiresAt === 'string'
    && /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,3})?(?:Z|[+-]\d{2}:\d{2})$/.test(payload.expiresAt);
  const expiresAt = isTimestamp ? new Date(payload.expiresAt as string) : null;
  if (!tipo || !expiresAt || Number.isNaN(expiresAt.getTime())) {
    return null;
  }

  return { tipo, expiresAt };
}

function parseGuestIds(body: unknown) {
  if (!body || typeof body !== 'object' || Array.isArray(body)) {
    return null;
  }

  const convidadoIds = (body as Record<string, unknown>).convidadoIds;
  if (!Array.isArray(convidadoIds) || convidadoIds.length === 0 || !convidadoIds.every(isUuid)) {
    return null;
  }

  return convidadoIds;
}

function parseValidationToken(body: unknown) {
  if (!body || typeof body !== 'object' || Array.isArray(body)) {
    return null;
  }

  const payload = body as Record<string, unknown>;
  const keys = Object.keys(payload);
  return keys.length === 1 && keys[0] === 'token' && typeof payload.token === 'string' && TOKEN_PATTERN.test(payload.token)
    ? payload.token
    : null;
}

function invitationResponse(convite: InvitationRecord, token: string) {
  return {
    id: convite.id,
    createdAt: convite.createdAt.toISOString(),
    condominioId: convite.condominioId,
    moradorId: convite.moradorId,
    convidadoId: convite.convidadoId,
    tipo: convite.tipo,
    expiresAt: convite.expiresAt?.toISOString() ?? null,
    token
  };
}

export function registerConviteRoutes(
  app: FastifyInstance,
  db: ConvitesStore,
  store: InvitationStore | undefined,
  authenticator: Authenticator,
  notifications: NotificationSender = createUnavailableNotificationSender()
) {
  const singlePath = '/condominios/:condominioId/moradores/:moradorId/convidados/:convidadoId/convites';
  const batchPath = '/condominios/:condominioId/moradores/:moradorId/convites/multiplos';
  const revokePath = '/condominios/:condominioId/moradores/:moradorId/convites/:conviteId';
  const validationPath = '/portaria/convites/validar';
  const management = {
    preHandler: authorize(
      authenticator,
      'convites:create',
      (request) => parseUuidParam(request.params, 'condominioId'),
      (request) => parseUuidParam(request.params, 'moradorId')
    )
  };

  app.post(validationPath, {
    onRequest: async (_request, reply) => {
      reply.header('cache-control', 'no-store');
      reply.header('pragma', 'no-cache');
      reply.header('expires', '0');
    },
    preHandler: authorize(authenticator, 'convites:validate')
  }, async (request, reply) => {
    const identity = request.authenticatedIdentity;
    const condominiumId = identity?.role === 'portaria' && identity.condominioIds.length === 1
      ? identity.condominioIds[0]
      : null;
    if (!condominiumId) {
      return reply.status(403).send({ error: 'Forbidden' });
    }

    const token = parseValidationToken(request.body);
    if (!token) {
      return { allowed: false, reason: 'invalid_or_unavailable' };
    }
    if (!store) {
      return reply.status(503).send({ allowed: false, reason: 'service_unavailable' });
    }

    try {
      const result = await store.validateActive({ token, condominiumId }, new Date());
      return result.allowed
        ? { allowed: true, guest: result.guest, invitation: result.invitation }
        : result;
    } catch (error) {
      if (error instanceof InvitationSecretMismatchError) {
        return reply.status(503).send({ allowed: false, reason: 'service_unavailable' });
      }
      throw error;
    }
  });

  app.post(singlePath, management, async (request, reply) => {
    const condominioId = parseUuidParam(request.params, 'condominioId');
    const moradorId = parseUuidParam(request.params, 'moradorId');
    const convidadoId = parseUuidParam(request.params, 'convidadoId');
    const body = parseInvitationBody(request.body);
    if (!condominioId || !moradorId || !convidadoId || !body) {
      return reply.status(400).send({ error: 'Invalid invitation payload' });
    }

    if (!store) {
      return reply.status(503).send({ error: 'Invitation service unavailable' });
    }

    const [condominio, morador, convidado] = await Promise.all([
      db.condominio.findFirst({ where: { id: condominioId, deletedAt: null } }),
      db.morador.findFirst({
        where: { id: moradorId, condominioId, deletedAt: null, condominio: activeCondominio }
      }),
      db.convidado.findFirst({
        where: { id: convidadoId, condominioId, moradorId, deletedAt: null, ...activeGuestParents }
      })
    ]);
    if (!condominio || !morador || !convidado) {
      return reply.status(404).send({ error: 'Guest not found' });
    }

    try {
      const result = await createInvitation(store, { condominioId, moradorId, convidadoId, ...body });
      if (!result) return reply.status(404).send({ error: 'Guest not found' });
      const message = invitationMessage({
        condominiumName: condominio.nome,
        residentName: morador.nome,
        generatedAt: result.convite.createdAt,
        expiresAt: result.convite.expiresAt ?? body.expiresAt,
        token: result.token
      });
      try {
        if (convidado.email) await notifications.email.send(convidado.email, message);
        if (convidado.telefone) await notifications.sms.send(convidado.telefone, message.body);
      } catch {
        return reply.header('cache-control', 'no-store').status(502).send({ error: 'Invitation created but notification delivery failed', invitationId: result.convite.id });
      }
      return reply.header('cache-control', 'no-store').status(201).send(invitationResponse(result.convite, result.token));
    } catch (error) {
      if (error instanceof RangeError) {
        return reply.status(400).send({ error: 'Invitation expiration must be in the future' });
      }
      if (error instanceof TokenGenerationExhaustedError) {
        return reply.status(503).send({ error: 'Invitation token unavailable' });
      }
      if (error instanceof DailyInvitationLimitError) {
        return reply.status(429).send({ error: 'Daily invitation limit reached' });
      }
      throw error;
    }
  });

  app.post(batchPath, management, async (request, reply) => {
    const condominioId = parseUuidParam(request.params, 'condominioId');
    const moradorId = parseUuidParam(request.params, 'moradorId');
    const convidadoIds = parseGuestIds(request.body);
    if (!condominioId || !moradorId || !convidadoIds) {
      return reply.status(400).send({ error: 'Invalid batch invitation payload' });
    }
    if (new Set(convidadoIds).size !== convidadoIds.length) {
      return reply.status(400).send({ error: 'Guest ids must be unique' });
    }
    if (!store) {
      return reply.status(503).send({ error: 'Invitation service unavailable' });
    }

    const morador = await db.morador.findFirst({
      where: { id: moradorId, condominioId, deletedAt: null, condominio: activeCondominio }
    });
    if (!morador) {
      return reply.status(404).send({ error: 'Resident not found' });
    }

    for (const convidadoId of convidadoIds) {
      const convidado = await db.convidado.findFirst({
        where: { id: convidadoId, condominioId, moradorId, deletedAt: null, ...activeGuestParents }
      });
      if (!convidado) {
        return reply.status(404).send({ error: `Guest is not active or owned by resident: ${convidadoId}` });
      }
    }

    try {
      const expiresAt = new Date(Date.now() + BATCH_EXPIRATION_MS);
      const results = await createInvitations(
        store,
        convidadoIds.map((convidadoId) => ({
          condominioId,
          moradorId,
          convidadoId,
          tipo: 'visitante',
          expiresAt
        }))
      );
      if (!results) {
        return reply.status(404).send({ error: 'One or more guests are no longer active or owned by resident' });
      }

      return reply.header('cache-control', 'no-store').status(201).send({
        convites: results.map(({ convite, token }) => ({
          id: convite.id,
          convidadoId: convite.convidadoId,
          token,
          expiraEm: convite.expiresAt?.toISOString() ?? expiresAt.toISOString()
        }))
      });
    } catch (error) {
      if (error instanceof TokenGenerationExhaustedError) {
        return reply.status(503).send({ error: 'Invitation token unavailable' });
      }
      if (error instanceof DailyInvitationLimitError) {
        return reply.status(429).send({ error: 'Daily invitation limit reached' });
      }
      throw error;
    }
  });

  app.delete(revokePath, management, async (request, reply) => {
    const condominioId = parseUuidParam(request.params, 'condominioId');
    const moradorId = parseUuidParam(request.params, 'moradorId');
    const conviteId = parseUuidParam(request.params, 'conviteId');
    if (!condominioId || !moradorId || !conviteId) {
      return reply.status(400).send({ error: 'Invalid invitation id' });
    }
    if (!store) {
      return reply.status(503).send({ error: 'Invitation service unavailable' });
    }

    const result = await store.revokeActive({ id: conviteId, condominioId, moradorId }, new Date());
    return result === 'unavailable'
      ? reply.status(404).send({ error: 'Active invitation not found' })
      : reply.status(204).send();
  });
}
