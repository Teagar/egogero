import { createHash, createHmac, randomInt } from 'node:crypto';

import { Prisma, type PrismaClient, type TipoConvite } from '@prisma/client';
import type { FastifyInstance } from 'fastify';

import { authorize, isUuid } from './auth.js';
import type { Authenticator } from './auth.js';

export const INVITATION_TYPES = ['visitante', 'prestador', 'entregador'] as const satisfies readonly TipoConvite[];
const TOKEN_PATTERN = /^[0-9]{6}$/;
const TOKEN_LIMIT = 1_000_000;
const MAX_TOKEN_ATTEMPTS = 32;

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
  tokenDigest: string | null;
};

export type InvitationCreateData = {
  condominioId: string;
  moradorId: string;
  convidadoId: string;
  tipo: TipoConvite;
  expiresAt: Date;
};

export interface InvitationStore {
  createActive(args: InvitationCreateData & { token: string; now: Date }): Promise<InvitationRecord | null>;
  consumeActive(token: string, now: Date): Promise<boolean>;
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

export function generateSixDigitToken() {
  return randomInt(TOKEN_LIMIT).toString().padStart(6, '0');
}

export async function createInvitation(
  store: InvitationStore,
  data: InvitationCreateData,
  options: { generateToken?: () => string; now?: () => Date; maxAttempts?: number } = {}
) {
  const now = options.now?.() ?? new Date();
  if (data.expiresAt.getTime() <= now.getTime()) {
    throw new RangeError('Invitation expiration must be in the future');
  }

  const generateToken = options.generateToken ?? generateSixDigitToken;
  const maxAttempts = options.maxAttempts ?? MAX_TOKEN_ATTEMPTS;

  for (let attempt = 0; attempt < maxAttempts; attempt += 1) {
    const token = generateToken();
    if (!TOKEN_PATTERN.test(token)) {
      throw new TypeError('Invitation token generator returned an invalid token');
    }

    try {
      const convite = await store.createActive({ ...data, token, now });
      return convite ? { convite, token } : null;
    } catch (error) {
      if (!(error instanceof ActiveTokenCollisionError)) {
        throw error;
      }
    }
  }

  throw new TokenGenerationExhaustedError();
}

export function consumeInvitationToken(store: InvitationStore, token: string, now = new Date()) {
  if (!TOKEN_PATTERN.test(token)) {
    return Promise.resolve(false);
  }

  return store.consumeActive(token, now);
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
      throw new Error('Invitation token secret does not match database configuration');
    }
  }

  return {
    async createActive(data) {
      const tokenDigest = digestToken(data.token);
      try {
        return await client.$transaction(async (transaction) => {
          await verifyTokenSecret(transaction);
          // Expired/consumed rows no longer own the candidate. The unique index arbitrates races.
          await transaction.$executeRaw`
            UPDATE "Convite"
            SET "tokenDigest" = NULL
            WHERE "tokenDigest" = ${tokenDigest}
              AND (
                "expiresAt" <= clock_timestamp()
                OR "usedAt" IS NOT NULL
                OR "deletedAt" IS NOT NULL
              )
          `;

          // Parent row locks keep tenant ownership active through insertion.
          const activeGuests = await transaction.$queryRaw<Array<{ id: string }>>`
            SELECT convidado.id
            FROM "Convidado" AS convidado
            JOIN "Morador" AS morador
              ON morador.id = convidado."moradorId"
             AND morador."condominioId" = convidado."condominioId"
            JOIN "Condominio" AS condominio ON condominio.id = convidado."condominioId"
            WHERE convidado.id = ${data.convidadoId}
              AND convidado."moradorId" = ${data.moradorId}
              AND convidado."condominioId" = ${data.condominioId}
              AND convidado."deletedAt" IS NULL
              AND morador."deletedAt" IS NULL
              AND condominio."deletedAt" IS NULL
              AND ${data.expiresAt} > clock_timestamp()
            FOR UPDATE OF convidado, morador, condominio
          `;

          if (activeGuests.length === 0) {
            return null;
          }

          return transaction.convite.create({
            data: {
              condominioId: data.condominioId,
              moradorId: data.moradorId,
              convidadoId: data.convidadoId,
              tipo: data.tipo,
              expiresAt: data.expiresAt,
              tokenDigest
            }
          });
        });
      } catch (error) {
        if (isTokenCollision(error)) {
          throw new ActiveTokenCollisionError();
        }

        throw error;
      }
    },

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
            AND "expiresAt" > clock_timestamp()
        `;
        return consumed === 1;
      });
    }
  };
}

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
  store: InvitationStore | undefined,
  authenticator: Authenticator
) {
  const path = '/condominios/:condominioId/moradores/:moradorId/convidados/:convidadoId/convites';
  const management = {
    preHandler: authorize(
      authenticator,
      'convites:create',
      (request) => parseUuidParam(request.params, 'condominioId'),
      (request) => parseUuidParam(request.params, 'moradorId')
    )
  };

  app.post(path, management, async (request, reply) => {
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

    try {
      const result = await createInvitation(store, { condominioId, moradorId, convidadoId, ...body });
      return result
        ? reply.header('cache-control', 'no-store').status(201).send(invitationResponse(result.convite, result.token))
        : reply.status(404).send({ error: 'Guest not found' });
    } catch (error) {
      if (error instanceof RangeError) {
        return reply.status(400).send({ error: 'Invitation expiration must be in the future' });
      }
      if (error instanceof TokenGenerationExhaustedError) {
        return reply.status(503).send({ error: 'Invitation token unavailable' });
      }
      throw error;
    }
  });
}
