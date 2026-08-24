import { createHash, createHmac, randomInt } from 'node:crypto';

import { Prisma, type PrismaClient, type TipoConvite } from '@prisma/client';
import type { FastifyInstance } from 'fastify';

import type { AppStore } from './app.js';
import { authorize, isUuid } from './auth.js';
import type { Authenticator } from './auth.js';

export const INVITATION_TYPES = ['visitante', 'prestador', 'entregador'] as const satisfies readonly TipoConvite[];
const TOKEN_PATTERN = /^[0-9]{6}$/;
const TOKEN_LIMIT = 1_000_000;
const MAX_TOKEN_ATTEMPTS = 32;
const BATCH_EXPIRATION_MS = 24 * 60 * 60 * 1000;

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

export type InvitationAllocation = InvitationCreateData & { token: string; now: Date };

export interface InvitationStore {
  createActive(args: InvitationAllocation): Promise<InvitationRecord | null>;
  createBatchActive(args: readonly InvitationAllocation[]): Promise<readonly InvitationRecord[] | null>;
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

  async function persistBatch(transaction: Prisma.TransactionClient, allocations: readonly InvitationAllocation[]) {
    await verifyTokenSecret(transaction);
    const withDigests = allocations.map((allocation) => ({
      ...allocation,
      tokenDigest: digestToken(allocation.token)
    }));

    for (const allocation of withDigests) {
      // Expired, consumed, and deleted rows no longer own a candidate digest.
      await transaction.$executeRaw`
        UPDATE "Convite"
        SET "tokenDigest" = NULL
        WHERE "tokenDigest" = ${allocation.tokenDigest}
          AND (
            "expiresAt" <= clock_timestamp()
            OR "usedAt" IS NOT NULL
            OR "deletedAt" IS NOT NULL
          )
      `;
    }

    const guestIds = allocations.map((allocation) => allocation.convidadoId);
    const first = allocations[0]!;
    const earliestExpiration = new Date(Math.min(...allocations.map((allocation) => allocation.expiresAt.getTime())));
    const activeGuests = await transaction.$queryRaw<Array<{ id: string }>>(Prisma.sql`
      SELECT convidado.id
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

type ConvitesStore = Pick<AppStore, 'morador' | 'convidado'>;
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
  authenticator: Authenticator
) {
  const singlePath = '/condominios/:condominioId/moradores/:moradorId/convidados/:convidadoId/convites';
  const batchPath = '/condominios/:condominioId/moradores/:moradorId/convites/multiplos';
  const management = {
    preHandler: authorize(
      authenticator,
      'convites:create',
      (request) => parseUuidParam(request.params, 'condominioId'),
      (request) => parseUuidParam(request.params, 'moradorId')
    )
  };

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
      throw error;
    }
  });
}
