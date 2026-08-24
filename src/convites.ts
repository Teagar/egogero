import {
  createCipheriv,
  createDecipheriv,
  createHash,
  createHmac,
  randomBytes,
  randomInt,
  randomUUID
} from 'node:crypto';

import { Prisma, type PrismaClient, type TipoConvite } from '@prisma/client';
import type { FastifyInstance } from 'fastify';
import QRCode from 'qrcode';

import type { AppStore } from './app.js';
import { authorize, isUuid } from './auth.js';
import type { Authenticator } from './auth.js';
import { createMemoryDeviceRateLimiter, DEVICE_RATE_LIMIT } from './dispositivos.js';
import type { DeviceRateLimiter } from './dispositivos.js';
import { insertEntryNotification } from './notificacoes.js';

export const INVITATION_TYPES = ['visitante', 'prestador', 'entregador'] as const satisfies readonly TipoConvite[];
export const ACCESS_TYPES = ['pedestre', 'veiculo'] as const;
export type AccessType = (typeof ACCESS_TYPES)[number];
const TOKEN_PATTERN = /^[0-9]{6}$/;
const TOKEN_LIMIT = 1_000_000;
const MAX_TOKEN_ATTEMPTS = 32;
const BATCH_EXPIRATION_MS = 24 * 60 * 60 * 1000;
const MAX_BATCH_SIZE = 100;
const IDEMPOTENCY_KEY_PATTERN = /^[A-Za-z0-9._:-]{16,128}$/;
const IDEMPOTENCY_KEY_VERSION = 1;

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
function formatDate(date: Date, timeZone: string) {
  return new Intl.DateTimeFormat('pt-BR', { dateStyle: 'short', timeZone }).format(date);
}

function formatTime(date: Date, timeZone: string) {
  return new Intl.DateTimeFormat('pt-BR', {
    hour: '2-digit',
    hour12: false,
    minute: '2-digit',
    timeZone
  }).format(date);
}

export function invitationMessage(input: {
  condominiumName: string;
  residentName: string;
  generatedAt: Date;
  expiresAt: Date;
  token: string;
  timeZone: string;
}): InvitationMessage {
  return {
    subject: `Convite de acesso ao condomínio ${input.condominiumName}`,
    body: `Seu código para a entrada no condomínio ${input.condominiumName} foi gerado por ${input.residentName} às ${formatTime(input.generatedAt, input.timeZone)} do dia ${formatDate(input.generatedAt, input.timeZone)} e será expirado em ${formatDate(input.expiresAt, input.timeZone)} às ${formatTime(input.expiresAt, input.timeZone)}.\nSeu código é: ${input.token}`
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

export type AccessAuditRecord = {
  id: string;
  createdAt: Date;
  condominiumId: string;
  deviceId: string;
  invitationId: string | null;
  residentId: string | null;
  guestId: string | null;
  accessType: AccessType;
  result: 'permitido' | 'negado';
};

export interface InvitationStore {
  createActive(args: InvitationAllocation): Promise<InvitationRecord | null>;
  createBatchActive(args: readonly InvitationAllocation[]): Promise<readonly InvitationRecord[] | null>;
  validateActive(args: {
    token: string | null;
    condominiumId: string;
    deviceId: string;
    accessType: AccessType;
    requireActiveDevice?: boolean;
  }, now: Date): Promise<InvitationValidationResult>;
  listOwnedAudits(args: {
    condominiumId: string;
    residentId: string;
    cursor: string | null;
    limit: number;
  }): Promise<readonly AccessAuditRecord[]>;
  revokeActive(args: { id: string; condominioId: string; moradorId: string }, now: Date): Promise<'revoked' | 'already-revoked' | 'unavailable'>;
  issueIdempotent?(args: IdempotentInvitationIssue): Promise<IdempotentInvitationResult | null>;
  verifyIdempotencyConfiguration?(): Promise<void>;
}

export type IdempotentInvitationIssue = {
  key: string;
  actorId: string;
  condominioId: string;
  method: 'POST';
  route: string;
  requestHash: string;
  invitations: readonly InvitationCreateData[];
  buildResponse(results: readonly { convite: InvitationRecord; token: string }[]): Promise<unknown>;
};

export type IdempotentInvitationResult = {
  statusCode: number;
  responseText: string;
  replayed: boolean;
};

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

export class IdempotencyConflictError extends Error {
  constructor() {
    super('Idempotency key was already used with a different request');
  }
}

export class IdempotencySecretMismatchError extends Error {
  constructor() {
    super('Idempotency cache secret does not match database configuration');
  }
}

export function parseIdempotencyKey(value: string | string[] | undefined) {
  return typeof value === 'string' && IDEMPOTENCY_KEY_PATTERN.test(value) ? value : null;
}

function canonicalJson(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  if (value && typeof value === 'object') {
    return `{${Object.entries(value as Record<string, unknown>)
      .filter(([, item]) => item !== undefined)
      .sort(([left], [right]) => left.localeCompare(right))
      .map(([key, item]) => `${JSON.stringify(key)}:${canonicalJson(item)}`)
      .join(',')}}`;
  }
  return JSON.stringify(value);
}

export function canonicalRequestHash(body: unknown) {
  return createHash('sha256').update(canonicalJson(body)).digest('hex');
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

export function createPrismaInvitationStore(
  client: PrismaClient,
  tokenSecret: string,
  idempotencySecret?: string,
  idempotencyTtlMs = 24 * 60 * 60 * 1000
): InvitationStore {
  if (Buffer.byteLength(tokenSecret) < 32) {
    throw new Error('Invitation token secret must be at least 32 bytes');
  }

  const digestToken = (token: string) => createHmac('sha256', tokenSecret).update(token).digest('hex');
  const secretFingerprint = createHash('sha256').update(tokenSecret).digest('hex');
  const idempotencyKey = idempotencySecret ? createHash('sha256').update(idempotencySecret).digest() : null;
  const idempotencyFingerprint = idempotencySecret
    ? createHash('sha256').update(`idempotency-cache:${idempotencySecret}`).digest('hex')
    : null;

  if (idempotencySecret !== undefined && Buffer.byteLength(idempotencySecret) < 32) {
    throw new Error('Idempotency cache secret must be at least 32 bytes');
  }
  if (!Number.isSafeInteger(idempotencyTtlMs) || idempotencyTtlMs <= 0) {
    throw new Error('Idempotency TTL must be a positive integer');
  }

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

  async function verifyIdempotencySecret(transaction: Prisma.TransactionClient) {
    if (!idempotencyFingerprint || !idempotencyKey || !idempotencySecret) {
      throw new IdempotencySecretMismatchError();
    }
    await transaction.$executeRaw`
      INSERT INTO "SecurityKey" (name, fingerprint)
      VALUES ('idempotency-cache-v1', ${idempotencyFingerprint})
      ON CONFLICT (name) DO NOTHING
    `;
    const configured = await transaction.$queryRaw<Array<{ fingerprint: string }>>`
      SELECT fingerprint FROM "SecurityKey" WHERE name = 'idempotency-cache-v1'
    `;
    if (configured[0]?.fingerprint.trim() !== idempotencyFingerprint) {
      throw new IdempotencySecretMismatchError();
    }
  }

  function encryptProtected(plaintext: string, aad: string) {
    if (!idempotencyKey) throw new IdempotencySecretMismatchError();
    const iv = randomBytes(12);
    const cipher = createCipheriv('aes-256-gcm', idempotencyKey, iv);
    cipher.setAAD(Buffer.from(aad));
    return {
      ciphertext: Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]),
      iv,
      authTag: cipher.getAuthTag()
    };
  }

  function decryptProtected(ciphertext: Buffer, iv: Buffer, authTag: Buffer, aad: string) {
    if (!idempotencyKey) throw new IdempotencySecretMismatchError();
    try {
      const decipher = createDecipheriv('aes-256-gcm', idempotencyKey, iv);
      decipher.setAAD(Buffer.from(aad));
      decipher.setAuthTag(authTag);
      return Buffer.concat([decipher.update(ciphertext), decipher.final()]).toString('utf8');
    } catch {
      throw new IdempotencySecretMismatchError();
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
      timezone: string;
    }>>(Prisma.sql`
      SELECT convidado.id,
             morador."dailyInvitationLimit" AS "residentLimit",
             condominio."dailyInvitationLimit" AS "condominiumLimit",
             condominio.timezone
      FROM "Convidado" AS convidado
      JOIN "Morador" AS morador
        ON morador.id = convidado."moradorId"
       AND morador."condominioId" = convidado."condominioId"
      JOIN "Condominio" AS condominio ON condominio.id = convidado."condominioId"
      WHERE convidado.id IN (${Prisma.join(guestIds)})
        AND convidado."moradorId" = ${first.moradorId}
        AND convidado."condominioId" = ${first.condominioId}
        AND convidado."deletedAt" IS NULL
        AND convidado."anonymizedAt" IS NULL
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
    // Local civil-day boundaries are converted to absolute instants; PostgreSQL resolves DST gaps/overlaps deterministically.
    const limit = activeGuests[0]!.residentLimit ?? activeGuests[0]!.condominiumLimit;
    if (limit !== null) {
      const [{ count }] = await transaction.$queryRaw<Array<{ count: bigint }>>`
        SELECT COUNT(*)::bigint AS count
        FROM "Convite"
        WHERE "condominioId" = ${first.condominioId}
          AND "moradorId" = ${first.moradorId}
          AND "deletedAt" IS NULL
          AND "createdAt" >= (((clock_timestamp() AT TIME ZONE ${activeGuests[0]!.timezone})::date)::timestamp AT TIME ZONE ${activeGuests[0]!.timezone})
          AND "createdAt" < ((((clock_timestamp() AT TIME ZONE ${activeGuests[0]!.timezone})::date + 1)::timestamp) AT TIME ZONE ${activeGuests[0]!.timezone})
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

  async function issueIdempotent(args: IdempotentInvitationIssue): Promise<IdempotentInvitationResult | null> {
    if (!idempotencySecret || !idempotencyKey || !idempotencyFingerprint) {
      throw new IdempotencySecretMismatchError();
    }
    if (args.invitations.length === 0) throw new RangeError('At least one invitation is required');
    const keyDigest = createHmac('sha256', idempotencySecret).update(args.key).digest('hex');

    for (let attempt = 0; attempt < MAX_TOKEN_ATTEMPTS; attempt += 1) {
      const now = new Date();
      if (args.invitations.some((invitation) => invitation.expiresAt.getTime() <= now.getTime())) {
        throw new RangeError('Invitation expiration must be in the future');
      }
      const allocations = args.invitations.map((invitation) => ({
        ...invitation,
        token: generateSixDigitToken(),
        now
      }));
      try {
        return await client.$transaction(async (transaction) => {
          await verifyIdempotencySecret(transaction);
          await transaction.$executeRaw`
            DELETE FROM "IdempotencyRecord"
            WHERE "actorId" = ${args.actorId}
              AND "condominioId" = ${args.condominioId}
              AND method = ${args.method}
              AND route = ${args.route}
              AND "keyDigest" = ${keyDigest}
              AND "confirmedAt" IS NOT NULL
              AND "expiresAt" <= clock_timestamp()
          `;

          const recordId = randomUUID();
          const inserted = await transaction.$queryRaw<Array<{ id: string }>>`
            INSERT INTO "IdempotencyRecord" (
              id, "actorId", "condominioId", method, route, "keyDigest", "requestHash", "keyVersion"
            ) VALUES (
              ${recordId}::uuid, ${args.actorId}, ${args.condominioId}, ${args.method}, ${args.route},
              ${keyDigest}, ${args.requestHash}, ${IDEMPOTENCY_KEY_VERSION}
            )
            ON CONFLICT ("actorId", "condominioId", method, route, "keyDigest") DO NOTHING
            RETURNING id
          `;

          if (inserted.length === 0) {
            const existing = await transaction.$queryRaw<Array<{
              id: string;
              requestHash: string;
              responseStatus: number | null;
              responseCiphertext: Buffer | null;
              responseIv: Buffer | null;
              responseAuthTag: Buffer | null;
              keyVersion: number;
            }>>`
              SELECT id, "requestHash", "responseStatus", "responseCiphertext",
                     "responseIv", "responseAuthTag", "keyVersion"
              FROM "IdempotencyRecord"
              WHERE "actorId" = ${args.actorId}
                AND "condominioId" = ${args.condominioId}
                AND method = ${args.method}
                AND route = ${args.route}
                AND "keyDigest" = ${keyDigest}
            `;
            const replay = existing[0];
            if (!replay || replay.requestHash.trim() !== args.requestHash) {
              throw new IdempotencyConflictError();
            }
            if (replay.keyVersion !== IDEMPOTENCY_KEY_VERSION || replay.responseStatus === null
              || !replay.responseCiphertext || !replay.responseIv || !replay.responseAuthTag) {
              throw new IdempotencySecretMismatchError();
            }
            return {
              statusCode: replay.responseStatus,
              responseText: decryptProtected(
                replay.responseCiphertext,
                replay.responseIv,
                replay.responseAuthTag,
                `idempotency:${replay.id}:v${replay.keyVersion}`
              ),
              replayed: true
            };
          }

          const convites = await persistBatch(transaction, allocations);
          if (!convites) return null;
          const results = convites.map((convite, index) => ({ convite, token: allocations[index]!.token }));
          const responseText = JSON.stringify(await args.buildResponse(results));

          const rows = await transaction.$queryRaw<Array<{
            conviteId: string;
            condominioId: string;
            createdAt: Date;
            expiresAt: Date;
            email: string | null;
            telefone: string | null;
            condominiumName: string;
            residentName: string;
            timezone: string;
          }>>(Prisma.sql`
            SELECT convite.id AS "conviteId", convite."condominioId", convite."createdAt", convite."expiresAt",
                   convidado.email, convidado.telefone, condominio.nome AS "condominiumName",
                   morador.nome AS "residentName", condominio.timezone
            FROM "Convite" AS convite
            JOIN "Convidado" AS convidado
              ON convidado.id = convite."convidadoId" AND convidado."condominioId" = convite."condominioId"
            JOIN "Morador" AS morador
              ON morador.id = convite."moradorId" AND morador."condominioId" = convite."condominioId"
            JOIN "Condominio" AS condominio ON condominio.id = convite."condominioId"
            WHERE convite.id IN (${Prisma.join(convites.map((convite) => convite.id))})
          `);

          for (const row of rows) {
            const token = results.find((result) => result.convite.id === row.conviteId)!.token;
            const message = invitationMessage({
              condominiumName: row.condominiumName,
              residentName: row.residentName,
              generatedAt: row.createdAt,
              expiresAt: row.expiresAt,
              token,
              timeZone: row.timezone
            });
            const channels = [
              ...(row.email ? [{ channel: 'email' as const, to: row.email, content: message }] : []),
              ...(row.telefone ? [{ channel: 'sms' as const, to: row.telefone, content: { body: message.body } }] : [])
            ];
            for (const delivery of channels) {
              const intentId = randomUUID();
              const protectedPayload = encryptProtected(
                JSON.stringify({ intentId, invitationId: row.conviteId, to: delivery.to, ...delivery.content }),
                `delivery:${intentId}:${row.conviteId}:${delivery.channel}:v${IDEMPOTENCY_KEY_VERSION}`
              );
              await transaction.$executeRaw`
                INSERT INTO "DeliveryIntent" (
                  id, "conviteId", "condominioId", channel, "payloadCiphertext", "payloadIv",
                  "payloadAuthTag", "keyVersion"
                ) VALUES (
                  ${intentId}::uuid, ${row.conviteId}, ${row.condominioId}, ${delivery.channel}::"DeliveryChannel",
                  ${protectedPayload.ciphertext}, ${protectedPayload.iv}, ${protectedPayload.authTag},
                  ${IDEMPOTENCY_KEY_VERSION}
                )
                ON CONFLICT ("conviteId", channel) DO NOTHING
              `;
            }
          }

          const protectedResponse = encryptProtected(
            responseText,
            `idempotency:${recordId}:v${IDEMPOTENCY_KEY_VERSION}`
          );
          const confirmed = await transaction.$executeRaw`
            UPDATE "IdempotencyRecord"
            SET "confirmedAt" = clock_timestamp(),
                "expiresAt" = clock_timestamp() + (${idempotencyTtlMs} * interval '1 millisecond'),
                "responseStatus" = 201,
                "responseCiphertext" = ${protectedResponse.ciphertext},
                "responseIv" = ${protectedResponse.iv},
                "responseAuthTag" = ${protectedResponse.authTag}
            WHERE id = ${recordId}::uuid AND "confirmedAt" IS NULL
          `;
          if (confirmed !== 1) throw new Error('Could not confirm idempotent invitation response');
          return { statusCode: 201, responseText, replayed: false };
        });
      } catch (error) {
        if (!isTokenCollision(error)) throw error;
      }
    }
    throw new TokenGenerationExhaustedError();
  }

  async function validateActive(args: {
    token: string | null;
    condominiumId: string;
    deviceId: string;
    accessType: AccessType;
    requireActiveDevice?: boolean;
  }): Promise<InvitationValidationResult> {
    return client.$transaction(async (transaction) => {
      const insertAudit = async (
        result: 'permitido' | 'negado',
        identified?: { id: string; condominioId: string; moradorId: string | null; convidadoId: string | null },
        createdAt?: Date
      ) => {
        const auditTime = createdAt ?? new Date();
        await transaction.$executeRaw`
          INSERT INTO "AuditoriaAcesso" (
            id, "createdAt", "condominioId", "dispositivoId", "conviteId",
            "moradorId", "convidadoId", "tipoAcesso", resultado
          ) VALUES (
            ${randomUUID()}, ${auditTime}, ${args.condominiumId}, ${args.deviceId}, ${identified?.id ?? null},
            ${identified?.moradorId ?? null}, ${identified?.convidadoId ?? null},
            ${args.accessType}::"TipoAcesso", ${result}::"ResultadoAcesso"
          )
        `;
      };

      if (args.requireActiveDevice) {
        const activeDevices = await transaction.$queryRaw<Array<{ id: string }>>`
          SELECT dispositivo.id
          FROM "Dispositivo" AS dispositivo
          JOIN "Condominio" AS condominio ON condominio.id = dispositivo."condominioId"
          WHERE dispositivo.id = ${args.deviceId}
            AND dispositivo."condominioId" = ${args.condominiumId}
            AND dispositivo.status = 'ativo'
            AND dispositivo."apiKeyDigest" IS NOT NULL
            AND dispositivo."deletedAt" IS NULL
            AND condominio."deletedAt" IS NULL
          FOR SHARE OF dispositivo
        `;
        if (activeDevices.length === 0) {
          return { allowed: false, reason: 'invalid_or_unavailable' };
        }
      }

      if (!args.token) {
        await insertAudit('negado');
        return { allowed: false, reason: 'invalid_or_unavailable' };
      }

      await verifyTokenSecret(transaction);
      const tokenDigest = digestToken(args.token);
      const candidates = await transaction.$queryRaw<Array<{
        id: string;
        condominioId: string;
        moradorId: string | null;
        convidadoId: string | null;
      }>>`
        SELECT id, "condominioId", "moradorId", "convidadoId"
        FROM "Convite"
        WHERE "tokenDigest" = ${tokenDigest}
          AND "condominioId" = ${args.condominiumId}
        FOR UPDATE
      `;
      const candidate = candidates[0];
      if (!candidate) {
        await insertAudit('negado');
        return { allowed: false, reason: 'invalid_or_unavailable' };
      }

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
        WHERE convite.id = ${candidate.id}
          AND convite."tokenDigest" = ${tokenDigest}
          AND convite."condominioId" = ${args.condominiumId}
          AND convite."deletedAt" IS NULL
          AND convite."usedAt" IS NULL
          AND convite."revokedAt" IS NULL
          AND convite."expiresAt" > clock_timestamp()
          AND convidado."deletedAt" IS NULL
          AND morador."deletedAt" IS NULL
          AND condominio."deletedAt" IS NULL
        FOR UPDATE OF convidado, morador, condominio
      `;

      const invitation = activeInvitations[0];
      if (!invitation) {
        await insertAudit('negado', candidate);
        return { allowed: false, reason: 'invalid_or_unavailable' };
      }

      const consumed = await transaction.$queryRaw<Array<{ usedAt: Date }>>`
        UPDATE "Convite"
        SET "tokenDigest" = NULL, "usedAt" = clock_timestamp()
        WHERE id = ${invitation.id}
          AND "tokenDigest" = ${tokenDigest}
          AND "condominioId" = ${args.condominiumId}
          AND "deletedAt" IS NULL
          AND "usedAt" IS NULL
          AND "revokedAt" IS NULL
          AND "expiresAt" > clock_timestamp()
        RETURNING "usedAt"
      `;
      const usedAt = consumed[0]?.usedAt;
      if (!usedAt) {
        await insertAudit('negado', invitation);
        return { allowed: false, reason: 'invalid_or_unavailable' };
      }

      const guestUpdated = await transaction.$executeRaw`
        UPDATE "Convidado"
        SET "ultimoUsoEm" = ${usedAt}
        WHERE id = ${invitation.convidadoId}
          AND "condominioId" = ${args.condominiumId}
          AND "deletedAt" IS NULL
      `;
      if (guestUpdated !== 1) {
        throw new Error('Invitation guest became unavailable during validation');
      }

      await insertAudit('permitido', invitation, usedAt);
      await insertEntryNotification(transaction, {
        invitationId: invitation.id,
        condominiumId: args.condominiumId,
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
          condominiumId: args.condominiumId,
          residentId: invitation.moradorId,
          guestId: invitation.convidadoId,
          invitationType: invitation.tipo,
          usedAt
        }
      };
    });
  }

  return {
    issueIdempotent,

    verifyIdempotencyConfiguration() {
      return client.$transaction((transaction) => verifyIdempotencySecret(transaction));
    },

    async createActive(data) {
      const records = await inTransaction([data]);
      return records?.[0] ?? null;
    },

    createBatchActive: inTransaction,

    validateActive(args) {
      return validateActive(args);
    },

    async listOwnedAudits({ condominiumId, residentId, cursor, limit }) {
      const rows = await client.$queryRaw<Array<{
        id: string;
        createdAt: Date;
        condominioId: string;
        dispositivoId: string;
        conviteId: string | null;
        moradorId: string | null;
        convidadoId: string | null;
        tipoAcesso: AccessType;
        resultado: 'permitido' | 'negado';
      }>>`
        SELECT id, "createdAt", "condominioId", "dispositivoId", "conviteId",
               "moradorId", "convidadoId", "tipoAcesso", resultado
        FROM "AuditoriaAcesso"
        WHERE "condominioId" = ${condominiumId}
          AND "moradorId" = ${residentId}
          AND (
            ${cursor}::text IS NULL
            OR ("createdAt", id) < (
              SELECT "createdAt", id
              FROM "AuditoriaAcesso"
              WHERE id = ${cursor}
                AND "condominioId" = ${condominiumId}
                AND "moradorId" = ${residentId}
            )
          )
        ORDER BY "createdAt" DESC, id DESC
        LIMIT ${limit}
      `;
      return rows.map((row) => ({
        id: row.id,
        createdAt: row.createdAt,
        condominiumId: row.condominioId,
        deviceId: row.dispositivoId,
        invitationId: row.conviteId,
        residentId: row.moradorId,
        guestId: row.convidadoId,
        accessType: row.tipoAcesso,
        result: row.resultado
      }));
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

  const link = payload.link === true;
  const qrCode = payload.qrCode === true;
  return { tipo, expiresAt, link: link || qrCode, qrCode };
}

function parseGuestIds(body: unknown) {
  if (!body || typeof body !== 'object' || Array.isArray(body)) {
    return null;
  }

  const convidadoIds = (body as Record<string, unknown>).convidadoIds;
  if (!Array.isArray(convidadoIds)
    || convidadoIds.length === 0
    || convidadoIds.length > MAX_BATCH_SIZE
    || !convidadoIds.every(isUuid)) {
    return null;
  }

  return convidadoIds;
}

function parseRepresentations(body: unknown) {
  if (!body || typeof body !== 'object' || Array.isArray(body)) return { link: false, qrCode: false };
  const payload = body as Record<string, unknown>;
  const qrCode = payload.qrCode === true;
  return { link: payload.link === true || qrCode, qrCode };
}

function invitationLink(baseUrl: string | undefined, token: string) {
  if (!baseUrl) return null;
  try {
    const url = new URL(baseUrl);
    if (url.protocol !== 'https:' || url.username || url.password || url.search || url.hash || !url.hostname) return null;
    return `${url.toString().replace(/\/$/, '')}/portaria/convites/validar#token=${encodeURIComponent(token)}`;
  } catch {
    return null;
  }
}

async function invitationRepresentations(token: string, requested: { link: boolean; qrCode: boolean }, baseUrl: string | undefined) {
  if (!requested.link && !requested.qrCode) return {};
  const link = invitationLink(baseUrl, token);
  if (!link) return null;
  return {
    ...(requested.link ? { link } : {}),
    ...(requested.qrCode ? { qrCode: await QRCode.toDataURL(link, { errorCorrectionLevel: 'M' }) } : {})
  };
}

function parseValidationBody(body: unknown) {
  if (!body || typeof body !== 'object' || Array.isArray(body)) {
    return null;
  }

  const payload = body as Record<string, unknown>;
  const accessType = ACCESS_TYPES.find((candidate) => candidate === payload.tipoAcesso);
  if (!accessType) return null;

  const keys = Object.keys(payload).sort();
  const validToken = keys.length === 2
    && keys[0] === 'tipoAcesso'
    && keys[1] === 'token'
    && typeof payload.token === 'string'
    && TOKEN_PATTERN.test(payload.token);
  return { accessType, token: validToken ? payload.token as string : null };
}

function parseAuditQuery(query: unknown) {
  if (!query || typeof query !== 'object' || Array.isArray(query)) return null;
  const payload = query as Record<string, unknown>;
  const keys = Object.keys(payload);
  if (keys.some((key) => key !== 'cursor' && key !== 'limit')) return null;

  const cursor = payload.cursor === undefined ? null : payload.cursor;
  if (cursor !== null && !isUuid(cursor)) return null;
  const limit = payload.limit === undefined ? 50 : Number(payload.limit);
  if (!Number.isSafeInteger(limit) || limit < 1 || limit > 100) return null;
  return { cursor, limit };
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
  _notifications: NotificationSender = createUnavailableNotificationSender(),
  publicValidationBaseUrl?: string,
  deviceRateLimiter: DeviceRateLimiter = createMemoryDeviceRateLimiter(),
  developmentRateLimiter: DeviceRateLimiter = createMemoryDeviceRateLimiter(),
  secureValidationTransport = false
) {
  const singlePath = '/condominios/:condominioId/moradores/:moradorId/convidados/:convidadoId/convites';
  const batchPath = '/condominios/:condominioId/moradores/:moradorId/convites/multiplos';
  const revokePath = '/condominios/:condominioId/moradores/:moradorId/convites/:conviteId';
  const auditPath = '/condominios/:condominioId/moradores/:moradorId/auditorias-acesso';
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
    onRequest: async (request, reply) => {
      reply.header('cache-control', 'no-store');
      reply.header('pragma', 'no-cache');
      reply.header('expires', '0');
      if (secureValidationTransport && request.protocol !== 'https') {
        return reply.status(426).send({ error: 'HTTPS required' });
      }
    },
    preHandler: authorize(authenticator, 'convites:validate')
  }, async (request, reply) => {
    const identity = request.authenticatedIdentity;
    const condominiumId = identity?.role === 'portaria' && identity.condominioIds.length === 1
      ? identity.condominioIds[0]
      : null;
    if (!condominiumId || !identity) {
      return reply.status(403).send({ error: 'Forbidden' });
    }
    if (identity.id.length === 0 || identity.id.length > 128) {
      return reply.status(403).send({ error: 'Forbidden' });
    }

    const now = new Date();
    const rateLimiter = identity.authMethod === 'device' ? deviceRateLimiter : developmentRateLimiter;
    const rateLimit = await rateLimiter.consume(identity.id, now);
    reply.header('x-ratelimit-limit', DEVICE_RATE_LIMIT);
    if (!rateLimit.allowed) {
      return reply
        .header('x-ratelimit-remaining', 0)
        .header('retry-after', rateLimit.retryAfterSeconds)
        .status(429)
        .send({ allowed: false, reason: 'rate_limited' });
    }
    reply.header('x-ratelimit-remaining', rateLimit.remaining);

    const body = parseValidationBody(request.body);
    if (!body) {
      return reply.status(400).send({ error: 'Invalid access type' });
    }
    if (!store) {
      return reply.status(503).send({ allowed: false, reason: 'service_unavailable' });
    }

    try {
      const result = await store.validateActive({
        token: body.token,
        condominiumId,
        deviceId: identity.id,
        accessType: body.accessType,
        requireActiveDevice: identity.authMethod === 'device'
      }, now);
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

  app.get(auditPath, {
    onRequest: async (_request, reply) => {
      reply.header('cache-control', 'no-store');
      reply.header('pragma', 'no-cache');
    },
    preHandler: authorize(
      authenticator,
      'auditorias:read-own',
      (request) => parseUuidParam(request.params, 'condominioId'),
      (request) => parseUuidParam(request.params, 'moradorId')
    )
  }, async (request, reply) => {
    const condominioId = parseUuidParam(request.params, 'condominioId');
    const moradorId = parseUuidParam(request.params, 'moradorId');
    const query = parseAuditQuery(request.query);
    if (!condominioId || !moradorId || !query) {
      return reply.status(400).send({ error: 'Invalid audit scope' });
    }
    if (!store) {
      return reply.status(503).send({ error: 'Audit service unavailable' });
    }

    const [condominio, morador] = await Promise.all([
      db.condominio.findFirst({ where: { id: condominioId, deletedAt: null } }),
      db.morador.findFirst({
        where: { id: moradorId, condominioId, deletedAt: null, condominio: activeCondominio }
      })
    ]);
    if (!condominio || !morador) {
      return reply.status(404).send({ error: 'Resident not found' });
    }

    const audits = await store.listOwnedAudits({
      condominiumId: condominioId,
      residentId: moradorId,
      cursor: query.cursor,
      limit: query.limit
    });
    return audits.map((audit) => ({
      id: audit.id,
      ocorreuEm: audit.createdAt.toISOString(),
      condominioId: audit.condominiumId,
      dispositivoId: audit.deviceId,
      conviteId: audit.invitationId,
      moradorId: audit.residentId,
      convidadoId: audit.guestId,
      tipoAcesso: audit.accessType,
      resultado: audit.result
    }));
  });

  app.post(singlePath, management, async (request, reply) => {
    const condominioId = parseUuidParam(request.params, 'condominioId');
    const moradorId = parseUuidParam(request.params, 'moradorId');
    const convidadoId = parseUuidParam(request.params, 'convidadoId');
    const body = parseInvitationBody(request.body);
    if (!condominioId || !moradorId || !convidadoId || !body) {
      return reply.status(400).send({ error: 'Invalid invitation payload' });
    }

    const idempotencyKey = parseIdempotencyKey(request.headers['idempotency-key']);
    if (!idempotencyKey) {
      return reply.status(400).send({ error: 'A valid Idempotency-Key header is required' });
    }
    const identity = request.authenticatedIdentity;
    if (!store?.issueIdempotent || !identity || identity.id.length === 0 || identity.id.length > 128) {
      return reply.status(503).send({ error: 'Invitation service unavailable' });
    }
    if (body?.link || body?.qrCode) {
      const representation = invitationLink(publicValidationBaseUrl, '000000');
      if (!representation) return reply.status(503).send({ error: 'Invitation link configuration unavailable' });
    }

    try {
      const result = await store.issueIdempotent({
        key: idempotencyKey,
        actorId: identity.id,
        condominioId,
        method: 'POST',
        route: singlePath,
        requestHash: canonicalRequestHash(request.body),
        invitations: [{ condominioId, moradorId, convidadoId, ...body }],
        async buildResponse(results) {
          const issued = results[0]!;
          const representations = await invitationRepresentations(issued.token, body, publicValidationBaseUrl);
          if (!representations) throw new Error('Invitation link configuration became unavailable');
          return { ...invitationResponse(issued.convite, issued.token), ...representations };
        }
      });
      if (!result) return reply.status(404).send({ error: 'Guest not found' });
      return reply
        .header('cache-control', 'no-store')
        .header('idempotency-replayed', String(result.replayed))
        .type('application/json')
        .status(result.statusCode)
        .send(result.responseText);
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
      if (error instanceof IdempotencyConflictError) {
        return reply.status(409).send({ error: 'Idempotency key conflicts with a different request' });
      }
      if (error instanceof IdempotencySecretMismatchError) {
        return reply.status(503).send({ error: 'Invitation service unavailable' });
      }
      throw error;
    }
  });

  app.post(batchPath, management, async (request, reply) => {
    const condominioId = parseUuidParam(request.params, 'condominioId');
    const moradorId = parseUuidParam(request.params, 'moradorId');
    const convidadoIds = parseGuestIds(request.body);
    const representations = parseRepresentations(request.body);
    if (!condominioId || !moradorId || !convidadoIds) {
      return reply.status(400).send({ error: 'Invalid batch invitation payload' });
    }
    if (new Set(convidadoIds).size !== convidadoIds.length) {
      return reply.status(400).send({ error: 'Guest ids must be unique' });
    }
    const idempotencyKey = parseIdempotencyKey(request.headers['idempotency-key']);
    if (!idempotencyKey) {
      return reply.status(400).send({ error: 'A valid Idempotency-Key header is required' });
    }
    const identity = request.authenticatedIdentity;
    if (!store?.issueIdempotent || !identity || identity.id.length === 0 || identity.id.length > 128) {
      return reply.status(503).send({ error: 'Invitation service unavailable' });
    }
    if (representations.link || representations.qrCode) {
      if (!invitationLink(publicValidationBaseUrl, '000000')) {
        return reply.status(503).send({ error: 'Invitation link configuration unavailable' });
      }
    }

    try {
      const expiresAt = new Date(Date.now() + BATCH_EXPIRATION_MS);
      const result = await store.issueIdempotent({
        key: idempotencyKey,
        actorId: identity.id,
        condominioId,
        method: 'POST',
        route: batchPath,
        requestHash: canonicalRequestHash(request.body),
        invitations: convidadoIds.map((convidadoId) => ({
          condominioId,
          moradorId,
          convidadoId,
          tipo: 'visitante',
          expiresAt
        })),
        async buildResponse(results) {
          const convites = await Promise.all(results.map(async ({ convite, token }) => ({
            id: convite.id,
            convidadoId: convite.convidadoId,
            token,
            expiraEm: convite.expiresAt?.toISOString() ?? expiresAt.toISOString(),
            ...(await invitationRepresentations(token, representations, publicValidationBaseUrl) ?? {})
          })));
          return { convites };
        }
      });
      if (!result) {
        return reply.status(404).send({ error: 'One or more guests are no longer active or owned by resident' });
      }
      return reply
        .header('cache-control', 'no-store')
        .header('idempotency-replayed', String(result.replayed))
        .type('application/json')
        .status(result.statusCode)
        .send(result.responseText);
    } catch (error) {
      if (error instanceof TokenGenerationExhaustedError) {
        return reply.status(503).send({ error: 'Invitation token unavailable' });
      }
      if (error instanceof DailyInvitationLimitError) {
        return reply.status(429).send({ error: 'Daily invitation limit reached' });
      }
      if (error instanceof IdempotencyConflictError) {
        return reply.status(409).send({ error: 'Idempotency key conflicts with a different request' });
      }
      if (error instanceof IdempotencySecretMismatchError) {
        return reply.status(503).send({ error: 'Invitation service unavailable' });
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
