import { createHash, createHmac, randomBytes } from 'node:crypto';

import { Prisma, type PrismaClient, type StatusDispositivo } from '@prisma/client';
import type { FastifyInstance } from 'fastify';

import { authorize, isUuid } from './auth.js';
import type { Authenticator } from './auth.js';

const API_KEY_PATTERN = /^egdev_[A-Za-z0-9_-]{43}$/;
const MAX_KEY_ATTEMPTS = 4;
export const DEVICE_RATE_LIMIT = 20;
const RATE_WINDOW_MS = 60_000;
const INITIAL_BACKOFF_SECONDS = 15;
const MAX_BACKOFF_SECONDS = 300;

export type DeviceRecord = {
  id: string;
  createdAt: Date;
  deletedAt: Date | null;
  nome: string;
  condominioId: string;
  status: StatusDispositivo;
  ultimoUsoEm: Date | null;
};

export interface DeviceStore {
  create(args: { condominiumId: string; name: string }): Promise<{ device: DeviceRecord; apiKey: string } | null>;
  list(args: { condominiumId: string }): Promise<readonly DeviceRecord[]>;
  revoke(args: { id: string; condominiumId: string }): Promise<'revoked' | 'already-revoked' | 'unavailable'>;
  authenticate(apiKey: string, now: Date): Promise<{ id: string; condominiumId: string } | null>;
  verifyConfiguration?(): Promise<void>;
}

export interface DeviceSecretConfiguration {
  verifyConfiguration(): Promise<void>;
}

export type RateLimitResult =
  | { allowed: true; remaining: number }
  | { allowed: false; retryAfterSeconds: number };

export interface DeviceRateLimiter {
  consume(deviceId: string, now: Date): Promise<RateLimitResult>;
}

export class DeviceSecretMismatchError extends Error {
  constructor() {
    super('Device API key secret does not match database configuration');
  }
}

export function generateDeviceApiKey() {
  return `egdev_${randomBytes(32).toString('base64url')}`;
}

function isDigestCollision(error: unknown) {
  if (!(error instanceof Prisma.PrismaClientKnownRequestError) || error.code !== 'P2002') return false;
  return String(error.meta?.target).toLowerCase().includes('apikeydigest');
}

export function createPrismaDeviceStore(
  client: PrismaClient,
  secret: string
): DeviceStore & DeviceSecretConfiguration {
  if (Buffer.byteLength(secret) < 32) throw new Error('Device API key secret must be at least 32 bytes');
  const digestKey = (key: string) => createHmac('sha256', secret).update('device-api-key\0').update(key).digest('hex');
  const fingerprint = createHash('sha256').update('device-api-key\0').update(secret).digest('hex');

  async function verifySecret(transaction: Prisma.TransactionClient) {
    await transaction.$executeRaw`
      INSERT INTO "SecurityKey" (name, fingerprint)
      VALUES ('device-api-key', ${fingerprint})
      ON CONFLICT (name) DO NOTHING
    `;
    const configured = await transaction.$queryRaw<Array<{ fingerprint: string }>>`
      SELECT fingerprint FROM "SecurityKey" WHERE name = 'device-api-key'
    `;
    if (configured[0]?.fingerprint.trim() !== fingerprint) throw new DeviceSecretMismatchError();
  }

  return {
    async verifyConfiguration() {
      await client.$transaction((transaction) => verifySecret(transaction));
    },

    async create({ condominiumId, name }) {
      for (let attempt = 0; attempt < MAX_KEY_ATTEMPTS; attempt += 1) {
        const apiKey = generateDeviceApiKey();
        try {
          const device = await client.$transaction(async (transaction) => {
            await verifySecret(transaction);
            const active = await transaction.$queryRaw<Array<{ id: string }>>`
              SELECT id FROM "Condominio"
              WHERE id = ${condominiumId} AND "deletedAt" IS NULL
              FOR UPDATE
            `;
            if (active.length === 0) return null;
            return transaction.dispositivo.create({
              data: { condominioId: condominiumId, nome: name, apiKeyDigest: digestKey(apiKey) }
            });
          });
          return device ? { device, apiKey } : null;
        } catch (error) {
          if (!isDigestCollision(error)) throw error;
        }
      }
      throw new Error('Could not allocate a device API key');
    },

    async list({ condominiumId }) {
      return client.dispositivo.findMany({
        where: { condominioId: condominiumId, deletedAt: null, condominio: { deletedAt: null } },
        orderBy: { createdAt: 'desc' }
      });
    },

    async revoke({ id, condominiumId }) {
      return client.$transaction(async (transaction) => {
        const revoked = await transaction.dispositivo.updateMany({
          where: { id, condominioId: condominiumId, status: 'ativo', deletedAt: null, condominio: { deletedAt: null } },
          data: { status: 'revogado', apiKeyDigest: null }
        });
        if (revoked.count === 1) return 'revoked';
        const existing = await transaction.dispositivo.findFirst({
          where: { id, condominioId: condominiumId, status: 'revogado', deletedAt: null, condominio: { deletedAt: null } },
          select: { id: true }
        });
        return existing ? 'already-revoked' : 'unavailable';
      });
    },

    async authenticate(apiKey, now) {
      if (!API_KEY_PATTERN.test(apiKey)) return null;
      return client.$transaction(async (transaction) => {
        await verifySecret(transaction);
        const devices = await transaction.$queryRaw<Array<{ id: string; condominioId: string }>>`
          UPDATE "Dispositivo" AS dispositivo
          SET "ultimoUsoEm" = ${now}
          FROM "Condominio" AS condominio
          WHERE dispositivo."apiKeyDigest" = ${digestKey(apiKey)}
            AND dispositivo.status = 'ativo'
            AND dispositivo."deletedAt" IS NULL
            AND condominio.id = dispositivo."condominioId"
            AND condominio."deletedAt" IS NULL
          RETURNING dispositivo.id, dispositivo."condominioId"
        `;
        const device = devices[0];
        return device ? { id: device.id, condominiumId: device.condominioId } : null;
      });
    }
  };
}

export function createDeviceAuthenticator(store: DeviceStore): Authenticator {
  return {
    async authenticate(request) {
      const authorization = request.headers.authorization;
      if (typeof authorization !== 'string') return null;
      const match = /^Bearer ([^ ]+)$/.exec(authorization);
      if (!match) return null;
      const device = await store.authenticate(match[1]!, new Date());
      return device
        ? {
            id: device.id,
            role: 'portaria',
            condominioIds: [device.condominiumId],
            principalType: 'device',
            authMethod: 'device'
          }
        : null;
    }
  };
}

function rateLimitDecision(
  attempts: readonly Date[],
  blockedUntil: Date | null,
  backoffLevel: number,
  now: Date
) {
  if (blockedUntil && blockedUntil.getTime() > now.getTime()) {
    return {
      result: { allowed: false as const, retryAfterSeconds: Math.max(1, Math.ceil((blockedUntil.getTime() - now.getTime()) / 1000)) },
      attempts: [...attempts],
      blockedUntil,
      backoffLevel
    };
  }
  const recent = attempts.filter((attempt) => attempt.getTime() > now.getTime() - RATE_WINDOW_MS);
  if (recent.length >= DEVICE_RATE_LIMIT) {
    const backoffSeconds = Math.min(INITIAL_BACKOFF_SECONDS * (2 ** backoffLevel), MAX_BACKOFF_SECONDS);
    const nextBlockedUntil = new Date(now.getTime() + backoffSeconds * 1000);
    return {
      result: { allowed: false as const, retryAfterSeconds: backoffSeconds },
      attempts: recent,
      blockedUntil: nextBlockedUntil,
      backoffLevel: Math.min(backoffLevel + 1, 5)
    };
  }
  return {
    result: { allowed: true as const, remaining: DEVICE_RATE_LIMIT - recent.length - 1 },
    attempts: [...recent, now],
    blockedUntil: null,
    backoffLevel: recent.length === 0 ? 0 : backoffLevel
  };
}

export function createMemoryDeviceRateLimiter(): DeviceRateLimiter {
  const states = new Map<string, { attempts: Date[]; blockedUntil: Date | null; backoffLevel: number }>();
  return {
    async consume(deviceId, now) {
      const state = states.get(deviceId) ?? { attempts: [], blockedUntil: null, backoffLevel: 0 };
      const decision = rateLimitDecision(state.attempts, state.blockedUntil, state.backoffLevel, now);
      states.set(deviceId, {
        attempts: decision.attempts,
        blockedUntil: decision.blockedUntil,
        backoffLevel: decision.backoffLevel
      });
      return decision.result;
    }
  };
}

export function createPrismaDeviceRateLimiter(client: PrismaClient): DeviceRateLimiter {
  return {
    async consume(deviceId, now) {
      return client.$transaction(async (transaction) => {
        await transaction.$executeRaw`
          INSERT INTO "DispositivoRateLimit" ("dispositivoId")
          VALUES (${deviceId})
          ON CONFLICT ("dispositivoId") DO NOTHING
        `;
        const rows = await transaction.$queryRaw<Array<{
          attempts: Date[];
          blockedUntil: Date | null;
          backoffLevel: number;
        }>>`
          SELECT attempts, "blockedUntil", "backoffLevel"
          FROM "DispositivoRateLimit"
          WHERE "dispositivoId" = ${deviceId}
          FOR UPDATE
        `;
        const state = rows[0]!;
        const decision = rateLimitDecision(state.attempts, state.blockedUntil, state.backoffLevel, now);
        await transaction.dispositivoRateLimit.update({
          where: { dispositivoId: deviceId },
          data: {
            attempts: decision.attempts,
            blockedUntil: decision.blockedUntil,
            backoffLevel: decision.backoffLevel
          }
        });
        return decision.result;
      });
    }
  };
}

function uuidParam(params: unknown, name: string) {
  if (!params || typeof params !== 'object' || Array.isArray(params)) return null;
  const value = (params as Record<string, unknown>)[name];
  return isUuid(value) ? value : null;
}

function deviceBody(body: unknown) {
  if (!body || typeof body !== 'object' || Array.isArray(body)) return null;
  const payload = body as Record<string, unknown>;
  if (Object.keys(payload).length !== 1 || typeof payload.nome !== 'string') return null;
  const name = payload.nome.trim();
  return name.length >= 1 && name.length <= 100 ? name : null;
}

function responseRecord(device: DeviceRecord) {
  return {
    id: device.id,
    createdAt: device.createdAt.toISOString(),
    condominioId: device.condominioId,
    nome: device.nome,
    status: device.status,
    ultimoUsoEm: device.ultimoUsoEm?.toISOString() ?? null
  };
}

export function registerDeviceRoutes(app: FastifyInstance, store: DeviceStore | undefined, authenticator: Authenticator) {
  const path = '/condominios/:condominioId/dispositivos';
  const management = {
    preHandler: authorize(authenticator, 'dispositivos:manage', (request) => uuidParam(request.params, 'condominioId'))
  };

  app.post(path, management, async (request, reply) => {
    const condominiumId = uuidParam(request.params, 'condominioId');
    const name = deviceBody(request.body);
    if (!condominiumId || !name) return reply.status(400).send({ error: 'Invalid device payload' });
    if (!store) return reply.status(503).send({ error: 'Device service unavailable' });
    try {
      const created = await store.create({ condominiumId, name });
      if (!created) return reply.status(404).send({ error: 'Condominium not found' });
      return reply.header('cache-control', 'no-store').status(201).send({
        ...responseRecord(created.device),
        apiKey: created.apiKey
      });
    } catch (error) {
      if (error instanceof DeviceSecretMismatchError) return reply.status(503).send({ error: 'Device service unavailable' });
      throw error;
    }
  });

  app.get(path, management, async (request, reply) => {
    const condominiumId = uuidParam(request.params, 'condominioId');
    if (!condominiumId) return reply.status(400).send({ error: 'Invalid condominium id' });
    if (!store) return reply.status(503).send({ error: 'Device service unavailable' });
    return (await store.list({ condominiumId })).map(responseRecord);
  });

  app.delete(`${path}/:deviceId`, management, async (request, reply) => {
    const condominiumId = uuidParam(request.params, 'condominioId');
    const id = uuidParam(request.params, 'deviceId');
    if (!condominiumId || !id) return reply.status(400).send({ error: 'Invalid device id' });
    if (!store) return reply.status(503).send({ error: 'Device service unavailable' });
    const result = await store.revoke({ id, condominiumId });
    return result === 'unavailable'
      ? reply.status(404).send({ error: 'Device not found' })
      : reply.status(204).send();
  });
}
