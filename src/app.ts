import Fastify from 'fastify';

import { authorize, isUuid, unauthenticatedAuthenticator } from './auth.js';
import type { Authenticator } from './auth.js';
import { registerConvidadoRoutes } from './convidados.js';
import {
  createPrismaInvitationStore,
  createUnavailableNotificationSender,
  IdempotencySecretMismatchError,
  registerConviteRoutes
} from './convites.js';
import type { InvitationStore, NotificationSender } from './convites.js';
import {
  createMemoryDeviceRateLimiter,
  createPrismaDeviceStore,
  DeviceSecretMismatchError,
  registerDeviceRoutes
} from './dispositivos.js';
import type { DeviceRateLimiter, DeviceStore } from './dispositivos.js';
import { createPrismaNotificationStore, registerNotificationRoutes } from './notificacoes.js';
import type { NotificationStore } from './notificacoes.js';
import { registerOidcRoutes } from './oidc.js';
import type { OidcService } from './oidc.js';
import type { BrowserSessionService } from './sessions.js';
import type { BrowserSessionStore } from './sessions.js';
import { registerBrowserAuthRoutes } from './browser-auth.js';
import { registerHumanAdministrationRoutes } from './human-administration.js';
import type { HumanAdministrationService } from './human-administration.js';
import { prisma as defaultPrisma } from './lib/prisma.js';
import { isDatabaseTimeZoneRejection, isValidTimeZone } from './timezones.js';
import type { AuthRateLimiter } from './auth-rate-limits.js';
import { registerFrontend } from './frontend.js';

type CondominioRecord = {
  id: string;
  createdAt: Date;
  deletedAt: Date | null;
  nome: string;
  responsavel: string;
  tipo: string;
  timezone: string;
  dailyInvitationLimit?: number | null;
};

type CondominioCreateData = {
  nome: string;
  responsavel: string;
  tipo: string;
  timezone: string;
};

type CondominioUpdateData = Partial<CondominioCreateData> & {
  dailyInvitationLimit?: number | null;
  deletedAt?: Date;
};

type MoradorRecord = {
  id: string;
  createdAt: Date;
  deletedAt: Date | null;
  nome: string;
  condominioId: string;
  enderecoRua: string | null;
  enderecoNumero: string | null;
  enderecoBloco: string | null;
  enderecoApartamento: string | null;
  dailyInvitationLimit?: number | null;
};

type MoradorEnderecoData = {
  enderecoRua: string | null;
  enderecoNumero: string | null;
  enderecoBloco: string | null;
  enderecoApartamento: string | null;
};

type MoradorCreateData = MoradorEnderecoData & {
  nome: string;
  condominioId: string;
};

type MoradorUpdateData = Partial<Pick<MoradorCreateData, 'nome'>> &
  Partial<MoradorEnderecoData> & {
    dailyInvitationLimit?: number | null;
    deletedAt?: Date;
  };

type ConvidadoRecord = {
  id: string;
  createdAt: Date;
  deletedAt: Date | null;
  nome: string;
  email?: string | null;
  telefone?: string | null;
  condominioId: string;
  moradorId: string | null;
  ultimoUsoEm: Date | null;
  anonymizedAt?: Date | null;
};

type ConvidadoCreateData = { nome: string; email: string | null; telefone: string | null; condominioId: string; moradorId: string };
type ConvidadoUpdateData = { nome?: string; email?: string | null; telefone?: string | null; ultimoUsoEm?: Date | null; deletedAt?: Date };
type ConvidadoOrderBy = { ultimoUsoEm: { sort: 'desc'; nulls: 'last' } } | { createdAt: 'desc' } | { id: 'desc' };
type ConvidadoWhere = {
  id?: string;
  anonymizedAt?: null;
  condominioId: string;
  moradorId: string;
  deletedAt: null;
  condominio: { deletedAt: null };
  morador: { is: { deletedAt: null } };
};

export type AppStore = {
  condominio: {
    create(args: { data: CondominioCreateData }): Promise<CondominioRecord>;
    findMany(args: { where: { deletedAt: null }; orderBy: { createdAt: 'desc' } }): Promise<CondominioRecord[]>;
    findFirst(args: { where: { id: string; deletedAt: null } }): Promise<CondominioRecord | null>;
    updateMany(args: { where: { id: string; deletedAt: null }; data: CondominioUpdateData }): Promise<{ count: number }>;
  };
  morador: {
    create(args: { data: MoradorCreateData }): Promise<MoradorRecord | null>;
    findMany(args: {
      where: { condominioId: string; deletedAt: null; condominio: { deletedAt: null } };
      orderBy: { createdAt: 'desc' };
    }): Promise<MoradorRecord[]>;
    findFirst(args: {
      where: { id: string; condominioId: string; deletedAt: null; condominio: { deletedAt: null } };
    }): Promise<MoradorRecord | null>;
    updateMany(args: {
      where: { id: string; condominioId: string; deletedAt: null; condominio: { deletedAt: null } };
      data: MoradorUpdateData;
    }): Promise<{ count: number }>;
  };
  convidado: {
    create(args: { data: ConvidadoCreateData }): Promise<ConvidadoRecord | null>;
    findMany(args: {
      where: ConvidadoWhere;
      orderBy: ConvidadoOrderBy[];
      take?: number;
    }): Promise<ConvidadoRecord[]>;
    findFirst(args: { where: ConvidadoWhere & { id: string } }): Promise<ConvidadoRecord | null>;
    updateMany(args: {
      where: ConvidadoWhere & { id: string };
      data: ConvidadoUpdateData;
    }): Promise<{ count: number }>;
  };
};

export type AppDependencies = AppStore & {
  convite?: InvitationStore;
  dispositivo?: DeviceStore;
  notificacao?: NotificationStore;
  notificationSender?: NotificationSender;
};

export type CondominioStore = AppStore;

export type Readiness = {
  checkDatabase(): Promise<void>;
  deviceSecretValidated: boolean;
  humanAuthEnabled: boolean;
  oidcMetadataValidated: boolean;
  requiredServicesComposed: boolean;
};

type CondominioBody = Partial<Record<keyof CondominioCreateData, unknown>>;
type MoradorBody = Partial<Record<'nome' | 'condominioId' | 'endereco', unknown>>;
type EnderecoBody = Partial<Record<'rua' | 'numero' | 'bloco' | 'apartamento', unknown>>;

function readRequiredString(body: Partial<Record<string, unknown>>, field: string) {
  const value = body[field];

  if (typeof value !== 'string') {
    return null;
  }

  const trimmed = value.trim();
  return trimmed.length > 0 ? trimmed : null;
}

function parseCreateBody(body: unknown) {
  if (!body || typeof body !== 'object' || Array.isArray(body)) {
    return null;
  }

  const payload = body as CondominioBody;
  const nome = readRequiredString(payload, 'nome');
  const responsavel = readRequiredString(payload, 'responsavel');
  const tipo = readRequiredString(payload, 'tipo');
  const timezone = readRequiredString(payload, 'timezone');

  if (!nome || !responsavel || !tipo || !timezone || !isValidTimeZone(timezone)) {
    return null;
  }

  return { nome, responsavel, tipo, timezone };
}

function parseUpdateBody(body: unknown) {
  if (!body || typeof body !== 'object' || Array.isArray(body)) {
    return null;
  }

  const payload = body as CondominioBody;
  const data: CondominioUpdateData = {};

  for (const field of ['nome', 'responsavel', 'tipo'] as const) {
    if (Object.hasOwn(payload, field)) {
      const value = readRequiredString(payload, field);

      if (!value) {
        return null;
      }

      data[field] = value;
    }
  }

  if (Object.hasOwn(payload, 'timezone')) {
    const timezone = readRequiredString(payload, 'timezone');
    if (!timezone || !isValidTimeZone(timezone)) return null;
    data.timezone = timezone;
  }

  return Object.keys(data).length > 0 ? data : null;
}

function parseId(params: unknown) {
  return parseUuidParam(params, 'id');
}

function parseUuidParam(params: unknown, field: string) {
  if (!params || typeof params !== 'object' || Array.isArray(params)) {
    return null;
  }

  const value = (params as Record<string, unknown>)[field];
  return isUuid(value) ? value : null;
}

function parseEndereco(value: unknown): MoradorEnderecoData | null {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    return null;
  }

  const payload = value as EnderecoBody;
  const rua = readEnderecoString(payload, 'rua');
  const numero = readEnderecoString(payload, 'numero');
  const bloco = readEnderecoString(payload, 'bloco');
  const apartamento = readEnderecoString(payload, 'apartamento');
  const hasRuaNumero = Boolean(rua && numero && !bloco && !apartamento);
  const hasBlocoApartamento = Boolean(bloco && apartamento && !rua && !numero);

  if (hasRuaNumero) {
    return {
      enderecoRua: rua,
      enderecoNumero: numero,
      enderecoBloco: null,
      enderecoApartamento: null
    };
  }

  if (hasBlocoApartamento) {
    return {
      enderecoRua: null,
      enderecoNumero: null,
      enderecoBloco: bloco,
      enderecoApartamento: apartamento
    };
  }

  return null;
}

function readEnderecoString(body: EnderecoBody, field: keyof EnderecoBody) {
  if (!Object.hasOwn(body, field)) {
    return null;
  }

  const value = body[field];

  if (typeof value !== 'string') {
    return null;
  }

  const trimmed = value.trim();
  return trimmed.length > 0 ? trimmed : null;
}

function parseMoradorCreateBody(body: unknown) {
  if (!body || typeof body !== 'object' || Array.isArray(body)) {
    return null;
  }

  const payload = body as MoradorBody;
  const nome = readRequiredString(payload, 'nome');
  const condominioId = isUuid(payload.condominioId) ? payload.condominioId : null;
  const endereco = parseEndereco(payload.endereco);

  if (!nome || !condominioId || !endereco) {
    return null;
  }

  return { nome, condominioId, ...endereco };
}

function parseMoradorUpdateBody(body: unknown) {
  if (!body || typeof body !== 'object' || Array.isArray(body)) {
    return null;
  }

  const payload = body as MoradorBody;
  const data: MoradorUpdateData = {};

  if (Object.hasOwn(payload, 'nome')) {
    const nome = readRequiredString(payload, 'nome');

    if (!nome) {
      return null;
    }

    data.nome = nome;
  }

  if (Object.hasOwn(payload, 'endereco')) {
    const endereco = parseEndereco(payload.endereco);

    if (!endereco) {
      return null;
    }

    Object.assign(data, endereco);
  }

  return Object.keys(data).length > 0 ? data : null;
}

function parseDailyInvitationLimit(body: unknown) {
  if (!body || typeof body !== 'object' || Array.isArray(body)) {
    return undefined;
  }
  const value = (body as Record<string, unknown>).dailyInvitationLimit;
  if (value === null) {
    return null;
  }
  return typeof value === 'number' && Number.isSafeInteger(value) && value >= 0 && value <= 100_000
    ? value
    : undefined;
}

function toCondominioResponse(condominio: CondominioRecord) {
  return {
    id: condominio.id,
    createdAt: condominio.createdAt.toISOString(),
    nome: condominio.nome,
    responsavel: condominio.responsavel,
    tipo: condominio.tipo,
    timezone: condominio.timezone
  };
}

function toMoradorResponse(morador: MoradorRecord) {
  const endereco = morador.enderecoRua
    ? { rua: morador.enderecoRua, numero: morador.enderecoNumero }
    : { bloco: morador.enderecoBloco, apartamento: morador.enderecoApartamento };

  return {
    id: morador.id,
    createdAt: morador.createdAt.toISOString(),
    condominioId: morador.condominioId,
    nome: morador.nome,
    endereco
  };
}

const activeCondominio = { deletedAt: null } as const;

const defaultStore: AppStore = {
  condominio: defaultPrisma.condominio,
  morador: {
    async create({ data }) {
      return defaultPrisma.$transaction(async (transaction) => {
        // Hold the parent row through insertion so soft deletion cannot race the active check.
        const activeCondominios = await transaction.$queryRaw<Array<{ id: string }>>`
          SELECT id
          FROM "Condominio"
          WHERE id = ${data.condominioId} AND "deletedAt" IS NULL
          FOR UPDATE
        `;

        if (activeCondominios.length === 0) {
          return null;
        }

        return transaction.morador.create({ data });
      });
    },
    findMany: (args) => defaultPrisma.morador.findMany(args),
    findFirst: (args) => defaultPrisma.morador.findFirst(args),
    updateMany: (args) => defaultPrisma.morador.updateMany(args)
  },
  convidado: {
    async create({ data }) {
      return defaultPrisma.$transaction(async (transaction) => {
        const activeMoradores = await transaction.$queryRaw<Array<{ id: string }>>`
          SELECT morador.id
          FROM "Morador" AS morador
          JOIN "Condominio" AS condominio ON condominio.id = morador."condominioId"
          WHERE morador.id = ${data.moradorId}
            AND morador."condominioId" = ${data.condominioId}
            AND morador."deletedAt" IS NULL
            AND condominio."deletedAt" IS NULL
          FOR UPDATE OF morador, condominio
        `;

        if (activeMoradores.length === 0) {
          return null;
        }

        return transaction.convidado.create({ data });
      });
    },
    findMany: (args) => defaultPrisma.convidado.findMany(args),
    findFirst: (args) => defaultPrisma.convidado.findFirst(args),
    updateMany: (args) => defaultPrisma.convidado.updateMany(args)
  }
};

export function createApp(
  {
    db: suppliedDb,
    invitationStore,
    deviceStore,
    authenticator = unauthenticatedAuthenticator,
    invitationTokenSecret = process.env.INVITATION_TOKEN_SECRET,
    idempotencyCacheSecret = process.env.IDEMPOTENCY_CACHE_SECRET,
    idempotencyTtlMs = 24 * 60 * 60 * 1000,
    deviceApiKeySecret = process.env.DEVICE_API_KEY_SECRET,
    deviceRateLimiter = createMemoryDeviceRateLimiter(),
    developmentRateLimiter = createMemoryDeviceRateLimiter(),
    notificationSender,
    publicValidationBaseUrl,
    secureValidationTransport = false,
    trustProxy = false,
    oidcService,
    browserSessionService,
    browserSessionStore,
    humanAdministrationService,
    authRateLimiter,
    frontendRoot,
    readiness
  }: {
    db?: AppDependencies;
    invitationStore?: InvitationStore;
    deviceStore?: DeviceStore;
    authenticator?: Authenticator;
    invitationTokenSecret?: string;
    idempotencyCacheSecret?: string;
    idempotencyTtlMs?: number;
    deviceApiKeySecret?: string;
    deviceRateLimiter?: DeviceRateLimiter;
    developmentRateLimiter?: DeviceRateLimiter;
    notificationSender?: NotificationSender;
    publicValidationBaseUrl?: string;
    secureValidationTransport?: boolean;
    trustProxy?: boolean | string;
    oidcService?: OidcService;
    browserSessionService?: BrowserSessionService;
    browserSessionStore?: BrowserSessionStore;
    humanAdministrationService?: HumanAdministrationService;
    authRateLimiter?: AuthRateLimiter;
    frontendRoot?: string;
    readiness?: Readiness;
  } = {}
) {
  if (!authRateLimiter && (oidcService || browserSessionService || browserSessionStore || humanAdministrationService)) {
    throw new Error('Human authentication routes require an AuthRateLimiter');
  }
  const db: AppDependencies = suppliedDb ?? {
    ...defaultStore,
    convite: invitationStore ?? (invitationTokenSecret
      ? createPrismaInvitationStore(defaultPrisma, invitationTokenSecret, {
          idempotencySecret: idempotencyCacheSecret,
          idempotencyTtlMs
        })
      : undefined),
    dispositivo: deviceStore ?? (deviceApiKeySecret
      ? createPrismaDeviceStore(defaultPrisma, deviceApiKeySecret)
      : undefined),
    notificacao: createPrismaNotificationStore(defaultPrisma)
  };
  const effectiveNotificationSender = notificationSender
    ?? suppliedDb?.notificationSender
    ?? createUnavailableNotificationSender();
  const app = Fastify({ logger: false, trustProxy });
  registerFrontend(app, frontendRoot);
  app.setErrorHandler((error, _request, reply) => {
    if (error instanceof DeviceSecretMismatchError) {
      return reply.status(503).send({ error: 'Device service unavailable' });
    }
    if (error instanceof IdempotencySecretMismatchError) {
      return reply.status(503).send({ error: 'Invitation service unavailable' });
    }
    return reply.send(error);
  });
  const condominioManagement = { preHandler: authorize(authenticator, 'condominios:manage') };
  const createMoradorManagement = {
    preHandler: authorize(authenticator, 'moradores:manage', (request) => {
      if (!request.body || typeof request.body !== 'object' || Array.isArray(request.body)) {
        return null;
      }

      const condominioId = (request.body as MoradorBody).condominioId;
      return isUuid(condominioId) ? condominioId : null;
    })
  };
  const nestedMoradorManagement = {
    preHandler: authorize(authenticator, 'moradores:manage', (request) =>
      parseUuidParam(request.params, 'condominioId')
    )
  };
  const invitationLimitManagement = {
    preHandler: authorize(authenticator, 'convites:limits:manage', (request) =>
      parseUuidParam(request.params, 'condominioId') ?? parseUuidParam(request.params, 'id')
    )
  };

  app.get('/health', async () => ({ status: 'ok' }));
  app.get('/ready', async (_request, reply) => {
    try {
      if (!readiness) throw new Error('Readiness is not configured');
      if (!readiness.deviceSecretValidated) throw new Error('Device configuration is not ready');
      if (readiness.humanAuthEnabled
        && (!readiness.oidcMetadataValidated || !readiness.requiredServicesComposed)) {
        throw new Error('Human authentication is not ready');
      }
      await readiness.checkDatabase();
      return { status: 'ready' };
    } catch {
      return reply.status(503).send({ status: 'unavailable' });
    }
  });

  app.post('/condominios', condominioManagement, async (request, reply) => {
    const payload = request.body && typeof request.body === 'object' && !Array.isArray(request.body)
      ? request.body as Record<string, unknown>
      : null;
    const timezone = payload?.timezone;
    if (payload && Object.hasOwn(payload, 'timezone')
      && (typeof timezone !== 'string' || !isValidTimeZone(timezone.trim()))) {
      return reply.status(400).send({ error: 'Invalid condominium timezone' });
    }
    const data = parseCreateBody(request.body);

    if (!data) {
      return reply.status(400).send({ error: 'Invalid condominium payload' });
    }

    let condominio: CondominioRecord;
    try {
      condominio = await db.condominio.create({ data });
    } catch (error) {
      if (isDatabaseTimeZoneRejection(error)) {
        return reply.status(400).send({ error: 'Invalid condominium timezone' });
      }
      throw error;
    }
    return reply.status(201).send(toCondominioResponse(condominio));
  });

  app.get('/condominios', condominioManagement, async () => {
    const condominios = await db.condominio.findMany({
      where: { deletedAt: null },
      orderBy: { createdAt: 'desc' }
    });

    return condominios.map(toCondominioResponse);
  });

  app.get('/condominios/:id', condominioManagement, async (request, reply) => {
    const id = parseId(request.params);

    if (!id) {
      return reply.status(400).send({ error: 'Invalid condominium id' });
    }

    const condominio = await db.condominio.findFirst({ where: { id, deletedAt: null } });

    if (!condominio) {
      return reply.status(404).send({ error: 'Condominium not found' });
    }

    return toCondominioResponse(condominio);
  });

  app.patch('/condominios/:id', condominioManagement, async (request, reply) => {
    const id = parseId(request.params);

    if (!id) {
      return reply.status(400).send({ error: 'Invalid condominium id' });
    }

    const payload = request.body && typeof request.body === 'object' && !Array.isArray(request.body)
      ? request.body as Record<string, unknown>
      : null;
    const timezone = payload?.timezone;
    if (payload && Object.hasOwn(payload, 'timezone')
      && (typeof timezone !== 'string' || !isValidTimeZone(timezone.trim()))) {
      return reply.status(400).send({ error: 'Invalid condominium timezone' });
    }
    const data = parseUpdateBody(request.body);

    if (!data) {
      return reply.status(400).send({ error: 'Invalid condominium payload' });
    }

    let result: { count: number };
    try {
      result = await db.condominio.updateMany({ where: { id, deletedAt: null }, data });
    } catch (error) {
      if (isDatabaseTimeZoneRejection(error)) {
        return reply.status(400).send({ error: 'Invalid condominium timezone' });
      }
      throw error;
    }

    if (result.count === 0) {
      return reply.status(404).send({ error: 'Condominium not found' });
    }

    const condominio = await db.condominio.findFirst({ where: { id, deletedAt: null } });

    if (!condominio) {
      return reply.status(404).send({ error: 'Condominium not found' });
    }

    return toCondominioResponse(condominio);
  });

  app.delete('/condominios/:id', condominioManagement, async (request, reply) => {
    const id = parseId(request.params);

    if (!id) {
      return reply.status(400).send({ error: 'Invalid condominium id' });
    }

    const result = await db.condominio.updateMany({
      where: { id, deletedAt: null },
      data: { deletedAt: new Date() }
    });

    if (result.count === 0) {
      return reply.status(404).send({ error: 'Condominium not found' });
    }

    return reply.status(204).send();
  });

  app.patch('/condominios/:id/limite-diario-convites', invitationLimitManagement, async (request, reply) => {
    const id = parseId(request.params);
    const dailyInvitationLimit = parseDailyInvitationLimit(request.body);
    if (!id || dailyInvitationLimit === undefined) {
      return reply.status(400).send({ error: 'Invalid daily invitation limit' });
    }
    const result = await db.condominio.updateMany({ where: { id, deletedAt: null }, data: { dailyInvitationLimit } });
    if (result.count === 0) {
      return reply.status(404).send({ error: 'Condominium not found' });
    }
    return { dailyInvitationLimit };
  });

  app.post('/moradores', createMoradorManagement, async (request, reply) => {
    const data = parseMoradorCreateBody(request.body);

    if (!data) {
      return reply.status(400).send({ error: 'Invalid resident payload' });
    }

    const morador = await db.morador.create({ data });

    if (!morador) {
      return reply.status(404).send({ error: 'Condominium not found' });
    }

    return reply.status(201).send(toMoradorResponse(morador));
  });

  app.get('/condominios/:condominioId/moradores', nestedMoradorManagement, async (request, reply) => {
    const condominioId = parseUuidParam(request.params, 'condominioId');

    if (!condominioId) {
      return reply.status(400).send({ error: 'Invalid condominium id' });
    }

    const moradores = await db.morador.findMany({
      where: { condominioId, deletedAt: null, condominio: activeCondominio },
      orderBy: { createdAt: 'desc' }
    });

    return moradores.map(toMoradorResponse);
  });

  app.get('/condominios/:condominioId/moradores/:id', nestedMoradorManagement, async (request, reply) => {
    const condominioId = parseUuidParam(request.params, 'condominioId');
    const id = parseId(request.params);

    if (!condominioId) {
      return reply.status(400).send({ error: 'Invalid condominium id' });
    }

    if (!id) {
      return reply.status(400).send({ error: 'Invalid resident id' });
    }

    const morador = await db.morador.findFirst({
      where: { id, condominioId, deletedAt: null, condominio: activeCondominio }
    });

    if (!morador) {
      return reply.status(404).send({ error: 'Resident not found' });
    }

    return toMoradorResponse(morador);
  });

  app.patch('/condominios/:condominioId/moradores/:id', nestedMoradorManagement, async (request, reply) => {
    const condominioId = parseUuidParam(request.params, 'condominioId');
    const id = parseId(request.params);

    if (!condominioId) {
      return reply.status(400).send({ error: 'Invalid condominium id' });
    }

    if (!id) {
      return reply.status(400).send({ error: 'Invalid resident id' });
    }

    const data = parseMoradorUpdateBody(request.body);

    if (!data) {
      return reply.status(400).send({ error: 'Invalid resident payload' });
    }

    const result = await db.morador.updateMany({
      where: { id, condominioId, deletedAt: null, condominio: activeCondominio },
      data
    });

    if (result.count === 0) {
      return reply.status(404).send({ error: 'Resident not found' });
    }

    const morador = await db.morador.findFirst({
      where: { id, condominioId, deletedAt: null, condominio: activeCondominio }
    });

    if (!morador) {
      return reply.status(404).send({ error: 'Resident not found' });
    }

    return toMoradorResponse(morador);
  });

  app.delete('/condominios/:condominioId/moradores/:id', nestedMoradorManagement, async (request, reply) => {
    const condominioId = parseUuidParam(request.params, 'condominioId');
    const id = parseId(request.params);

    if (!condominioId) {
      return reply.status(400).send({ error: 'Invalid condominium id' });
    }

    if (!id) {
      return reply.status(400).send({ error: 'Invalid resident id' });
    }

    const result = await db.morador.updateMany({
      where: { id, condominioId, deletedAt: null, condominio: activeCondominio },
      data: { deletedAt: new Date() }
    });

    if (result.count === 0) {
      return reply.status(404).send({ error: 'Resident not found' });
    }

    return reply.status(204).send();
  });

  app.patch('/condominios/:condominioId/moradores/:id/limite-diario-convites', invitationLimitManagement, async (request, reply) => {
    const condominioId = parseUuidParam(request.params, 'condominioId');
    const id = parseId(request.params);
    const dailyInvitationLimit = parseDailyInvitationLimit(request.body);
    if (!condominioId || !id || dailyInvitationLimit === undefined) {
      return reply.status(400).send({ error: 'Invalid daily invitation limit' });
    }
    const result = await db.morador.updateMany({
      where: { id, condominioId, deletedAt: null, condominio: activeCondominio },
      data: { dailyInvitationLimit }
    });
    if (result.count === 0) {
      return reply.status(404).send({ error: 'Resident not found' });
    }
    return { dailyInvitationLimit };
  });

  registerConvidadoRoutes(app, db, authenticator);
  registerDeviceRoutes(app, db.dispositivo, authenticator);
  registerConviteRoutes(
    app,
    db,
    db.convite,
    authenticator,
    effectiveNotificationSender,
    publicValidationBaseUrl,
    deviceRateLimiter,
    developmentRateLimiter,
    secureValidationTransport,
    authRateLimiter
  );
  registerNotificationRoutes(app, db.notificacao, authenticator);
  registerOidcRoutes(
    app, oidcService, browserSessionService, browserSessionStore, humanAdministrationService, authRateLimiter
  );
  registerBrowserAuthRoutes(app, browserSessionStore, browserSessionService, oidcService, authRateLimiter);
  registerHumanAdministrationRoutes(app, authenticator, humanAdministrationService);

  return app;
}
