import Fastify from 'fastify';

import { authorize, isUuid, unauthenticatedAuthenticator } from './auth.js';
import type { Authenticator } from './auth.js';
import { prisma as defaultPrisma } from './lib/prisma.js';

type CondominioRecord = {
  id: string;
  createdAt: Date;
  deletedAt: Date | null;
  nome: string;
  responsavel: string;
  tipo: string;
};

type CondominioCreateData = {
  nome: string;
  responsavel: string;
  tipo: string;
};

type CondominioUpdateData = Partial<CondominioCreateData> & {
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
    deletedAt?: Date;
  };

type ConvidadoRecord = {
  id: string;
  createdAt: Date;
  deletedAt: Date | null;
  nome: string;
  condominioId: string;
  moradorId: string;
  ultimoUsoEm: Date | null;
};

type ConvidadoCreateData = { nome: string; condominioId: string; moradorId: string };
type ConvidadoUpdateData = { nome?: string; ultimoUsoEm?: Date | null; deletedAt?: Date };

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
  convidado?: {
    create(args: { data: ConvidadoCreateData }): Promise<ConvidadoRecord>;
    findMany(args: {
      where: { condominioId: string; moradorId: string; deletedAt: null };
      orderBy: [{ ultimoUsoEm: 'desc' }, { createdAt: 'desc' }];
      take?: number;
    }): Promise<ConvidadoRecord[]>;
    findFirst(args: {
      where: { id: string; condominioId: string; moradorId: string; deletedAt: null };
    }): Promise<ConvidadoRecord | null>;
    updateMany(args: {
      where: { id: string; condominioId: string; moradorId: string; deletedAt: null };
      data: ConvidadoUpdateData;
    }): Promise<{ count: number }>;
  };
};

export type CondominioStore = AppStore;

type CondominioBody = Partial<Record<keyof CondominioCreateData, unknown>>;
type MoradorBody = Partial<Record<'nome' | 'condominioId' | 'endereco', unknown>>;
type EnderecoBody = Partial<Record<'rua' | 'numero' | 'bloco' | 'apartamento', unknown>>;
type ConvidadoBody = Partial<Record<'nome', unknown>>;

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

  if (!nome || !responsavel || !tipo) {
    return null;
  }

  return { nome, responsavel, tipo };
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

function parseConvidadoBody(body: unknown) {
  if (!body || typeof body !== 'object' || Array.isArray(body)) return null;
  const nome = readRequiredString(body as ConvidadoBody, 'nome');
  return nome ? { nome } : null;
}

function parseLimit(query: unknown) {
  if (!query || typeof query !== 'object' || Array.isArray(query)) return 10;
  const value = (query as Record<string, unknown>).limite ?? (query as Record<string, unknown>).limit;
  if (value === undefined) return 10;
  const parsed = typeof value === 'string' && /^[1-9][0-9]*$/.test(value) ? Number(value) : NaN;
  return Number.isInteger(parsed) && parsed <= 100 ? parsed : null;
}

function toCondominioResponse(condominio: CondominioRecord) {
  return {
    id: condominio.id,
    createdAt: condominio.createdAt.toISOString(),
    nome: condominio.nome,
    responsavel: condominio.responsavel,
    tipo: condominio.tipo
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

function toConvidadoResponse(convidado: ConvidadoRecord) {
  return {
    id: convidado.id,
    createdAt: convidado.createdAt.toISOString(),
    condominioId: convidado.condominioId,
    moradorId: convidado.moradorId,
    nome: convidado.nome,
    ultimoUsoEm: convidado.ultimoUsoEm?.toISOString() ?? null
  };
}

async function ensureActiveCondominio(db: AppStore, condominioId: string) {
  return db.condominio.findFirst({ where: { id: condominioId, deletedAt: null } });
}

async function ensureActiveMorador(db: AppStore, condominioId: string, moradorId: string) {
  return db.morador.findFirst({
    where: { id: moradorId, condominioId, deletedAt: null, condominio: activeCondominio }
  });
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
  convidado: defaultPrisma.convidado
};

export function createApp(
  {
    db = defaultStore,
    authenticator = unauthenticatedAuthenticator
  }: { db?: AppStore; authenticator?: Authenticator } = {}
) {
  const app = Fastify({ logger: false });
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
  const guestManagement = {
    preHandler: authorize(
      authenticator,
      'convidados:manage',
      (request) => parseUuidParam(request.params, 'condominioId'),
      (request) => parseUuidParam(request.params, 'moradorId')
    )
  };

  app.get('/health', async () => ({ status: 'ok' }));

  app.post('/condominios', condominioManagement, async (request, reply) => {
    const data = parseCreateBody(request.body);

    if (!data) {
      return reply.status(400).send({ error: 'Invalid condominium payload' });
    }

    const condominio = await db.condominio.create({ data });
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

    const data = parseUpdateBody(request.body);

    if (!data) {
      return reply.status(400).send({ error: 'Invalid condominium payload' });
    }

    const result = await db.condominio.updateMany({ where: { id, deletedAt: null }, data });

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

  app.get('/condominios/:condominioId/moradores/:moradorId/convidados/recentes', guestManagement, async (request, reply) => {
    const condominioId = parseUuidParam(request.params, 'condominioId');
    const moradorId = parseUuidParam(request.params, 'moradorId');
    const limit = parseLimit(request.query);
    if (!condominioId || !moradorId || !limit) return reply.status(400).send({ error: 'Invalid recent guests query' });
    if (!await ensureActiveCondominio(db, condominioId) || !await ensureActiveMorador(db, condominioId, moradorId)) {
      return reply.status(404).send({ error: 'Resident not found' });
    }
    const convidados = await db.convidado!.findMany({
      where: { condominioId, moradorId, deletedAt: null },
      orderBy: [{ ultimoUsoEm: 'desc' }, { createdAt: 'desc' }],
      take: limit
    });
    return convidados.map(toConvidadoResponse);
  });

  app.post('/condominios/:condominioId/moradores/:moradorId/convidados', guestManagement, async (request, reply) => {
    const condominioId = parseUuidParam(request.params, 'condominioId');
    const moradorId = parseUuidParam(request.params, 'moradorId');
    const data = parseConvidadoBody(request.body);
    if (!condominioId || !moradorId || !data) return reply.status(400).send({ error: 'Invalid guest payload' });
    if (!await ensureActiveCondominio(db, condominioId) || !await ensureActiveMorador(db, condominioId, moradorId)) {
      return reply.status(404).send({ error: 'Resident not found' });
    }
    const convidado = await db.convidado!.create({ data: { ...data, condominioId, moradorId } });
    return reply.status(201).send(toConvidadoResponse(convidado));
  });

  app.get('/condominios/:condominioId/moradores/:moradorId/convidados', guestManagement, async (request, reply) => {
    const condominioId = parseUuidParam(request.params, 'condominioId');
    const moradorId = parseUuidParam(request.params, 'moradorId');
    if (!condominioId || !moradorId) return reply.status(400).send({ error: 'Invalid guest scope' });
    if (!await ensureActiveMorador(db, condominioId, moradorId)) return reply.status(404).send({ error: 'Resident not found' });
    const convidados = await db.convidado!.findMany({
      where: { condominioId, moradorId, deletedAt: null },
      orderBy: [{ ultimoUsoEm: 'desc' }, { createdAt: 'desc' }]
    });
    return convidados.map(toConvidadoResponse);
  });

  app.get('/condominios/:condominioId/moradores/:moradorId/convidados/:id', guestManagement, async (request, reply) => {
    const condominioId = parseUuidParam(request.params, 'condominioId');
    const moradorId = parseUuidParam(request.params, 'moradorId');
    const id = parseId(request.params);
    if (!condominioId || !moradorId || !id) return reply.status(400).send({ error: 'Invalid guest id' });
    const convidado = await db.convidado!.findFirst({ where: { id, condominioId, moradorId, deletedAt: null } });
    if (!convidado) return reply.status(404).send({ error: 'Guest not found' });
    return toConvidadoResponse(convidado);
  });

  app.patch('/condominios/:condominioId/moradores/:moradorId/convidados/:id', guestManagement, async (request, reply) => {
    const condominioId = parseUuidParam(request.params, 'condominioId');
    const moradorId = parseUuidParam(request.params, 'moradorId');
    const id = parseId(request.params);
    const data = parseConvidadoBody(request.body);
    if (!condominioId || !moradorId || !id || !data) return reply.status(400).send({ error: 'Invalid guest payload' });
    const result = await db.convidado!.updateMany({ where: { id, condominioId, moradorId, deletedAt: null }, data });
    if (!result.count) return reply.status(404).send({ error: 'Guest not found' });
    const convidado = await db.convidado!.findFirst({ where: { id, condominioId, moradorId, deletedAt: null } });
    return convidado ? toConvidadoResponse(convidado) : reply.status(404).send({ error: 'Guest not found' });
  });

  app.delete('/condominios/:condominioId/moradores/:moradorId/convidados/:id', guestManagement, async (request, reply) => {
    const condominioId = parseUuidParam(request.params, 'condominioId');
    const moradorId = parseUuidParam(request.params, 'moradorId');
    const id = parseId(request.params);
    if (!condominioId || !moradorId || !id) return reply.status(400).send({ error: 'Invalid guest id' });
    const result = await db.convidado!.updateMany({ where: { id, condominioId, moradorId, deletedAt: null }, data: { deletedAt: new Date() } });
    if (!result.count) return reply.status(404).send({ error: 'Guest not found' });
    return reply.status(204).send();
  });

  return app;
}
