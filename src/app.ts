import Fastify from 'fastify';
import type { FastifyReply, FastifyRequest } from 'fastify';

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
  moradorId: string | null;
  ultimoUsoEm: Date | null;
};

type ConvidadoCreateData = { nome: string; condominioId: string; moradorId: string };
type ConvidadoUpdateData = { nome?: string; ultimoUsoEm?: Date | null; deletedAt?: Date };
type ConvidadoOrderBy = { ultimoUsoEm: { sort: 'desc'; nulls: 'last' } } | { createdAt: 'desc' } | { id: 'desc' };

export type AppStore = {
  condominio: {
    create(args: { data: CondominioCreateData }): Promise<CondominioRecord>;
    findMany(args: { where: { deletedAt: null }; orderBy: { createdAt: 'desc' } }): Promise<CondominioRecord[]>;
    findFirst(args: { where: { id: string; deletedAt: null } }): Promise<CondominioRecord | null>;
    updateMany(args: { where: { id: string; deletedAt: null }; data: CondominioUpdateData }): Promise<{ count: number }>;
  };
  morador: {
    create(args: { data: MoradorCreateData }): Promise<MoradorRecord>;
    findMany(args: {
      where: { condominioId: string; deletedAt: null };
      orderBy: { createdAt: 'desc' };
    }): Promise<MoradorRecord[]>;
    findFirst(args: {
      where: { id: string; condominioId?: string; deletedAt: null };
    }): Promise<MoradorRecord | null>;
    updateMany(args: {
      where: { id: string; condominioId: string; deletedAt: null };
      data: MoradorUpdateData;
    }): Promise<{ count: number }>;
  };
  convidado?: {
    create(args: { data: ConvidadoCreateData }): Promise<ConvidadoRecord>;
    findMany(args: {
      where: { condominioId: string; moradorId: string; deletedAt: null };
      orderBy: ConvidadoOrderBy[];
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

const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

function requireRoles(request: FastifyRequest, reply: FastifyReply, allowedRoles: string[]) {
  const roleHeader = request.headers['x-user-role'];
  const role = Array.isArray(roleHeader) ? roleHeader[0] : roleHeader;

  if (!role) {
    reply.status(401).send({ error: 'Authentication required' });
    return false;
  }

  if (!allowedRoles.includes(role)) {
    reply.status(403).send({ error: 'Forbidden' });
    return false;
  }

  return true;
}

function requireProvedor(request: FastifyRequest, reply: FastifyReply) {
  return requireRoles(request, reply, ['provedor']);
}

function requireMoradorManager(request: FastifyRequest, reply: FastifyReply) {
  return requireRoles(request, reply, ['provedor', 'sindico']);
}

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
  return typeof value === 'string' && UUID_PATTERN.test(value) ? value : null;
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
  const condominioId = typeof payload.condominioId === 'string' && UUID_PATTERN.test(payload.condominioId) ? payload.condominioId : null;
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
  return db.morador.findFirst({ where: { id: moradorId, condominioId, deletedAt: null } });
}

async function ensureActiveGuestScope(db: AppStore, condominioId: string, moradorId: string) {
  if (!await ensureActiveCondominio(db, condominioId)) {
    return 'condominio' as const;
  }

  return await ensureActiveMorador(db, condominioId, moradorId) ? null : 'morador' as const;
}

function guestScopeNotFound(reply: FastifyReply, inactiveParent: 'condominio' | 'morador') {
  return reply.status(404).send({ error: inactiveParent === 'condominio' ? 'Condominium not found' : 'Resident not found' });
}

export function createApp({ db = defaultPrisma }: { db?: AppStore } = {}) {
  const app = Fastify({ logger: false });

  app.get('/health', async () => ({ status: 'ok' }));

  app.post('/condominios', async (request, reply) => {
    if (!requireProvedor(request, reply)) {
      return;
    }

    const data = parseCreateBody(request.body);

    if (!data) {
      return reply.status(400).send({ error: 'Invalid condominium payload' });
    }

    const condominio = await db.condominio.create({ data });
    return reply.status(201).send(toCondominioResponse(condominio));
  });

  app.get('/condominios', async (request, reply) => {
    if (!requireProvedor(request, reply)) {
      return;
    }

    const condominios = await db.condominio.findMany({
      where: { deletedAt: null },
      orderBy: { createdAt: 'desc' }
    });

    return condominios.map(toCondominioResponse);
  });

  app.get('/condominios/:id', async (request, reply) => {
    if (!requireProvedor(request, reply)) {
      return;
    }

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

  app.patch('/condominios/:id', async (request, reply) => {
    if (!requireProvedor(request, reply)) {
      return;
    }

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

  app.delete('/condominios/:id', async (request, reply) => {
    if (!requireProvedor(request, reply)) {
      return;
    }

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

  app.post('/moradores', async (request, reply) => {
    if (!requireMoradorManager(request, reply)) {
      return;
    }

    const data = parseMoradorCreateBody(request.body);

    if (!data) {
      return reply.status(400).send({ error: 'Invalid resident payload' });
    }

    const condominio = await ensureActiveCondominio(db, data.condominioId);

    if (!condominio) {
      return reply.status(404).send({ error: 'Condominium not found' });
    }

    const morador = await db.morador.create({ data });
    return reply.status(201).send(toMoradorResponse(morador));
  });

  app.get('/condominios/:condominioId/moradores', async (request, reply) => {
    if (!requireMoradorManager(request, reply)) {
      return;
    }

    const condominioId = parseUuidParam(request.params, 'condominioId');

    if (!condominioId) {
      return reply.status(400).send({ error: 'Invalid condominium id' });
    }

    const condominio = await ensureActiveCondominio(db, condominioId);

    if (!condominio) {
      return reply.status(404).send({ error: 'Condominium not found' });
    }

    const moradores = await db.morador.findMany({
      where: { condominioId, deletedAt: null },
      orderBy: { createdAt: 'desc' }
    });

    return moradores.map(toMoradorResponse);
  });

  app.get('/condominios/:condominioId/moradores/:id', async (request, reply) => {
    if (!requireMoradorManager(request, reply)) {
      return;
    }

    const condominioId = parseUuidParam(request.params, 'condominioId');
    const id = parseId(request.params);

    if (!condominioId) {
      return reply.status(400).send({ error: 'Invalid condominium id' });
    }

    if (!id) {
      return reply.status(400).send({ error: 'Invalid resident id' });
    }

    const condominio = await ensureActiveCondominio(db, condominioId);

    if (!condominio) {
      return reply.status(404).send({ error: 'Condominium not found' });
    }

    const morador = await db.morador.findFirst({ where: { id, condominioId, deletedAt: null } });

    if (!morador) {
      return reply.status(404).send({ error: 'Resident not found' });
    }

    return toMoradorResponse(morador);
  });

  app.patch('/condominios/:condominioId/moradores/:id', async (request, reply) => {
    if (!requireMoradorManager(request, reply)) {
      return;
    }

    const condominioId = parseUuidParam(request.params, 'condominioId');
    const id = parseId(request.params);

    if (!condominioId) {
      return reply.status(400).send({ error: 'Invalid condominium id' });
    }

    if (!id) {
      return reply.status(400).send({ error: 'Invalid resident id' });
    }

    const condominio = await ensureActiveCondominio(db, condominioId);

    if (!condominio) {
      return reply.status(404).send({ error: 'Condominium not found' });
    }

    const data = parseMoradorUpdateBody(request.body);

    if (!data) {
      return reply.status(400).send({ error: 'Invalid resident payload' });
    }

    const result = await db.morador.updateMany({ where: { id, condominioId, deletedAt: null }, data });

    if (result.count === 0) {
      return reply.status(404).send({ error: 'Resident not found' });
    }

    const morador = await db.morador.findFirst({ where: { id, condominioId, deletedAt: null } });

    if (!morador) {
      return reply.status(404).send({ error: 'Resident not found' });
    }

    return toMoradorResponse(morador);
  });

  app.delete('/condominios/:condominioId/moradores/:id', async (request, reply) => {
    if (!requireMoradorManager(request, reply)) {
      return;
    }

    const condominioId = parseUuidParam(request.params, 'condominioId');
    const id = parseId(request.params);

    if (!condominioId) {
      return reply.status(400).send({ error: 'Invalid condominium id' });
    }

    if (!id) {
      return reply.status(400).send({ error: 'Invalid resident id' });
    }

    const condominio = await ensureActiveCondominio(db, condominioId);

    if (!condominio) {
      return reply.status(404).send({ error: 'Condominium not found' });
    }

    const result = await db.morador.updateMany({
      where: { id, condominioId, deletedAt: null },
      data: { deletedAt: new Date() }
    });

    if (result.count === 0) {
      return reply.status(404).send({ error: 'Resident not found' });
    }

    return reply.status(204).send();
  });

  app.get('/condominios/:condominioId/moradores/:moradorId/convidados/recentes', async (request, reply) => {
    if (!requireMoradorManager(request, reply)) return;
    const condominioId = parseUuidParam(request.params, 'condominioId');
    const moradorId = parseUuidParam(request.params, 'moradorId');
    const limit = parseLimit(request.query);
    if (!condominioId || !moradorId || !limit) return reply.status(400).send({ error: 'Invalid recent guests query' });
    const inactiveParent = await ensureActiveGuestScope(db, condominioId, moradorId);
    if (inactiveParent) return guestScopeNotFound(reply, inactiveParent);
    const convidados = await db.convidado!.findMany({
      where: { condominioId, moradorId, deletedAt: null },
      orderBy: [{ ultimoUsoEm: { sort: 'desc', nulls: 'last' } }, { createdAt: 'desc' }, { id: 'desc' }],
      take: limit
    });
    return convidados.map(toConvidadoResponse);
  });

  app.post('/condominios/:condominioId/moradores/:moradorId/convidados', async (request, reply) => {
    if (!requireMoradorManager(request, reply)) return;
    const condominioId = parseUuidParam(request.params, 'condominioId');
    const moradorId = parseUuidParam(request.params, 'moradorId');
    const data = parseConvidadoBody(request.body);
    if (!condominioId || !moradorId || !data) return reply.status(400).send({ error: 'Invalid guest payload' });
    const inactiveParent = await ensureActiveGuestScope(db, condominioId, moradorId);
    if (inactiveParent) return guestScopeNotFound(reply, inactiveParent);
    const convidado = await db.convidado!.create({ data: { ...data, condominioId, moradorId } });
    return reply.status(201).send(toConvidadoResponse(convidado));
  });

  app.get('/condominios/:condominioId/moradores/:moradorId/convidados', async (request, reply) => {
    if (!requireMoradorManager(request, reply)) return;
    const condominioId = parseUuidParam(request.params, 'condominioId');
    const moradorId = parseUuidParam(request.params, 'moradorId');
    if (!condominioId || !moradorId) return reply.status(400).send({ error: 'Invalid guest scope' });
    const inactiveParent = await ensureActiveGuestScope(db, condominioId, moradorId);
    if (inactiveParent) return guestScopeNotFound(reply, inactiveParent);
    const convidados = await db.convidado!.findMany({
      where: { condominioId, moradorId, deletedAt: null },
      orderBy: [{ ultimoUsoEm: { sort: 'desc', nulls: 'last' } }, { createdAt: 'desc' }, { id: 'desc' }]
    });
    return convidados.map(toConvidadoResponse);
  });

  app.get('/condominios/:condominioId/moradores/:moradorId/convidados/:id', async (request, reply) => {
    if (!requireMoradorManager(request, reply)) return;
    const condominioId = parseUuidParam(request.params, 'condominioId');
    const moradorId = parseUuidParam(request.params, 'moradorId');
    const id = parseId(request.params);
    if (!condominioId || !moradorId || !id) return reply.status(400).send({ error: 'Invalid guest id' });
    const inactiveParent = await ensureActiveGuestScope(db, condominioId, moradorId);
    if (inactiveParent) return guestScopeNotFound(reply, inactiveParent);
    const convidado = await db.convidado!.findFirst({ where: { id, condominioId, moradorId, deletedAt: null } });
    if (!convidado) return reply.status(404).send({ error: 'Guest not found' });
    return toConvidadoResponse(convidado);
  });

  app.patch('/condominios/:condominioId/moradores/:moradorId/convidados/:id', async (request, reply) => {
    if (!requireMoradorManager(request, reply)) return;
    const condominioId = parseUuidParam(request.params, 'condominioId');
    const moradorId = parseUuidParam(request.params, 'moradorId');
    const id = parseId(request.params);
    const data = parseConvidadoBody(request.body);
    if (!condominioId || !moradorId || !id || !data) return reply.status(400).send({ error: 'Invalid guest payload' });
    const inactiveParent = await ensureActiveGuestScope(db, condominioId, moradorId);
    if (inactiveParent) return guestScopeNotFound(reply, inactiveParent);
    const result = await db.convidado!.updateMany({ where: { id, condominioId, moradorId, deletedAt: null }, data });
    if (!result.count) return reply.status(404).send({ error: 'Guest not found' });
    const convidado = await db.convidado!.findFirst({ where: { id, condominioId, moradorId, deletedAt: null } });
    return convidado ? toConvidadoResponse(convidado) : reply.status(404).send({ error: 'Guest not found' });
  });

  app.delete('/condominios/:condominioId/moradores/:moradorId/convidados/:id', async (request, reply) => {
    if (!requireMoradorManager(request, reply)) return;
    const condominioId = parseUuidParam(request.params, 'condominioId');
    const moradorId = parseUuidParam(request.params, 'moradorId');
    const id = parseId(request.params);
    if (!condominioId || !moradorId || !id) return reply.status(400).send({ error: 'Invalid guest id' });
    const inactiveParent = await ensureActiveGuestScope(db, condominioId, moradorId);
    if (inactiveParent) return guestScopeNotFound(reply, inactiveParent);
    const result = await db.convidado!.updateMany({ where: { id, condominioId, moradorId, deletedAt: null }, data: { deletedAt: new Date() } });
    if (!result.count) return reply.status(404).send({ error: 'Guest not found' });
    return reply.status(204).send();
  });

  return app;
}
