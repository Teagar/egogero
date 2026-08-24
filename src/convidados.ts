import type { FastifyInstance } from 'fastify';

import type { AppStore } from './app.js';
import { authorize, isUuid } from './auth.js';
import type { Authenticator } from './auth.js';

type ConvidadoBody = Partial<Record<'nome', unknown>>;
type ConvidadoRecord = NonNullable<Awaited<ReturnType<AppStore['convidado']['findFirst']>>>;
type GuestRouteStore = Pick<AppStore, 'morador' | 'convidado'>;

const activeCondominio = { deletedAt: null } as const;
const activeGuestParents = {
  condominio: activeCondominio,
  morador: { is: { deletedAt: null } }
} as const;
const recentOrder = [
  { ultimoUsoEm: { sort: 'desc', nulls: 'last' } },
  { createdAt: 'desc' },
  { id: 'desc' }
] as const;

function parseUuidParam(params: unknown, field: string) {
  if (!params || typeof params !== 'object' || Array.isArray(params)) {
    return null;
  }

  const value = (params as Record<string, unknown>)[field];
  return isUuid(value) ? value : null;
}

function parseConvidadoBody(body: unknown) {
  if (!body || typeof body !== 'object' || Array.isArray(body)) {
    return null;
  }

  const value = (body as ConvidadoBody).nome;
  if (typeof value !== 'string') {
    return null;
  }

  const nome = value.trim();
  return nome ? { nome } : null;
}

function parseLimit(query: unknown) {
  if (!query || typeof query !== 'object' || Array.isArray(query)) {
    return 10;
  }

  const payload = query as Record<string, unknown>;
  const value = payload.limite ?? payload.limit;
  if (value === undefined) {
    return 10;
  }

  const parsed = typeof value === 'string' && /^[1-9][0-9]*$/.test(value) ? Number(value) : NaN;
  return Number.isInteger(parsed) && parsed <= 100 ? parsed : null;
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

async function hasActiveMorador(db: GuestRouteStore, condominioId: string, moradorId: string) {
  return db.morador.findFirst({
    where: { id: moradorId, condominioId, deletedAt: null, condominio: activeCondominio }
  });
}

export function registerConvidadoRoutes(app: FastifyInstance, db: GuestRouteStore, authenticator: Authenticator) {
  const guestManagement = {
    preHandler: authorize(
      authenticator,
      'convidados:manage',
      (request) => parseUuidParam(request.params, 'condominioId'),
      (request) => parseUuidParam(request.params, 'moradorId')
    )
  };
  const collectionPath = '/condominios/:condominioId/moradores/:moradorId/convidados';

  app.get(`${collectionPath}/recentes`, guestManagement, async (request, reply) => {
    const condominioId = parseUuidParam(request.params, 'condominioId');
    const moradorId = parseUuidParam(request.params, 'moradorId');
    const limit = parseLimit(request.query);

    if (!condominioId || !moradorId || !limit) {
      return reply.status(400).send({ error: 'Invalid recent guests query' });
    }

    if (!await hasActiveMorador(db, condominioId, moradorId)) {
      return reply.status(404).send({ error: 'Resident not found' });
    }

    const convidados = await db.convidado.findMany({
      where: { condominioId, moradorId, deletedAt: null, ...activeGuestParents },
      orderBy: [...recentOrder],
      take: limit
    });
    return convidados.map(toConvidadoResponse);
  });

  app.post(collectionPath, guestManagement, async (request, reply) => {
    const condominioId = parseUuidParam(request.params, 'condominioId');
    const moradorId = parseUuidParam(request.params, 'moradorId');
    const data = parseConvidadoBody(request.body);

    if (!condominioId || !moradorId || !data) {
      return reply.status(400).send({ error: 'Invalid guest payload' });
    }

    const convidado = await db.convidado.create({ data: { ...data, condominioId, moradorId } });
    if (!convidado) {
      return reply.status(404).send({ error: 'Resident not found' });
    }

    return reply.status(201).send(toConvidadoResponse(convidado));
  });

  app.get(collectionPath, guestManagement, async (request, reply) => {
    const condominioId = parseUuidParam(request.params, 'condominioId');
    const moradorId = parseUuidParam(request.params, 'moradorId');

    if (!condominioId || !moradorId) {
      return reply.status(400).send({ error: 'Invalid guest scope' });
    }

    if (!await hasActiveMorador(db, condominioId, moradorId)) {
      return reply.status(404).send({ error: 'Resident not found' });
    }

    const convidados = await db.convidado.findMany({
      where: { condominioId, moradorId, deletedAt: null, ...activeGuestParents },
      orderBy: [...recentOrder]
    });
    return convidados.map(toConvidadoResponse);
  });

  app.get(`${collectionPath}/:id`, guestManagement, async (request, reply) => {
    const condominioId = parseUuidParam(request.params, 'condominioId');
    const moradorId = parseUuidParam(request.params, 'moradorId');
    const id = parseUuidParam(request.params, 'id');

    if (!condominioId || !moradorId || !id) {
      return reply.status(400).send({ error: 'Invalid guest id' });
    }

    const convidado = await db.convidado.findFirst({
      where: { id, condominioId, moradorId, deletedAt: null, ...activeGuestParents }
    });
    return convidado
      ? toConvidadoResponse(convidado)
      : reply.status(404).send({ error: 'Guest not found' });
  });

  app.patch(`${collectionPath}/:id`, guestManagement, async (request, reply) => {
    const condominioId = parseUuidParam(request.params, 'condominioId');
    const moradorId = parseUuidParam(request.params, 'moradorId');
    const id = parseUuidParam(request.params, 'id');
    const data = parseConvidadoBody(request.body);

    if (!condominioId || !moradorId || !id || !data) {
      return reply.status(400).send({ error: 'Invalid guest payload' });
    }

    const where = { id, condominioId, moradorId, deletedAt: null, ...activeGuestParents } as const;
    const result = await db.convidado.updateMany({ where, data });
    if (!result.count) {
      return reply.status(404).send({ error: 'Guest not found' });
    }

    const convidado = await db.convidado.findFirst({ where });
    return convidado
      ? toConvidadoResponse(convidado)
      : reply.status(404).send({ error: 'Guest not found' });
  });

  app.delete(`${collectionPath}/:id`, guestManagement, async (request, reply) => {
    const condominioId = parseUuidParam(request.params, 'condominioId');
    const moradorId = parseUuidParam(request.params, 'moradorId');
    const id = parseUuidParam(request.params, 'id');

    if (!condominioId || !moradorId || !id) {
      return reply.status(400).send({ error: 'Invalid guest id' });
    }

    const result = await db.convidado.updateMany({
      where: { id, condominioId, moradorId, deletedAt: null, ...activeGuestParents },
      data: { deletedAt: new Date() }
    });
    return result.count
      ? reply.status(204).send()
      : reply.status(404).send({ error: 'Guest not found' });
  });
}
