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

export type CondominioStore = {
  condominio: {
    create(args: { data: CondominioCreateData }): Promise<CondominioRecord>;
    findMany(args: { where: { deletedAt: null }; orderBy: { createdAt: 'desc' } }): Promise<CondominioRecord[]>;
    findFirst(args: { where: { id: string; deletedAt: null } }): Promise<CondominioRecord | null>;
    updateMany(args: { where: { id: string; deletedAt: null }; data: CondominioUpdateData }): Promise<{ count: number }>;
  };
};

type CondominioBody = Partial<Record<keyof CondominioCreateData, unknown>>;

const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

function requireProvedor(request: FastifyRequest, reply: FastifyReply) {
  const roleHeader = request.headers['x-user-role'];
  const role = Array.isArray(roleHeader) ? roleHeader[0] : roleHeader;

  if (!role) {
    reply.status(401).send({ error: 'Authentication required' });
    return false;
  }

  if (role !== 'provedor') {
    reply.status(403).send({ error: 'Forbidden' });
    return false;
  }

  return true;
}

function readRequiredString(body: CondominioBody, field: keyof CondominioCreateData) {
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
  if (!params || typeof params !== 'object' || Array.isArray(params)) {
    return null;
  }

  const { id } = params as { id?: unknown };
  return typeof id === 'string' && UUID_PATTERN.test(id) ? id : null;
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

export function createApp({ db = defaultPrisma }: { db?: CondominioStore } = {}) {
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

  return app;
}
