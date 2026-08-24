import type { Prisma, PrismaClient } from '@prisma/client';
import type { FastifyInstance } from 'fastify';

import { authorize, isUuid } from './auth.js';
import type { Authenticator } from './auth.js';

export type EntryNotificationEvent = {
  invitationId: string;
  condominiumId: string;
  residentId: string;
  guestId: string;
  guestName: string;
  enteredAt: Date;
};

export type EntryNotificationRecord = {
  id: string;
  createdAt: Date;
  readAt: Date | null;
  message: string;
  guestName: string;
  enteredAt: Date;
  invitationId: string;
  guestId: string;
};

export interface NotificationStore {
  list(args: { condominiumId: string; residentId: string; unreadOnly: boolean; limit: number }): Promise<EntryNotificationRecord[]>;
  markRead(args: { id: string; condominiumId: string; residentId: string; now: Date }): Promise<'read' | 'unavailable'>;
}

export async function insertEntryNotification(transaction: Prisma.TransactionClient, event: EntryNotificationEvent) {
  await transaction.notificacao.create({
    data: {
      condominioId: event.condominiumId,
      moradorId: event.residentId,
      convidadoId: event.guestId,
      conviteId: event.invitationId,
      tipo: 'entrada_visitante',
      mensagem: `${event.guestName} entrou no condomínio`,
      nomeConvidado: event.guestName,
      entrouEm: event.enteredAt
    }
  });
}

export function createPrismaNotificationStore(client: PrismaClient): NotificationStore {
  return {
    async list({ condominiumId, residentId, unreadOnly, limit }) {
      const rows = await client.notificacao.findMany({
        where: { condominioId: condominiumId, moradorId: residentId, deletedAt: null, ...(unreadOnly ? { lidaEm: null } : {}) },
        orderBy: { createdAt: 'desc' },
        take: limit
      });
      return rows.map((row) => ({ id: row.id, createdAt: row.createdAt, readAt: row.lidaEm, message: row.mensagem, guestName: row.nomeConvidado, enteredAt: row.entrouEm, invitationId: row.conviteId, guestId: row.convidadoId }));
    },
    async markRead({ id, condominiumId, residentId, now }) {
      const result = await client.notificacao.updateMany({ where: { id, condominioId: condominiumId, moradorId: residentId, deletedAt: null }, data: { lidaEm: now } });
      return result.count === 1 ? 'read' : 'unavailable';
    }
  };
}

function uuidParam(params: unknown, name: string) {
  if (!params || typeof params !== 'object' || Array.isArray(params)) return null;
  const value = (params as Record<string, unknown>)[name];
  return isUuid(value) ? value : null;
}

export function registerNotificationRoutes(app: FastifyInstance, store: NotificationStore | undefined, authenticator: Authenticator) {
  const path = '/condominios/:condominioId/moradores/:moradorId/notificacoes';
  const scope = authorize(authenticator, 'notificacoes:read', (request) => uuidParam(request.params, 'condominioId'), (request) => uuidParam(request.params, 'moradorId'));
  app.get(path, { preHandler: scope }, async (request, reply) => {
    const condominiumId = uuidParam(request.params, 'condominioId');
    const residentId = uuidParam(request.params, 'moradorId');
    if (!condominiumId || !residentId) return reply.status(400).send({ error: 'Invalid notification scope' });
    if (!store) return reply.status(503).send({ error: 'Notification service unavailable' });
    const unreadOnly = (request.query as Record<string, unknown> | undefined)?.unread === 'true';
    const rows = await store.list({ condominiumId, residentId, unreadOnly, limit: 100 });
    return rows.map((row) => ({ id: row.id, createdAt: row.createdAt.toISOString(), readAt: row.readAt?.toISOString() ?? null, message: row.message, guestName: row.guestName, enteredAt: row.enteredAt.toISOString(), invitationId: row.invitationId, guestId: row.guestId }));
  });
  app.patch(`${path}/:notificationId`, { preHandler: scope }, async (request, reply) => {
    const condominiumId = uuidParam(request.params, 'condominioId');
    const residentId = uuidParam(request.params, 'moradorId');
    const notificationId = uuidParam(request.params, 'notificationId');
    if (!condominiumId || !residentId || !notificationId) return reply.status(400).send({ error: 'Invalid notification id' });
    if (!store) return reply.status(503).send({ error: 'Notification service unavailable' });
    const result = await store.markRead({ id: notificationId, condominiumId, residentId, now: new Date() });
    return result === 'read' ? { read: true } : reply.status(404).send({ error: 'Notification not found' });
  });
}
