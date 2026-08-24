import type { FastifyInstance } from 'fastify';

import type { AppStore } from './app.js';
import { authorize, isUuid } from './auth.js';
import type { Authenticator } from './auth.js';

export type InvitationIssue = {
  conviteId: string;
  convidadoId: string;
  token: string;
  expiraEm: Date;
};

export type InvitationBatch = {
  condominioId: string;
  moradorId: string;
  convidadoIds: readonly string[];
};

// PC-7 supplies the token implementation and must make this single call atomic.
export interface InvitationIssuer {
  issueForRegisteredGuests(batch: InvitationBatch): Promise<readonly InvitationIssue[]>;
}

export const unavailableInvitationIssuer: InvitationIssuer = {
  async issueForRegisteredGuests() {
    throw new InvitationIssuingUnavailableError();
  }
};

export class InvitationIssuingUnavailableError extends Error {
  constructor() {
    super('Invitation issuing is unavailable');
  }
}

type ConvitesBatchStore = Pick<AppStore, 'morador' | 'convidado'>;
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

function toInvitationResponse(invitation: InvitationIssue) {
  return {
    id: invitation.conviteId,
    convidadoId: invitation.convidadoId,
    token: invitation.token,
    expiraEm: invitation.expiraEm.toISOString()
  };
}

export function registerConviteRoutes(
  app: FastifyInstance,
  db: ConvitesBatchStore,
  authenticator: Authenticator,
  invitationIssuer: InvitationIssuer
) {
  const batchPath = '/condominios/:condominioId/moradores/:moradorId/convites/multiplos';
  const invitationManagement = {
    preHandler: authorize(
      authenticator,
      'convidados:manage',
      (request) => parseUuidParam(request.params, 'condominioId'),
      (request) => parseUuidParam(request.params, 'moradorId')
    )
  };

  app.post(batchPath, invitationManagement, async (request, reply) => {
    const condominioId = parseUuidParam(request.params, 'condominioId');
    const moradorId = parseUuidParam(request.params, 'moradorId');
    const convidadoIds = parseGuestIds(request.body);

    if (!condominioId || !moradorId || !convidadoIds) {
      return reply.status(400).send({ error: 'Invalid batch invitation payload' });
    }

    if (new Set(convidadoIds).size !== convidadoIds.length) {
      return reply.status(400).send({ error: 'Guest ids must be unique' });
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
      const invitations = await invitationIssuer.issueForRegisteredGuests({ condominioId, moradorId, convidadoIds });
      const issuedGuestIds = new Set(invitations.map((invitation) => invitation.convidadoId));
      if (
        invitations.length !== convidadoIds.length ||
        issuedGuestIds.size !== convidadoIds.length ||
        convidadoIds.some((convidadoId) => !issuedGuestIds.has(convidadoId))
      ) {
        request.log.error('Invitation issuer returned an invalid batch result');
        return reply.status(503).send({ error: 'Invitation issuing is unavailable' });
      }

      return reply.status(201).send({ convites: invitations.map(toInvitationResponse) });
    } catch (error) {
      if (error instanceof InvitationIssuingUnavailableError) {
        return reply.status(503).send({ error: error.message });
      }

      throw error;
    }
  });
}
