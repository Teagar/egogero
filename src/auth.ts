import type { FastifyReply, FastifyRequest } from 'fastify';

export const ROLES = ['provedor', 'sindico', 'morador', 'portaria'] as const;

export type Role = (typeof ROLES)[number];

export type Permission = 'condominios:manage' | 'moradores:manage';

export const ROLE_PERMISSIONS = {
  provedor: ['condominios:manage', 'moradores:manage'],
  sindico: ['moradores:manage'],
  morador: [],
  portaria: []
} as const satisfies Record<Role, readonly Permission[]>;

export type AuthenticatedIdentity =
  | { id: string; role: 'provedor'; condominioIds: null }
  | { id: string; role: Exclude<Role, 'provedor'>; condominioIds: readonly string[] };

export interface Authenticator {
  authenticate(request: FastifyRequest): Promise<AuthenticatedIdentity | null>;
}

const DEVELOPMENT_ID_HEADER = 'x-development-user-id';
const DEVELOPMENT_ROLE_HEADER = 'x-development-user-role';
const DEVELOPMENT_CONDOMINIO_HEADER = 'x-development-condominio-id';
const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

export function isUuid(value: unknown): value is string {
  return typeof value === 'string' && UUID_PATTERN.test(value);
}

export const unauthenticatedAuthenticator: Authenticator = {
  async authenticate() {
    return null;
  }
};

function readSingleHeader(request: FastifyRequest, name: string) {
  const value = request.headers[name];
  return typeof value === 'string' ? value : null;
}

function isRole(value: string): value is Role {
  return ROLES.some((role) => role === value);
}

export function createDevelopmentHeaderAuthenticator(enabled: boolean): Authenticator {
  if (!enabled) {
    throw new Error('Development header authentication requires explicit opt-in');
  }

  return {
    async authenticate(request) {
      const id = readSingleHeader(request, DEVELOPMENT_ID_HEADER)?.trim();
      const role = readSingleHeader(request, DEVELOPMENT_ROLE_HEADER);
      const condominioId = readSingleHeader(request, DEVELOPMENT_CONDOMINIO_HEADER);

      if (!id || !role || !isRole(role) || !condominioId) {
        return null;
      }

      if (role === 'provedor') {
        return condominioId === '*' ? { id, role, condominioIds: null } : null;
      }

      if (!isUuid(condominioId)) {
        return null;
      }

      return { id, role, condominioIds: [condominioId] };
    }
  };
}

export function authorize(
  authenticator: Authenticator,
  permission: Permission,
  getCondominioId?: (request: FastifyRequest) => string | null
) {
  return async function authorizationHook(request: FastifyRequest, reply: FastifyReply) {
    const identity = await authenticator.authenticate(request);

    if (!identity) {
      return reply.status(401).send({ error: 'Authentication required' });
    }

    const permissions: readonly Permission[] = ROLE_PERMISSIONS[identity.role];

    if (!permissions.includes(permission)) {
      return reply.status(403).send({ error: 'Forbidden' });
    }

    const condominioId = getCondominioId?.(request);
    const globallyAuthorized = identity.role === 'provedor' && identity.condominioIds === null;

    if (condominioId && !globallyAuthorized && !identity.condominioIds?.includes(condominioId)) {
      return reply.status(403).send({ error: 'Forbidden' });
    }
  };
}
