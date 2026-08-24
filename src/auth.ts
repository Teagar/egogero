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

export type AuthenticatedIdentity = {
  id: string;
  role: Role;
};

export interface Authenticator {
  authenticate(request: FastifyRequest): Promise<AuthenticatedIdentity | null>;
}

const DEVELOPMENT_ID_HEADER = 'x-development-user-id';
const DEVELOPMENT_ROLE_HEADER = 'x-development-user-role';

function readSingleHeader(request: FastifyRequest, name: string) {
  const value = request.headers[name];
  return typeof value === 'string' ? value : null;
}

function isRole(value: string): value is Role {
  return ROLES.some((role) => role === value);
}

export function createDevelopmentHeaderAuthenticator(environment = process.env.NODE_ENV): Authenticator {
  if (environment !== 'development' && environment !== 'test') {
    throw new Error('Development header authentication is disabled outside development and test');
  }

  return {
    async authenticate(request) {
      const id = readSingleHeader(request, DEVELOPMENT_ID_HEADER)?.trim();
      const role = readSingleHeader(request, DEVELOPMENT_ROLE_HEADER);

      if (!id || !role || !isRole(role)) {
        return null;
      }

      return { id, role };
    }
  };
}

export function authorize(authenticator: Authenticator, permission: Permission) {
  return async function authorizationHook(request: FastifyRequest, reply: FastifyReply) {
    const identity = await authenticator.authenticate(request);

    if (!identity) {
      return reply.status(401).send({ error: 'Authentication required' });
    }

    const permissions: readonly Permission[] = ROLE_PERMISSIONS[identity.role];

    if (!permissions.includes(permission)) {
      return reply.status(403).send({ error: 'Forbidden' });
    }
  };
}
