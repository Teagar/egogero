import type { FastifyReply, FastifyRequest } from 'fastify';

export const ROLES = ['provedor', 'sindico', 'morador', 'portaria'] as const;

export type Role = (typeof ROLES)[number];

export type Permission =
  | 'condominios:manage'
  | 'moradores:manage'
  | 'convidados:manage'
  | 'convites:create'
  | 'convites:limits:manage'
  | 'dispositivos:manage'
  | 'convites:validate'
  | 'auditorias:read-own'
  | 'notificacoes:read';

export const ROLE_PERMISSIONS = {
  provedor: ['condominios:manage', 'moradores:manage', 'convidados:manage', 'convites:create', 'convites:limits:manage', 'dispositivos:manage'],
  sindico: ['moradores:manage', 'convidados:manage', 'convites:create', 'convites:limits:manage', 'dispositivos:manage'],
  morador: ['convidados:manage', 'convites:create', 'auditorias:read-own', 'notificacoes:read'],
  portaria: ['convites:validate']
} as const satisfies Record<Role, readonly Permission[]>;

type ScopedIdentity =
  | { id: string; role: 'provedor'; condominioIds: null }
  | { id: string; role: Exclude<Role, 'provedor'>; condominioIds: readonly string[] };

export type HumanSessionIdentity = ScopedIdentity & {
  principalType: 'human';
  authMethod: 'oidc-session';
  accountId: string;
  sessionId: string;
};

export type AuthenticatedIdentity =
  | HumanSessionIdentity
  | (ScopedIdentity & { principalType: 'human'; authMethod: 'development' })
  | { id: string; role: 'portaria'; condominioIds: readonly string[]; principalType: 'device'; authMethod: 'device' };

export class AuthenticationError extends Error {
  constructor(
    readonly statusCode: 400 | 401 | 403 | 429,
    readonly code: 'ambiguous_credentials' | 'authentication_required' | 'authentication_temporarily_unavailable' | 'csrf_required',
    readonly headers: Readonly<Record<string, string>> = {}
  ) {
    super(code);
    this.name = 'AuthenticationError';
  }
}

declare module 'fastify' {
  interface FastifyRequest {
    authenticatedIdentity?: AuthenticatedIdentity;
  }
}

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
        return condominioId === '*'
          ? { id, role, condominioIds: null, principalType: 'human', authMethod: 'development' }
          : null;
      }

      if (!isUuid(condominioId)) {
        return null;
      }

      return { id, role, condominioIds: [condominioId], principalType: 'human', authMethod: 'development' };
    }
  };
}

export function createCompositeAuthenticator(...authenticators: readonly Authenticator[]): Authenticator {
  return {
    async authenticate(request) {
      for (const authenticator of authenticators) {
        const identity = await authenticator.authenticate(request);
        if (identity) return identity;
      }
      return null;
    }
  };
}

export function authorize(
  authenticator: Authenticator,
  permission: Permission,
  getCondominioId?: (request: FastifyRequest) => string | null,
  getMoradorId?: (request: FastifyRequest) => string | null
) {
  return async function authorizationHook(request: FastifyRequest, reply: FastifyReply) {
    let identity: AuthenticatedIdentity | null;
    try {
      identity = await authenticator.authenticate(request);
    } catch (error) {
      if (!(error instanceof AuthenticationError)) throw error;
      for (const [name, value] of Object.entries(error.headers)) reply.header(name, value);
      return reply.status(error.statusCode).send({ error: error.code });
    }

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

    const moradorId = getMoradorId?.(request);

    if (moradorId && identity.role === 'morador' && identity.id !== moradorId) {
      return reply.status(403).send({ error: 'Forbidden' });
    }

    request.authenticatedIdentity = identity;
  };
}
