import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';

import { AuthenticationError, isUuid } from './auth.js';
import type { OidcService } from './oidc.js';
import {
  CLEARED_SESSION_COOKIE,
  createBrowserSessionAuthenticator,
  hasBrowserSessionCookie,
  parseBrowserSessionCookie
} from './sessions.js';
import type { BrowserSessionService, BrowserSessionStore } from './sessions.js';

function noStore(reply: { header(name: string, value: string): unknown }) {
  reply.header('Cache-Control', 'no-store');
}

function validRequestContext(request: FastifyRequest, publicOrigin: string) {
  const origin = typeof request.headers.origin === 'string' ? request.headers.origin : null;
  let refererOrigin: string | null = null;
  try {
    if (typeof request.headers.referer === 'string') {
      const referer = new URL(request.headers.referer);
      refererOrigin = !referer.username && !referer.password ? referer.origin : null;
    }
  } catch {
    refererOrigin = null;
  }
  const contentType = typeof request.headers['content-type'] === 'string' ? request.headers['content-type'] : '';
  return (origin === publicOrigin || (origin === null && refererOrigin === publicOrigin))
    && /^application\/json(?:\s*;\s*charset=[A-Za-z0-9._-]+)?$/i.test(contentType);
}

export function registerBrowserAuthRoutes(
  app: FastifyInstance,
  store?: BrowserSessionStore,
  service?: BrowserSessionService,
  oidcService?: OidcService
) {
  if (!store || !service) return;
  const authenticator = createBrowserSessionAuthenticator(store);

  async function rejectAmbiguousCredentials(request: FastifyRequest, reply: FastifyReply) {
    if (hasBrowserSessionCookie(request.headers.cookie)
      && typeof request.headers.authorization === 'string'
      && /^Bearer egdev_/.test(request.headers.authorization)) {
      noStore(reply);
      await store!.recordAmbiguousCredentials({ requestCorrelationId: request.id });
      return reply.status(400).send({ error: 'ambiguous_credentials' });
    }
  }

  const unambiguous = { onRequest: rejectAmbiguousCredentials };

  async function authenticateMutation(request: FastifyRequest) {
    return authenticator.authenticate(request);
  }

  app.get('/auth/session', unambiguous, async (request, reply) => {
    noStore(reply);
    const token = parseBrowserSessionCookie(request.headers.cookie);
    if (!token) {
      reply.header('Set-Cookie', CLEARED_SESSION_COOKIE);
      return reply.status(401).send({ error: 'authentication_required' });
    }
    const snapshot = await store.inspect({ sessionToken: token, requestCorrelationId: request.id });
    if (!snapshot) {
      reply.header('Set-Cookie', CLEARED_SESSION_COOKIE);
      return reply.status(401).send({ error: 'authentication_required' });
    }
    return {
      account: snapshot.account,
      memberships: snapshot.memberships,
      activeTenantId: snapshot.activeTenantId,
      csrfToken: snapshot.csrfToken,
      expiresAt: snapshot.expiresAt.toISOString(),
      idleExpiresAt: snapshot.idleExpiresAt.toISOString()
    };
  });

  app.post('/auth/tenant', unambiguous, async (request, reply) => {
    noStore(reply);
    try {
      await authenticateMutation(request);
    } catch (error) {
      if (!(error instanceof AuthenticationError)) throw error;
      for (const [name, value] of Object.entries(error.headers)) reply.header(name, value);
      return reply.status(error.statusCode).send({ error: error.code });
    }
    const body = request.body && typeof request.body === 'object' && !Array.isArray(request.body)
      ? request.body as Record<string, unknown>
      : null;
    if (!body || Object.keys(body).length !== 1 || !isUuid(body.membershipId)) {
      return reply.status(400).send({ error: 'invalid_request' });
    }
    const token = parseBrowserSessionCookie(request.headers.cookie)!;
    const result = await service.rotate({
      sessionToken: token,
      targetMembershipId: body.membershipId,
      requestCorrelationId: request.id,
      userAgent: typeof request.headers['user-agent'] === 'string' ? request.headers['user-agent'] : null
    });
    if (result.status === 'stale') {
      return reply.status(409).send({ error: 'stale_session' });
    }
    if (result.status !== 'rotated') return reply.status(403).send({ error: 'forbidden' });
    reply.header('Set-Cookie', service.sessionCookie(result.sessionToken));
    return reply.status(204).send();
  });

  app.post('/auth/logout', unambiguous, async (request, reply) => {
    noStore(reply);
    if (!hasBrowserSessionCookie(request.headers.cookie)) {
      if (!validRequestContext(request, store.publicApplicationOrigin)) {
        return reply.status(403).send({ error: 'csrf_required' });
      }
      reply.header('Set-Cookie', service.clearSessionCookie());
      return reply.status(204).send();
    }
    try {
      await authenticateMutation(request);
    } catch (error) {
      if (!(error instanceof AuthenticationError)) throw error;
      const token = parseBrowserSessionCookie(request.headers.cookie);
      if (error.statusCode === 401 && token && validRequestContext(request, store.publicApplicationOrigin)
        && await service.isRevoked(token)) {
        reply.header('Set-Cookie', service.clearSessionCookie());
        return reply.status(204).send();
      }
      for (const [name, value] of Object.entries(error.headers)) reply.header(name, value);
      return reply.status(error.statusCode).send({ error: error.code });
    }
    await service.revoke({
      sessionToken: parseBrowserSessionCookie(request.headers.cookie)!,
      requestCorrelationId: request.id,
      userAgent: typeof request.headers['user-agent'] === 'string' ? request.headers['user-agent'] : null
    });
    reply.header('Set-Cookie', service.clearSessionCookie());
    return reply.status(204).send();
  });

  app.post('/auth/logout-all', unambiguous, async (request, reply) => {
    noStore(reply);
    try {
      await authenticateMutation(request);
    } catch (error) {
      if (!(error instanceof AuthenticationError)) throw error;
      for (const [name, value] of Object.entries(error.headers)) reply.header(name, value);
      return reply.status(error.statusCode).send({ error: error.code });
    }
    const result = await service.revokeAll({
      sessionToken: parseBrowserSessionCookie(request.headers.cookie)!,
      requestCorrelationId: request.id,
      userAgent: typeof request.headers['user-agent'] === 'string' ? request.headers['user-agent'] : null
    });
    if (result === 'reauthentication-required') {
      return reply.status(403).send({ error: 'reauthentication_required' });
    }
    if (result !== 'revoked') {
      reply.header('Set-Cookie', service.clearSessionCookie());
      return reply.status(401).send({ error: 'authentication_required' });
    }
    reply.header('Set-Cookie', service.clearSessionCookie());
    return reply.status(204).send();
  });

  app.post('/auth/reauthenticate', unambiguous, async (request, reply) => {
    noStore(reply);
    if (!oidcService) return reply.status(503).send({ error: 'authentication_unavailable' });
    try {
      await authenticateMutation(request);
    } catch (error) {
      if (!(error instanceof AuthenticationError)) throw error;
      for (const [name, value] of Object.entries(error.headers)) reply.header(name, value);
      return reply.status(error.statusCode).send({ error: error.code });
    }
    const body = request.body && typeof request.body === 'object' && !Array.isArray(request.body)
      ? request.body as Record<string, unknown>
      : {};
    if (Object.keys(body).some((key) => key !== 'returnTo')
      || (body.returnTo !== undefined && typeof body.returnTo !== 'string')) {
      return reply.status(400).send({ error: 'invalid_request' });
    }
    const authorizationUrl = await oidcService.startLogin({
      returnTo: body.returnTo as string | undefined,
      requestCorrelationId: request.id,
      reauthentication: true,
      reauthenticationFamilyId: request.browserSessionSnapshot!.familyId
    });
    return reply.redirect(authorizationUrl.toString(), 303);
  });
}
