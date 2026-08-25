import { existsSync } from 'node:fs';
import { readFile } from 'node:fs/promises';
import path from 'node:path';

import fastifyStatic from '@fastify/static';
import type { FastifyInstance } from 'fastify';

const DOCUMENT_ROUTES = [
  '/', '/app', '/login', '/invitation', '/recovery', '/logout', '/logout-all/continue', '/auth/error'
] as const;
const CSP = [
  "default-src 'none'",
  "script-src 'self'",
  "style-src 'self'",
  "font-src 'self'",
  "img-src 'self'",
  "connect-src 'self'",
  "base-uri 'none'",
  "form-action 'self'",
  "frame-ancestors 'none'"
].join('; ');

export function registerFrontend(app: FastifyInstance, root?: string) {
  app.addHook('onSend', async (request, reply, payload) => {
    reply.header('Content-Security-Policy', CSP);
    reply.header('X-Content-Type-Options', 'nosniff');
    reply.header('Referrer-Policy', 'no-referrer');
    reply.header('Permissions-Policy', 'camera=(), microphone=(), geolocation=(), payment=(), usb=()');
    if (!request.url.startsWith('/assets/')) reply.header('Cache-Control', 'no-store');
    return payload;
  });

  if (!root) return;
  const indexPath = path.join(root, 'index.html');
  const assetsPath = path.join(root, 'assets');
  if (!existsSync(indexPath) || !existsSync(assetsPath)) return;

  app.register(fastifyStatic, {
    root: assetsPath,
    prefix: '/assets/',
    wildcard: true,
    cacheControl: true,
    immutable: true,
    maxAge: '1y',
    index: false
  });

  for (const route of DOCUMENT_ROUTES) {
    app.get(route, async (_request, reply) => {
      const document = await readFile(indexPath);
      return reply.type('text/html; charset=utf-8').send(document);
    });
  }
}
