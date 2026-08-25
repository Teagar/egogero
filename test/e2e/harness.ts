import { spawn, spawnSync, type ChildProcess } from 'node:child_process';
import { createHash, generateKeyPairSync, randomBytes } from 'node:crypto';
import { readFile, readdir, writeFile } from 'node:fs/promises';
import { request as httpRequest } from 'node:http';
import { createServer as createHttpsServer, type Server as HttpsServer } from 'node:https';
import { once } from 'node:events';
import path from 'node:path';

import { PrismaClient } from '@prisma/client';
import { exportJWK, SignJWT } from 'jose';
import { Client } from 'pg';

const DATABASE_URL = process.env.DATABASE_URL
  ?? 'postgresql://office:office@127.0.0.1:5432/office_pc31_e2e?schema=public';
const APP_ORIGIN = 'https://127.0.0.1:3443';
const OIDC_ORIGIN = 'https://127.0.0.1:3444';
const CLIENT_ID = 'pc31-browser-suite';
const CLIENT_SECRET = 'pc31-local-client-secret-at-least-32-bytes';
const REGULAR_SUBJECT = 'pc31-regular';
const IDS = {
  account: '31000000-0000-4000-8000-000000000001',
  identity: '31000000-0000-4000-8000-000000000002',
  condominium: '31000000-0000-4000-8000-000000000003',
  resident: '31000000-0000-4000-8000-000000000004',
  residentMembership: '31000000-0000-4000-8000-000000000005',
  managerMembership: '31000000-0000-4000-8000-000000000006',
  invitedAccount: '31000000-0000-4000-8000-000000000007',
  invitedMembership: '31000000-0000-4000-8000-000000000008',
  invitation: '31000000-0000-4000-8000-000000000009'
} as const;

type AttackMode = 'none' | 'state' | 'nonce' | 'pkce' | 'issuer' | 'signature' | 'audience' | 'time';
type ProviderState = {
  attack: AttackMode;
  subject: string;
  email: string;
  amr: string[];
  acr: string;
};
type AuthorizationCode = {
  challenge: string;
  nonce: string;
  redirectUri: string;
  state: ProviderState;
};

function assertIsolatedDatabase() {
  const url = new URL(DATABASE_URL);
  if (url.protocol !== 'postgresql:' || url.hostname !== '127.0.0.1' || url.port !== '5432'
    || url.pathname !== '/office_pc31_e2e' || url.searchParams.get('schema') !== 'public') {
    throw new Error('E2E reset refused: DATABASE_URL must target the isolated office_pc31_e2e database');
  }
}

async function ensureDatabaseExists() {
  const target = new URL(DATABASE_URL);
  const maintenance = new URL(DATABASE_URL);
  maintenance.pathname = '/postgres';
  maintenance.search = '';
  const client = new Client({ connectionString: maintenance.toString() });
  try {
    await client.connect();
    const existing = await client.query('SELECT 1 FROM pg_database WHERE datname = $1', [target.pathname.slice(1)]);
    if (existing.rowCount === 0) await client.query('CREATE DATABASE office_pc31_e2e');
  } finally {
    await client.end().catch(() => undefined);
  }
}

async function resetDatabase() {
  assertIsolatedDatabase();
  await ensureDatabaseExists();
  const migrationRoot = path.resolve('prisma/migrations');
  const migrations = (await readdir(migrationRoot, { withFileTypes: true }))
    .filter((entry) => entry.isDirectory() && /^\d{4}_/.test(entry.name))
    .map((entry) => Number(entry.name.slice(0, 4))).sort((left, right) => left - right);
  if (migrations.length === 0 || migrations.some((number, index) => number !== index + 1)) {
    throw new Error('Migration sequence must be non-empty, unique, and contiguous from 0001');
  }
  const reset = spawnSync('npx', ['prisma', 'migrate', 'reset', '--force', '--skip-generate'], {
    cwd: process.cwd(), env: { ...process.env, DATABASE_URL }, encoding: 'utf8'
  });
  if (reset.status !== 0) throw new Error(`Migration reset failed: ${redact(reset.stderr || reset.stdout)}`);
}

async function seedDatabase(invitationToken: string) {
  const prisma = new PrismaClient({ datasourceUrl: DATABASE_URL });
  try {
    await prisma.condominio.create({ data: {
      id: IDS.condominium, nome: 'Residencial PC31', responsavel: 'Equipe E2E', tipo: 'residencial', timezone: 'UTC'
    } });
    await prisma.humanAuthRolloutPolicy.update({
      where: { scope: 'global' },
      data: { state: 'enabled', cohortPercentage: null, cohortAlgorithm: null }
    });
    await prisma.humanAuthRolloutPolicy.create({
      data: { scope: `tenant:${IDS.condominium}`, condominioId: IDS.condominium, state: 'enabled' }
    });
    await prisma.morador.create({ data: {
      id: IDS.resident, condominioId: IDS.condominium, nome: 'Pessoa E2E', enderecoApartamento: '31'
    } });
    await prisma.humanAccount.create({ data: { id: IDS.account, displayName: 'Conta PC31', status: 'active' } });
    await prisma.externalIdentity.create({ data: {
      id: IDS.identity, accountId: IDS.account, issuer: OIDC_ORIGIN, subject: REGULAR_SUBJECT,
      email: 'pc31@example.test', emailVerified: true
    } });
    await prisma.humanMembership.create({ data: {
      id: IDS.residentMembership, accountId: IDS.account, condominioId: IDS.condominium,
      residentId: IDS.resident, role: 'morador', status: 'active', createdAt: new Date('2026-01-01T00:00:00Z')
    } });
    await prisma.humanMembership.create({ data: {
      id: IDS.managerMembership, accountId: IDS.account, condominioId: IDS.condominium,
      role: 'sindico', status: 'active', createdAt: new Date('2026-01-02T00:00:00Z')
    } });
    await prisma.humanAccount.create({ data: {
      id: IDS.invitedAccount, displayName: 'Convite PC31', status: 'invited'
    } });
    await prisma.humanMembership.create({ data: {
      id: IDS.invitedMembership, accountId: IDS.invitedAccount, condominioId: IDS.condominium,
      role: 'portaria', status: 'invited'
    } });
    await prisma.humanProvisioningInvitation.create({ data: {
      id: IDS.invitation, expiresAt: new Date(Date.now() + 60 * 60 * 1000),
      tokenDigest: createHash('sha256').update(invitationToken).digest(), expectedEmail: 'invited@example.test',
      accountId: IDS.invitedAccount, membershipId: IDS.invitedMembership, createdByAccountId: IDS.account
    } });
  } finally {
    await prisma.$disconnect();
  }
}

function redact(value: string) {
  return value
    .replace(/(authorization:\s*(?:basic|bearer)\s+)[^\s]+/gi, '$1[REDACTED]')
    .replace(/(?:[A-Za-z0-9_-]{43}|egdev_[A-Za-z0-9_-]+)/g, '[REDACTED]')
    .replace(/([?&](?:code|state|nonce|token|code_verifier)=)[^&\s]+/gi, '$1[REDACTED]');
}

async function readBody(request: import('node:http').IncomingMessage) {
  const chunks: Buffer[] = [];
  for await (const chunk of request) chunks.push(Buffer.from(chunk));
  return Buffer.concat(chunks).toString('utf8');
}

async function startOidcProvider(key: Buffer, cert: Buffer, observedAlerts: Set<string>) {
  const { privateKey, publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
  const { privateKey: forgedPrivateKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
  const jwk = { ...await exportJWK(publicKey), kid: 'pc31-key', alg: 'RS256', use: 'sig' };
  const codes = new Map<string, AuthorizationCode>();
  let tokenExchanges = 0;
  let rejectedCodeReplays = 0;
  let state: ProviderState = {
    attack: 'none', subject: REGULAR_SUBJECT, email: 'pc31@example.test', amr: ['otp'], acr: 'resident'
  };
  const json = (response: import('node:http').ServerResponse, status: number, body: unknown) => {
    response.writeHead(status, { 'content-type': 'application/json', 'cache-control': 'no-store' });
    response.end(JSON.stringify(body));
  };
  const authorize = (url: URL, response: import('node:http').ServerResponse) => {
    const required = ['client_id', 'redirect_uri', 'state', 'nonce', 'code_challenge'];
    if (url.searchParams.get('response_type') !== 'code' || url.searchParams.get('client_id') !== CLIENT_ID
      || url.searchParams.get('redirect_uri') !== `${APP_ORIGIN}/auth/callback`
      || url.searchParams.get('code_challenge_method') !== 'S256'
      || !required.every((name) => url.searchParams.getAll(name).length === 1)) {
      return json(response, 400, { error: 'invalid_request' });
    }
    const code = randomBytes(24).toString('base64url');
    codes.set(code, {
      challenge: state.attack === 'pkce' ? 'invalid-pkce-challenge' : url.searchParams.get('code_challenge')!,
      nonce: url.searchParams.get('nonce')!, redirectUri: url.searchParams.get('redirect_uri')!,
      state: { ...state, amr: [...state.amr] }
    });
    const callback = new URL(url.searchParams.get('redirect_uri')!);
    callback.searchParams.set('code', code);
    callback.searchParams.set('state', state.attack === 'state' ? `${url.searchParams.get('state')}x` : url.searchParams.get('state')!);
    callback.searchParams.set('iss', state.attack === 'issuer' ? 'https://mixup.invalid' : OIDC_ORIGIN);
    response.writeHead(302, { location: callback.toString(), 'cache-control': 'no-store', 'referrer-policy': 'no-referrer' });
    response.end();
  };
  const server = createHttpsServer({ key, cert }, async (request, response) => {
    const url = new URL(request.url ?? '/', OIDC_ORIGIN);
    if (request.method === 'GET' && url.pathname === '/.well-known/openid-configuration') {
      return json(response, 200, {
        issuer: OIDC_ORIGIN, authorization_endpoint: `${OIDC_ORIGIN}/authorize`, token_endpoint: `${OIDC_ORIGIN}/token`,
        jwks_uri: `${OIDC_ORIGIN}/jwks`, response_types_supported: ['code'], response_modes_supported: ['query'],
        subject_types_supported: ['public'], id_token_signing_alg_values_supported: ['RS256'], scopes_supported: ['openid', 'profile', 'email'],
        grant_types_supported: ['authorization_code'], code_challenge_methods_supported: ['S256'],
        token_endpoint_auth_methods_supported: ['client_secret_basic'], authorization_response_iss_parameter_supported: true
      });
    }
    if (request.method === 'GET' && url.pathname === '/jwks') return json(response, 200, { keys: [jwk] });
    if (request.method === 'GET' && url.pathname === '/__stats') {
      return json(response, 200, { tokenExchanges, rejectedCodeReplays, alerts: [...observedAlerts].sort() });
    }
    if (request.method === 'GET' && (url.pathname === '/authorize' || url.pathname === '/recovery')) return authorize(url, response);
    if (request.method === 'POST' && url.pathname === '/__control') {
      const body = JSON.parse(await readBody(request)) as Partial<ProviderState>;
      state = {
        attack: body.attack ?? 'none', subject: body.subject ?? REGULAR_SUBJECT,
        email: body.email ?? 'pc31@example.test', amr: body.amr ?? ['otp'], acr: body.acr ?? 'resident'
      };
      return json(response, 204, null);
    }
    if (request.method === 'POST' && url.pathname === '/token') {
      const expectedBasic = `Basic ${Buffer.from(`${CLIENT_ID}:${CLIENT_SECRET}`).toString('base64')}`;
      const form = new URLSearchParams(await readBody(request));
      const code = form.get('code');
      const saved = code ? codes.get(code) : undefined;
      tokenExchanges += 1;
      if (request.headers.authorization !== expectedBasic || form.get('grant_type') !== 'authorization_code'
        || form.get('client_id') !== CLIENT_ID || !saved || form.get('redirect_uri') !== saved.redirectUri) {
        if (code && !saved) rejectedCodeReplays += 1;
        return json(response, 400, { error: 'invalid_grant' });
      }
      codes.delete(code!);
      const verifier = form.get('code_verifier') ?? '';
      const challenge = createHash('sha256').update(verifier).digest('base64url');
      if (challenge !== saved.challenge) return json(response, 400, { error: 'invalid_grant' });
      const now = Math.floor(Date.now() / 1000);
      const tokenTime = saved.state.attack === 'time' ? now - 3_600 : now;
      const idToken = await new SignJWT({
        nonce: saved.state.attack === 'nonce' ? `${saved.nonce}x` : saved.nonce,
        email: saved.state.email, email_verified: true, auth_time: tokenTime,
        amr: saved.state.amr, acr: saved.state.acr
      }).setProtectedHeader({ alg: 'RS256', kid: 'pc31-key' }).setIssuer(OIDC_ORIGIN)
        .setAudience(saved.state.attack === 'audience' ? 'forged-audience' : CLIENT_ID)
        .setSubject(saved.state.subject).setIssuedAt(tokenTime).setExpirationTime(tokenTime + 300)
        .sign(saved.state.attack === 'signature' ? forgedPrivateKey : privateKey);
      return json(response, 200, { access_token: 'local-access-token', token_type: 'Bearer', expires_in: 300, id_token: idToken });
    }
    json(response, 404, { error: 'not_found' });
  });
  server.listen(3444, '127.0.0.1');
  try { await once(server, 'listening'); }
  catch (error) { await closeServer(server); throw error; }
  return server;
}

async function waitForApp(child: ChildProcess) {
  for (let attempt = 0; attempt < 200; attempt += 1) {
    if (child.exitCode !== null) throw new Error(`Application exited during startup (${child.exitCode})`);
    try {
      const response = await fetch('http://127.0.0.1:3442/health');
      if (response.ok) return;
    } catch { /* startup is still in progress */ }
    await new Promise((resolve) => setTimeout(resolve, 50));
  }
  throw new Error('Application did not become healthy');
}

function startTlsProxy(key: Buffer, cert: Buffer) {
  const server = createHttpsServer({ key, cert }, (incoming, outgoing) => {
    const upstream = httpRequest({
      hostname: '127.0.0.1', port: 3442, method: incoming.method, path: incoming.url,
      headers: {
        ...incoming.headers,
        host: '127.0.0.1:3443',
        'x-forwarded-for': incoming.socket.remoteAddress ?? '127.0.0.1',
        'x-forwarded-proto': 'https'
      }
    }, (response) => {
      outgoing.writeHead(response.statusCode ?? 502, response.headers);
      response.pipe(outgoing);
    });
    upstream.on('error', () => { outgoing.writeHead(502); outgoing.end(); });
    incoming.pipe(upstream);
  });
  server.listen(3443, '127.0.0.1');
  return server;
}

async function closeServer(server: HttpsServer) {
  if (!server.listening) return;
  server.closeAllConnections();
  await Promise.race([
    new Promise<void>((resolve) => server.close(() => resolve())),
    new Promise<void>((resolve) => setTimeout(resolve, 2_000))
  ]);
}

async function main() {
  const tempRoot = path.resolve('.e2e-tmp');
  const certPath = path.join(tempRoot, 'trusted-cert.pem');
  const [key, cert, untrustedKey, untrustedCert] = await Promise.all([
    readFile(path.join(tempRoot, 'trusted-key.pem')), readFile(certPath),
    readFile(path.join(tempRoot, 'untrusted-key.pem')), readFile(path.join(tempRoot, 'untrusted-cert.pem'))
  ]);
  let provider: HttpsServer | undefined;
  let proxy: HttpsServer | undefined;
  let untrusted: HttpsServer | undefined;
  let application: ChildProcess | undefined;
  let resolveStop: (() => void) | undefined;
  const stopped = new Promise<void>((resolve) => { resolveStop = resolve; });
  const requestStop = () => resolveStop?.();
  process.once('SIGTERM', requestStop);
  process.once('SIGINT', requestStop);
  try {
    const invitationToken = randomBytes(32).toString('base64url');
    const observedAlerts = new Set<string>();
    await writeFile(path.join(tempRoot, 'invitation-token'), invitationToken, { mode: 0o600 });
    await resetDatabase();
    await seedDatabase(invitationToken);
    provider = await startOidcProvider(key, cert, observedAlerts);
    application = spawn(process.execPath, ['--import', 'tsx', 'src/server.ts'], {
      cwd: process.cwd(), stdio: ['ignore', 'pipe', 'pipe'],
      env: {
        ...process.env, NODE_ENV: 'production', NODE_EXTRA_CA_CERTS: certPath, DATABASE_URL,
        HOST: '127.0.0.1', PORT: '3442', TRUST_PROXY: '127.0.0.1/32', HUMAN_AUTH_ENABLED: 'true',
        PUBLIC_APPLICATION_ORIGIN: APP_ORIGIN,
        PUBLIC_VALIDATION_BASE_URL: APP_ORIGIN, INVITATION_TOKEN_SECRET: 'pc31-invitation-secret-at-least-32-bytes',
        DEVICE_API_KEY_SECRET: 'pc31-device-secret-at-least-32-bytes', IDEMPOTENCY_CACHE_SECRET: 'pc31-idempotency-secret-at-least-32-bytes',
        OIDC_ISSUER: OIDC_ORIGIN, OIDC_AUTHORIZATION_ENDPOINT: `${OIDC_ORIGIN}/authorize`,
        OIDC_TOKEN_ENDPOINT: `${OIDC_ORIGIN}/token`, OIDC_JWKS_URI: `${OIDC_ORIGIN}/jwks`,
        OIDC_CLIENT_ID: CLIENT_ID, OIDC_CLIENT_SECRET: CLIENT_SECRET, OIDC_REDIRECT_URI: `${APP_ORIGIN}/auth/callback`,
        OIDC_ID_TOKEN_SIGNING_ALG: 'RS256', OIDC_PKCE_KEYS: JSON.stringify({ 1: randomBytes(32).toString('base64url') }),
        OIDC_PKCE_CURRENT_KEY_VERSION: '1', OIDC_RETURN_TO_PREFIXES: '/,/app,/logout-all/continue',
        SESSION_CSRF_KEYS: JSON.stringify({ 1: randomBytes(32).toString('base64url') }), SESSION_CSRF_CURRENT_KEY_VERSION: '1',
        OIDC_RECOVERY_URL: `${OIDC_ORIGIN}/recovery`, RECOVERY_WEBHOOK_ISSUERS: OIDC_ORIGIN,
        RECOVERY_WEBHOOK_SECRET: 'pc31-recovery-webhook-secret-at-least-32-bytes',
        HUMAN_MFA_ROLE_POLICY: JSON.stringify({
          provedor: { amr: ['webauthn'], acr: ['strong'] }, sindico: { amr: ['webauthn'], acr: ['strong'] },
          morador: { amr: ['otp', 'webauthn'], acr: [] }, portaria: { amr: ['webauthn'], acr: ['strong'] }
        })
      }
    });
    for (const stream of [application.stdout, application.stderr]) {
      pipeSanitized(stream, process.stderr, (line) => observeAlert(line, observedAlerts));
    }
    application.once('exit', requestStop);
    await waitForApp(application);
    proxy = startTlsProxy(key, cert);
    await once(proxy, 'listening');
    untrusted = createHttpsServer({ key: untrustedKey, cert: untrustedCert }, (_request, response) => response.end('untrusted'));
    untrusted.listen(3445, '127.0.0.1');
    await once(untrusted, 'listening');
    process.stdout.write('PC31 E2E HTTPS harness ready\n');
    await stopped;
  } finally {
    process.removeListener('SIGTERM', requestStop);
    process.removeListener('SIGINT', requestStop);
    await Promise.all([provider, proxy, untrusted].filter((server): server is HttpsServer => Boolean(server)).map(closeServer));
    if (application) await terminateChild(application);
  }
}

async function terminateChild(child: ChildProcess) {
  if (child.exitCode !== null) return;
  child.kill('SIGTERM');
  const exited = new Promise<void>((resolve) => child.once('exit', () => resolve()));
  const graceful = await Promise.race([exited.then(() => true), new Promise<false>((resolve) => setTimeout(() => resolve(false), 3_000))]);
  if (!graceful && child.exitCode === null) {
    child.kill('SIGKILL');
    await new Promise<void>((resolve) => child.once('exit', () => resolve()));
  }
}

function pipeSanitized(input: NodeJS.ReadableStream | null, output: NodeJS.WritableStream, observe?: (line: string) => void) {
  if (!input) return;
  let pending = '';
  input.setEncoding('utf8');
  input.on('data', (chunk: string) => {
    pending += chunk;
    const lines = pending.split('\n');
    pending = lines.pop() ?? '';
    for (const line of lines) {
      observe?.(line);
      output.write(`${redact(line)}\n`);
    }
  });
  input.on('end', () => { if (pending) output.write(redact(pending)); });
}

function observeAlert(line: string, alerts: Set<string>) {
  try {
    const event = JSON.parse(line) as { contract?: unknown; event?: unknown; type?: unknown };
    const recognized = event.event === 'auth_alert' || event.contract === 'egogero.auth-alert-delivery/v1';
    if (recognized && typeof event.type === 'string' && /^[a-z_]{1,100}$/.test(event.type)) {
      alerts.add(event.type);
    }
  } catch { /* non-JSON application output */ }
}

main().catch((error) => {
  process.stderr.write(`${redact(error instanceof Error ? error.stack ?? error.message : String(error))}\n`);
  process.exit(1);
});
