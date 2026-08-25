import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import { once } from 'node:events';
import { createServer } from 'node:net';
import test from 'node:test';

import { PrismaClient } from '@prisma/client';

import { getEnv, normalizePublicValidationBaseUrl } from '../src/env.js';

const INVITATION_TOKEN_SECRET = 'idempotency-db-invitation-token-secret-minimum-32-bytes';
const DEVICE_API_KEY_SECRET = 'test-device-api-key-secret-at-least-32-bytes';
const IDEMPOTENCY_CACHE_SECRET = 'idempotency-db-cache-secret-minimum-32-bytes';
const runDatabaseTests = process.env.RUN_DATABASE_TESTS === 'true';

function fingerprint(value: string) {
  return createHash('sha256').update(value).digest('hex');
}

async function reservePort() {
  const server = createServer();
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  const address = server.address();

  if (!address || typeof address === 'string') {
    throw new Error('Could not reserve a startup test port');
  }

  await new Promise<void>((resolve, reject) => server.close((error) => (error ? reject(error) : resolve())));
  return address.port;
}

async function startRuntime(
  nodeEnvironment: string,
  localDevelopmentAuth: boolean,
  databaseUrl = process.env.DATABASE_URL ?? 'postgresql://unused:unused@127.0.0.1:1/unused'
) {
  const port = await reservePort();
  const child = spawn(process.execPath, ['--import', 'tsx', 'src/server.ts'], {
    cwd: process.cwd(),
    env: {
      ...process.env,
      DATABASE_URL: databaseUrl,
      INVITATION_TOKEN_SECRET,
      DEVICE_API_KEY_SECRET,
      IDEMPOTENCY_CACHE_SECRET,
      HOST: '127.0.0.1',
      LOCAL_DEVELOPMENT_AUTH: localDevelopmentAuth ? 'true' : '',
      HUMAN_AUTH_ENABLED: 'false',
      NODE_ENV: nodeEnvironment,
      PORT: String(port)
    },
    stdio: ['ignore', 'ignore', 'pipe']
  });
  let stderr = '';
  child.stderr.setEncoding('utf8');
  child.stderr.on('data', (chunk: string) => {
    stderr += chunk;
  });

  const url = `http://127.0.0.1:${port}`;

  for (let attempt = 0; attempt < 100; attempt += 1) {
    if (child.exitCode !== null) {
      throw new Error(`Server exited during startup: ${stderr}`);
    }

    try {
      const response = await fetch(`${url}/health`);
      if (response.ok) {
        return { child, url };
      }
    } catch {
      // The process has not started listening yet.
    }

    await new Promise((resolve) => setTimeout(resolve, 25));
  }

  child.kill();
  throw new Error(`Server did not start: ${stderr}`);
}

async function stopRuntime(child: ReturnType<typeof spawn>) {
  if (child.exitCode === null) {
    child.kill('SIGTERM');
    await once(child, 'exit');
  }
}

test('matching idempotency fingerprint starts before production authentication fails closed', { skip: !runDatabaseTests }, async () => {
  const prisma = new PrismaClient();
  await prisma.securityKey.upsert({
    where: { name: 'invitation-token' },
    create: { name: 'invitation-token', fingerprint: fingerprint(INVITATION_TOKEN_SECRET) },
    update: { fingerprint: fingerprint(INVITATION_TOKEN_SECRET) }
  });
  await prisma.securityKey.upsert({
    where: { name: 'idempotency-cache-v1' },
    create: { name: 'idempotency-cache-v1', fingerprint: fingerprint(`idempotency-cache:${IDEMPOTENCY_CACHE_SECRET}`) },
    update: { fingerprint: fingerprint(`idempotency-cache:${IDEMPOTENCY_CACHE_SECRET}`) }
  });
  let runtime: Awaited<ReturnType<typeof startRuntime>> | undefined;
  try {
    runtime = await startRuntime('production', false);
    const response = await fetch(`${runtime.url}/condominios`);
    assert.equal(response.status, 401);
  } finally {
    if (runtime) await stopRuntime(runtime.child);
    await prisma.$disconnect();
  }
});

test('NODE_ENV alone never enables development header authentication', { skip: !runDatabaseTests }, async () => {
  const runtime = await startRuntime('development', false);

  try {
    const response = await fetch(`${runtime.url}/condominios`, {
      headers: {
        'x-development-user-id': 'provider-1',
        'x-development-user-role': 'provedor',
        'x-development-condominio-id': '*'
      }
    });
    assert.equal(response.status, 401);
  } finally {
    await stopRuntime(runtime.child);
  }
});

test('explicit local development mode starts with scoped header authentication', { skip: !runDatabaseTests }, async () => {
  const runtime = await startRuntime('development', true);

  try {
    const response = await fetch(`${runtime.url}/condominios`, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        'x-development-user-id': 'provider-1',
        'x-development-user-role': 'provedor',
        'x-development-condominio-id': '*'
      },
      body: '{}'
    });
    assert.equal(response.status, 400);
  } finally {
    await stopRuntime(runtime.child);
  }
});

test('local development authentication binds to loopback by default', () => {
  const env = getEnv({
    DATABASE_URL: 'postgresql://unused:unused@127.0.0.1:1/unused',
    INVITATION_TOKEN_SECRET,
    DEVICE_API_KEY_SECRET,
    IDEMPOTENCY_CACHE_SECRET,
    LOCAL_DEVELOPMENT_AUTH: 'true'
  });

  assert.equal(env.host, '127.0.0.1');
});

test('startup rejects a missing or weak invitation token secret', () => {
  assert.throws(
    () => getEnv({ DATABASE_URL: 'postgresql://unused', INVITATION_TOKEN_SECRET: 'too-short' }),
    /at least 32 bytes/
  );
});

test('startup rejects a missing or weak device API key secret', () => {
  assert.throws(
    () => getEnv({
      DATABASE_URL: 'postgresql://unused',
      INVITATION_TOKEN_SECRET,
      DEVICE_API_KEY_SECRET: 'too-short'
    }),
    /DEVICE_API_KEY_SECRET must be at least 32 bytes/
  );
});

test('startup rejects a missing or weak idempotency cache secret and invalid replay TTL', () => {
  const base = {
    DATABASE_URL: 'postgresql://unused',
    INVITATION_TOKEN_SECRET,
    DEVICE_API_KEY_SECRET
  };
  assert.throws(() => getEnv(base), /IDEMPOTENCY_CACHE_SECRET must be at least 32 bytes/);
  assert.throws(
    () => getEnv({ ...base, IDEMPOTENCY_CACHE_SECRET: 'too-short' }),
    /IDEMPOTENCY_CACHE_SECRET must be at least 32 bytes/
  );
  assert.throws(
    () => getEnv({ ...base, IDEMPOTENCY_CACHE_SECRET, IDEMPOTENCY_REPLAY_TTL_SECONDS: '59' }),
    /IDEMPOTENCY_REPLAY_TTL_SECONDS/
  );
  assert.equal(getEnv({ ...base, IDEMPOTENCY_CACHE_SECRET }).idempotencyTtlMs, 24 * 60 * 60 * 1000);
});

test('startup fails before listen on an idempotency fingerprint mismatch', { skip: !runDatabaseTests }, async () => {
  const prisma = new PrismaClient();
  try {
    await prisma.securityKey.upsert({
      where: { name: 'idempotency-cache-v1' },
      create: { name: 'idempotency-cache-v1', fingerprint: '0'.repeat(64) },
      update: { fingerprint: '0'.repeat(64) }
    });
    await assert.rejects(startRuntime('production', false), /Server exited during startup: Startup failed/);
  } finally {
    await prisma.securityKey.update({
      where: { name: 'idempotency-cache-v1' },
      data: { fingerprint: fingerprint(`idempotency-cache:${IDEMPOTENCY_CACHE_SECRET}`) }
    });
    await prisma.$disconnect();
  }
});

test('startup fails before listen when PostgreSQL is unavailable', async () => {
  await assert.rejects(
    startRuntime('production', false, 'postgresql://unused:unused@127.0.0.1:1/unused'),
    /Server exited during startup: Startup failed/
  );
});

test('public validation URL is optional but rejects unsafe values', () => {
  const base = getEnv({
    DATABASE_URL: 'postgresql://unused',
    INVITATION_TOKEN_SECRET,
    DEVICE_API_KEY_SECRET,
    IDEMPOTENCY_CACHE_SECRET,
    PUBLIC_VALIDATION_BASE_URL: 'https://access.example.test/'
  });
  assert.equal(base.publicValidationBaseUrl, 'https://access.example.test');
  assert.throws(() => normalizePublicValidationBaseUrl('http://access.example.test'), /absolute HTTPS URL/);
  assert.throws(() => normalizePublicValidationBaseUrl('https://access.example.test/?token=secret'), /without credentials/);
});

test('production gatehouse validation rejects HTTP and untrusted forwarded protocol', { skip: !runDatabaseTests }, async () => {
  const runtime = await startRuntime('production', false);

  try {
    for (const headers of [{}, { 'x-forwarded-proto': 'https' }]) {
      const response = await fetch(`${runtime.url}/portaria/convites/validar`, {
        method: 'POST',
        headers: { 'content-type': 'application/json', ...headers },
        body: JSON.stringify({ token: '123456', tipoAcesso: 'pedestre' })
      });
      assert.equal(response.status, 426);
      assert.deepEqual(await response.json(), { error: 'HTTPS required' });
    }
  } finally {
    await stopRuntime(runtime.child);
  }
});

test('bootstrap configuration failures exit cleanly through the startup handler', async () => {
  const child = spawn(process.execPath, ['--import', 'tsx', 'src/server.ts'], {
    cwd: process.cwd(),
    env: {
      ...process.env,
      DATABASE_URL: 'postgresql://unused:unused@127.0.0.1:1/unused',
      PORT: 'invalid'
    },
    stdio: ['ignore', 'ignore', 'pipe']
  });
  let stderr = '';
  child.stderr.setEncoding('utf8');
  child.stderr.on('data', (chunk: string) => {
    stderr += chunk;
  });
  const [code] = (await once(child, 'exit')) as [number, NodeJS.Signals | null];

  assert.equal(code, 1);
  assert.equal(stderr.trim(), 'Startup failed');
});
