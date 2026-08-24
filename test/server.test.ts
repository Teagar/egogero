import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { once } from 'node:events';
import { createServer } from 'node:net';
import test from 'node:test';

import { getEnv, normalizePublicValidationBaseUrl } from '../src/env.js';

const INVITATION_TOKEN_SECRET = 'test-invitation-token-secret-at-least-32-bytes';

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

async function startRuntime(nodeEnvironment: string, localDevelopmentAuth: boolean) {
  const port = await reservePort();
  const child = spawn(process.execPath, ['--import', 'tsx', 'src/server.ts'], {
    cwd: process.cwd(),
    env: {
      ...process.env,
      DATABASE_URL: 'postgresql://unused:unused@127.0.0.1:1/unused',
      INVITATION_TOKEN_SECRET,
      HOST: '127.0.0.1',
      LOCAL_DEVELOPMENT_AUTH: localDevelopmentAuth ? 'true' : '',
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

test('production startup is fail-closed when no production authenticator is configured', async () => {
  const runtime = await startRuntime('production', false);

  try {
    const response = await fetch(`${runtime.url}/condominios`);
    assert.equal(response.status, 401);
  } finally {
    await stopRuntime(runtime.child);
  }
});

test('NODE_ENV alone never enables development header authentication', async () => {
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

test('explicit local development mode starts with scoped header authentication', async () => {
  const runtime = await startRuntime('production', true);

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

test('public validation URL is optional but rejects unsafe values', () => {
  const base = getEnv({
    DATABASE_URL: 'postgresql://unused',
    INVITATION_TOKEN_SECRET,
    PUBLIC_VALIDATION_BASE_URL: 'https://access.example.test/'
  });
  assert.equal(base.publicValidationBaseUrl, 'https://access.example.test');
  assert.throws(() => normalizePublicValidationBaseUrl('http://access.example.test'), /absolute HTTPS URL/);
  assert.throws(() => normalizePublicValidationBaseUrl('https://access.example.test/?token=secret'), /without credentials/);
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
  assert.match(stderr, /PORT must be a positive integer/);
});
