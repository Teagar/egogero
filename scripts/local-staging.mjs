import { createHash, randomBytes } from 'node:crypto';
import { Buffer } from 'node:buffer';
import { chmod, mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import http from 'node:http';
import https from 'node:https';
import path from 'node:path';
import process from 'node:process';
import { spawnSync } from 'node:child_process';
import { setTimeout as delay } from 'node:timers/promises';

const root = process.cwd();
const runtimeDirectory = path.join(root, '.local-staging');
const composeFile = path.join(root, 'docker-compose.staging.yml');
const projectName = `office-local-staging-${createHash('sha256').update(root).digest('hex').slice(0, 10)}`;
const realmTemplate = path.join(root, 'deploy/local-staging/realm.template.json');
const requiredFiles = [
  'postgres.env',
  'keycloak-postgres.env',
  'migration.env',
  'seed.env',
  'app.env',
  'delivery-worker.env',
  'recovery-worker.env',
  'postgres-exporter.env',
  'keycloak.env',
  'grafana.env',
  'realm.json'
];
const composeArguments = ['compose', '--project-name', projectName, '-f', composeFile];

const action = process.argv[2] ?? 'configure';

try {
  if (action === 'configure') await configure();
  else if (action === 'up') {
    await configure();
    docker(['up', '--build', '--detach']);
    process.stdout.write('Local staging started. Run `npm run local-staging:check` once services are healthy.\n');
  } else if (action === 'check') await check();
  else if (action === 'credentials') await credentials();
  else if (action === 'ca') await exportCertificate();
  else if (action === 'down') docker(['down', '--remove-orphans']);
  else if (action === 'status') docker(['ps']);
  else if (action === 'logs') docker(['logs', ...process.argv.slice(3)]);
  else if (action === 'reset') {
    await ensureComposeInputs();
    docker(['down', '--volumes', '--remove-orphans']);
    await rm(runtimeDirectory, { recursive: true, force: true });
    process.stdout.write('Local staging data and generated credentials removed.\n');
  } else {
    throw new Error('Expected configure, up, check, credentials, ca, down, status, logs, or reset');
  }
} catch (error) {
  process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
  process.exitCode = 1;
}

async function configure() {
  const existing = await Promise.all(requiredFiles.map(async (name) => {
    try {
      await readFile(path.join(runtimeDirectory, name));
      return true;
    } catch {
      return false;
    }
  }));
  if (existing.every(Boolean)) {
    process.stdout.write('Local staging configuration already exists.\n');
    return;
  }
  if (existing.some(Boolean)) {
    throw new Error('Local staging configuration is partial; run reset before generating it again');
  }
  if (dockerVolumeExists(`${projectName}_office_db_data`)) {
    throw new Error('Local staging volumes exist without their credentials; run reset before generating them again');
  }
  await mkdir(runtimeDirectory, { recursive: true, mode: 0o700 });

  const postgresPassword = secret();
  const keycloakDatabasePassword = secret();
  const runtimeDatabasePassword = secret();
  const monitorDatabasePassword = secret();
  const idempotencySecret = secret();
  const oidcClientSecret = secret();
  const labUserPassword = secret(24);
  const keycloakAdminPassword = secret(24);
  const grafanaAdminPassword = secret(24);
  const issuer = 'https://auth.localhost:8443/realms/office';
  const databaseUrl = databaseConnection('office_application', runtimeDatabasePassword, 'db', 'office');
  const migrationDatabaseUrl = databaseConnection('office', postgresPassword, 'db', 'office');
  const mfaPolicy = JSON.stringify(Object.fromEntries(
    ['provedor', 'sindico', 'morador', 'portaria'].map((role) => [role, { amr: ['webauthn'], acr: [] }])
  ));

  await Promise.all([
    envFile('postgres.env', {
      POSTGRES_DB: 'office', POSTGRES_USER: 'office', POSTGRES_PASSWORD: postgresPassword
    }),
    envFile('keycloak-postgres.env', {
      POSTGRES_DB: 'keycloak', POSTGRES_USER: 'keycloak', POSTGRES_PASSWORD: keycloakDatabasePassword
    }),
    envFile('migration.env', { DATABASE_URL: migrationDatabaseUrl }),
    envFile('seed.env', {
      PGPASSWORD: postgresPassword,
      RUNTIME_DB_PASSWORD: runtimeDatabasePassword,
      MONITOR_DB_PASSWORD: monitorDatabasePassword
    }),
    envFile('app.env', {
      NODE_ENV: 'staging',
      HUMAN_AUTH_ENABLED: 'true',
      HOST: '0.0.0.0',
      PORT: '3000',
      DATABASE_URL: databaseUrl,
      INVITATION_TOKEN_SECRET: secret(),
      IDEMPOTENCY_CACHE_SECRET: idempotencySecret,
      DEVICE_API_KEY_SECRET: secret(),
      PUBLIC_APPLICATION_ORIGIN: 'https://office.localhost:8443',
      TRUST_PROXY: '172.31.46.254/32',
      OIDC_ISSUER: issuer,
      OIDC_AUTHORIZATION_ENDPOINT: `${issuer}/protocol/openid-connect/auth`,
      OIDC_TOKEN_ENDPOINT: `${issuer}/protocol/openid-connect/token`,
      OIDC_JWKS_URI: `${issuer}/protocol/openid-connect/certs`,
      OIDC_CLIENT_ID: 'office-local-staging',
      OIDC_CLIENT_SECRET: oidcClientSecret,
      OIDC_REDIRECT_URI: 'https://office.localhost:8443/auth/callback',
      OIDC_ID_TOKEN_SIGNING_ALG: 'RS256',
      OIDC_PKCE_KEYS: JSON.stringify({ 1: encryptionKey() }),
      OIDC_PKCE_CURRENT_KEY_VERSION: '1',
      OIDC_RETURN_TO_PREFIXES: '/',
      OIDC_FAILURE_PATH: '/auth/error',
      SESSION_CSRF_KEYS: JSON.stringify({ 1: encryptionKey() }),
      SESSION_CSRF_CURRENT_KEY_VERSION: '1',
      HUMAN_MFA_ROLE_POLICY: mfaPolicy,
      OIDC_RECOVERY_URL: 'https://auth.localhost:8443/realms/office/account',
      RECOVERY_WEBHOOK_ISSUERS: issuer,
      RECOVERY_WEBHOOK_KEYS: JSON.stringify({ 1: secret() }),
      AUTH_ALERT_ADAPTER: 'stdout',
      AUTH_ROLLOUT_MODE: 'off'
    }),
    envFile('delivery-worker.env', {
      NODE_ENV: 'staging',
      DATABASE_URL: databaseUrl,
      IDEMPOTENCY_CACHE_SECRET: idempotencySecret,
      DELIVERY_BATCH_SIZE: '50',
      DELIVERY_CONCURRENCY: '5',
      DELIVERY_LEASE_MS: '60000',
      DELIVERY_PROVIDER_TIMEOUT_MS: '30000'
    }),
    envFile('recovery-worker.env', {
      NODE_ENV: 'staging',
      DATABASE_URL: databaseUrl,
      RECOVERY_BATCH_SIZE: '20',
      RECOVERY_CONCURRENCY: '5',
      RECOVERY_LEASE_MS: '2000',
      RECOVERY_ADAPTER_TIMEOUT_MS: '1000',
      AUTH_ALERT_ADAPTER: 'stdout'
    }),
    envFile('postgres-exporter.env', {
      DATA_SOURCE_NAME: `${databaseConnection('office_monitor', monitorDatabasePassword, 'db', 'office')}?sslmode=disable`
    }),
    envFile('keycloak.env', {
      KC_DB_USERNAME: 'keycloak',
      KC_DB_PASSWORD: keycloakDatabasePassword,
      KC_BOOTSTRAP_ADMIN_USERNAME: 'admin',
      KC_BOOTSTRAP_ADMIN_PASSWORD: keycloakAdminPassword
    }),
    envFile('grafana.env', {
      GF_SECURITY_ADMIN_USER: 'admin',
      GF_SECURITY_ADMIN_PASSWORD: grafanaAdminPassword
    })
  ]);

  const template = await readFile(realmTemplate, 'utf8');
  const realm = template
    .replace('__OIDC_CLIENT_SECRET__', oidcClientSecret)
    .replace('__LAB_USER_PASSWORD__', labUserPassword);
  JSON.parse(realm);
  await writeSecure('realm.json', realm);
  process.stdout.write('Generated local-only credentials under .local-staging/.\n');
}

async function check() {
  await configure();
  await exportCertificate();
  const ca = await readFile(path.join(runtimeDirectory, 'caddy-root.crt'));
  const grafana = parseEnv(await readFile(path.join(runtimeDirectory, 'grafana.env'), 'utf8'));
  const grafanaAuthorization = `Basic ${Buffer.from(`${grafana.GF_SECURITY_ADMIN_USER}:${grafana.GF_SECURITY_ADMIN_PASSWORD}`).toString('base64')}`;
  const checks = [
    ['application liveness', () => request('https://office.localhost:8443/health', { ca }, (response) => response.statusCode === 200)],
    ['application readiness', () => request('https://office.localhost:8443/ready', { ca }, (response) => response.statusCode === 200)],
    ['OIDC metadata', () => request('https://auth.localhost:8443/realms/office/.well-known/openid-configuration', { ca }, (response, body) => {
      return response.statusCode === 200 && JSON.parse(body).issuer === 'https://auth.localhost:8443/realms/office';
    })],
    ['OIDC login redirect', () => request('https://office.localhost:8443/auth/login', { ca }, (response) => {
      return response.statusCode === 302 && response.headers.location?.startsWith('https://auth.localhost:8443/realms/office/');
    })],
    ['Prometheus targets', () => request('http://127.0.0.1:9090/api/v1/query?query=up', {}, (response, body) => {
      const result = JSON.parse(body);
      const jobs = new Set(result.data?.result?.filter(freshSuccess).map((item) => item.metric?.job));
      return response.statusCode === 200 && jobs.has('prometheus') && jobs.has('postgres') && jobs.has('blackbox');
    })],
    ['PostgreSQL exporter connection', () => request('http://127.0.0.1:9090/api/v1/query?query=pg_up', {}, (response, body) => {
      const result = JSON.parse(body);
      const connections = result.data?.result ?? [];
      return response.statusCode === 200 && connections.length === 1 && connections.every(freshSuccess);
    })],
    ['HTTPS probes', () => request('http://127.0.0.1:9090/api/v1/query?query=probe_success', {}, (response, body) => {
      const result = JSON.parse(body);
      const probes = result.data?.result ?? [];
      const expected = new Set([
        'https://office.localhost:8443/health',
        'https://office.localhost:8443/ready',
        'https://auth.localhost:8443/realms/office/.well-known/openid-configuration'
      ]);
      return response.statusCode === 200 && probes.length === expected.size && probes.every((item) => {
        return freshSuccess(item) && expected.delete(item.metric?.instance);
      }) && expected.size === 0;
    })],
    ['worker processes', assertWorkersRunning],
    ['Grafana datasource', () => request('http://127.0.0.1:3002/api/datasources/uid/local-prometheus', {
      headers: { authorization: grafanaAuthorization }
    }, (response, body) => {
      const datasource = JSON.parse(body);
      return response.statusCode === 200 && datasource.type === 'prometheus' && datasource.url === 'http://prometheus:9090';
    })],
    ['Grafana dashboard', () => request('http://127.0.0.1:3002/api/dashboards/uid/local-staging', {
      headers: { authorization: grafanaAuthorization }
    }, (response, body) => response.statusCode === 200 && JSON.parse(body).dashboard?.uid === 'local-staging')]
  ];
  for (const [name, operation] of checks) {
    await retry(operation, 90_000);
    process.stdout.write(`PASS ${name}\n`);
  }
}

async function credentials() {
  await configure();
  const keycloak = parseEnv(await readFile(path.join(runtimeDirectory, 'keycloak.env'), 'utf8'));
  const realm = JSON.parse(await readFile(path.join(runtimeDirectory, 'realm.json'), 'utf8'));
  const grafana = parseEnv(await readFile(path.join(runtimeDirectory, 'grafana.env'), 'utf8'));
  process.stdout.write([
    'Application: https://office.localhost:8443',
    `OIDC user: operator / ${realm.users[0].credentials[0].value}`,
    'Keycloak: https://auth.localhost:8443/admin',
    `Keycloak admin: ${keycloak.KC_BOOTSTRAP_ADMIN_USERNAME} / ${keycloak.KC_BOOTSTRAP_ADMIN_PASSWORD}`,
    'Grafana: http://127.0.0.1:3002',
    `Grafana admin: ${grafana.GF_SECURITY_ADMIN_USER} / ${grafana.GF_SECURITY_ADMIN_PASSWORD}`,
    'Prometheus: http://127.0.0.1:9090'
  ].join('\n') + '\n');
}

async function exportCertificate() {
  const destination = path.join(runtimeDirectory, 'caddy-root.crt');
  docker(['cp', 'caddy:/data/caddy/pki/authorities/local/root.crt', destination]);
  await chmod(destination, 0o600);
  process.stdout.write(`Local CA exported to ${path.relative(root, destination)}.\n`);
}

function docker(arguments_) {
  const result = spawnSync('docker', [...composeArguments, ...arguments_], {
    cwd: root,
    stdio: 'inherit',
    env: { ...process.env, COMPOSE_PROJECT_NAME: projectName }
  });
  if (result.error) throw result.error;
  if (result.status !== 0) throw new Error(`docker compose ${arguments_.join(' ')} failed`);
}

async function assertWorkersRunning() {
  const result = spawnSync('docker', [...composeArguments, 'ps', '--format', 'json', 'delivery-worker', 'recovery-worker'], {
    cwd: root,
    encoding: 'utf8',
    env: { ...process.env, COMPOSE_PROJECT_NAME: projectName }
  });
  if (result.error) throw result.error;
  if (result.status !== 0) throw new Error(result.stderr.trim() || 'could not inspect workers');
  const workers = result.stdout.trim().split('\n').filter(Boolean).map((line) => JSON.parse(line));
  if (workers.length !== 2 || workers.some((worker) => worker.State !== 'running')) {
    throw new Error('delivery and recovery worker processes are not running');
  }
}

function dockerVolumeExists(name) {
  const result = spawnSync('docker', ['volume', 'inspect', name], { stdio: 'ignore' });
  if (result.error) throw result.error;
  return result.status === 0;
}

async function ensureComposeInputs() {
  await mkdir(runtimeDirectory, { recursive: true, mode: 0o700 });
  await Promise.all(requiredFiles.map(async (name) => {
    try {
      await readFile(path.join(runtimeDirectory, name));
    } catch {
      await writeSecure(name, '');
    }
  }));
}

function secret(bytes = 48) {
  return randomBytes(bytes).toString('base64url');
}

function encryptionKey() {
  return randomBytes(32).toString('base64url');
}

function databaseConnection(user, password, host, database) {
  return `postgresql://${user}:${password}@${host}:5432/${database}`;
}

async function envFile(name, values) {
  const content = Object.entries(values).map(([key, value]) => `${key}=${value}`).join('\n') + '\n';
  await writeSecure(name, content);
}

async function writeSecure(name, content) {
  const destination = path.join(runtimeDirectory, name);
  await writeFile(destination, content, { mode: 0o600 });
  await chmod(destination, 0o600);
}

function parseEnv(content) {
  return Object.fromEntries(content.trim().split('\n').map((line) => {
    const separator = line.indexOf('=');
    return [line.slice(0, separator), line.slice(separator + 1)];
  }));
}

function request(url, options, validate) {
  return new Promise((resolve, reject) => {
    const client = url.startsWith('https:') ? https : http;
    const operation = client.get(url, { ...options, timeout: 5_000 }, (response) => {
      let body = '';
      response.setEncoding('utf8');
      response.on('data', (chunk) => { body += chunk; });
      response.on('end', () => {
        try {
          if (!validate(response, body)) throw new Error(`unexpected response from ${url}`);
          resolve();
        } catch (error) {
          reject(error);
        }
      });
    });
    operation.on('timeout', () => operation.destroy(new Error(`timeout from ${url}`)));
    operation.on('error', reject);
  });
}

async function retry(operation, timeoutMs) {
  const deadline = Date.now() + timeoutMs;
  let lastError;
  while (Date.now() < deadline) {
    try {
      await operation();
      return;
    } catch (error) {
      lastError = error;
      await delay(2_000);
    }
  }
  throw lastError ?? new Error('check timed out');
}

function freshSuccess(sample) {
  const timestamp = Number(sample.value?.[0]);
  return sample.value?.[1] === '1' && Number.isFinite(timestamp) && Date.now() / 1000 - timestamp < 60;
}
