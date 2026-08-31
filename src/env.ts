import { oidcConfigFromEnvironment } from './oidc.js';
import { sessionConfigFromEnvironment } from './sessions.js';
import { humanAdministrationConfigFromEnvironment } from './human-administration.js';
import { trustedProxyFromEnvironment } from './client-ip.js';
import { assertDistinctSecretMaterial } from './secret-material.js';

const DEFAULT_PORT = 3000;
const DEFAULT_IDEMPOTENCY_TTL_SECONDS = 24 * 60 * 60;
const HUMAN_AUTH_VARIABLES = [
  'PUBLIC_APPLICATION_ORIGIN',
  'OIDC_ISSUER',
  'OIDC_AUTHORIZATION_ENDPOINT',
  'OIDC_TOKEN_ENDPOINT',
  'OIDC_JWKS_URI',
  'OIDC_CLIENT_ID',
  'OIDC_CLIENT_SECRET',
  'OIDC_REDIRECT_URI',
  'OIDC_ID_TOKEN_SIGNING_ALG',
  'OIDC_PKCE_KEYS',
  'OIDC_PKCE_CURRENT_KEY_VERSION',
  'OIDC_RETURN_TO_PREFIXES',
  'OIDC_FAILURE_PATH',
  'SESSION_CSRF_KEYS',
  'SESSION_CSRF_CURRENT_KEY_VERSION',
  'OIDC_RECOVERY_URL',
  'RECOVERY_WEBHOOK_ISSUERS',
  'RECOVERY_WEBHOOK_KEYS',
  'HUMAN_MFA_ROLE_POLICY'
] as const;

function validateDatabaseUrl(value: string) {
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    throw new Error('DATABASE_URL must be an absolute PostgreSQL URL');
  }
  if (!['postgres:', 'postgresql:'].includes(url.protocol) || !url.hostname || url.hash) {
    throw new Error('DATABASE_URL must be an absolute PostgreSQL URL');
  }
}

function validateDeploymentSecret(value: string | undefined, name: string) {
  if (!value || Buffer.byteLength(value) < 32) throw new Error(`${name} must be at least 32 bytes`);
  if (new Set(value).size < 8 || /^(.)\1{31,}$/s.test(value)
    || /(change[-_ ]?me|replace[-_ ]?me|placeholder|not[-_ ]?a[-_ ]?secret|dummy[-_ ]?secret)/i.test(value)) {
    throw new Error(`${name} must not be a placeholder or repeated-character value`);
  }
  return value;
}

const DEFAULT_AUTH_ALERT_TIMEOUT_MS = 5_000;

export type AuthAlertEnvironmentConfig =
  | { adapter: 'stdout'; timeoutMs: number; rolloutMode: 'off'; instanceId: string; stageId: string; snapshotPath?: string }
  | { adapter: 'https_webhook'; timeoutMs: number; rolloutMode: 'off' | 'canary'; url: string; instanceId: string; stageId: string; snapshotPath?: string };

export function authAlertConfigFromEnvironment(environment: NodeJS.ProcessEnv): AuthAlertEnvironmentConfig {
  const adapter = environment.AUTH_ALERT_ADAPTER ?? 'stdout';
  const instanceId = environment.AUTH_ROLLOUT_INSTANCE_ID ?? '00000000-0000-4000-8000-000000000000';
  const stageId = environment.AUTH_ROLLOUT_STAGE_ID ?? 'staging:non-canary';
  const snapshotPath = environment.AUTH_ROLLOUT_SNAPSHOT_PATH;
  const rawRolloutMode = environment.AUTH_ROLLOUT_MODE ?? 'off';
  if (rawRolloutMode !== 'off' && rawRolloutMode !== 'canary') throw new Error('AUTH_ROLLOUT_MODE must be off or canary');
  const rolloutMode: 'off' | 'canary' = rawRolloutMode;
  if (rolloutMode === 'off' && ['AUTH_ROLLOUT_INSTANCE_ID', 'AUTH_ROLLOUT_STAGE_ID',
    'AUTH_ROLLOUT_SNAPSHOT_PATH', 'AUTH_ALERT_SMOKE_ACK_ID'].some((name) => environment[name] !== undefined)) {
    throw new Error('Canary rollout identity, snapshot, and acknowledgement variables require AUTH_ROLLOUT_MODE=canary');
  }
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(instanceId)) {
    throw new Error('AUTH_ROLLOUT_INSTANCE_ID must be an injected UUID v4');
  }
  if (!stageId || !/^(?:staging|production):[a-z0-9](?:[a-z0-9._-]{0,62}[a-z0-9])?$/.test(stageId)) {
    throw new Error('AUTH_ROLLOUT_STAGE_ID must identify a bounded staging or production partition');
  }
  if (snapshotPath !== undefined && (!snapshotPath.startsWith('/') || snapshotPath.includes('\0'))) {
    throw new Error('AUTH_ROLLOUT_SNAPSHOT_PATH must be an absolute path');
  }
  if (rolloutMode === 'canary' && (adapter !== 'https_webhook' || !environment.AUTH_ALERT_SMOKE_ACK_ID
    || !/^[A-Za-z0-9._-]{8,128}$/.test(environment.AUTH_ALERT_SMOKE_ACK_ID) || !snapshotPath
    || instanceId === '00000000-0000-4000-8000-000000000000' || stageId.endsWith(':non-canary')
    || environment.AUTH_ROLLOUT_INSTANCE_ID === undefined
    || environment.AUTH_ROLLOUT_STAGE_ID === undefined)) {
    throw new Error('Canary requires HTTPS alerts, acknowledged smoke evidence, durable snapshots, instance ID, and stage ID');
  }
  const timeoutMs = Number(environment.AUTH_ALERT_TIMEOUT_MS ?? DEFAULT_AUTH_ALERT_TIMEOUT_MS);
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 100 || timeoutMs > 10_000) {
    throw new Error('AUTH_ALERT_TIMEOUT_MS must be an integer between 100 and 10000');
  }
  if (adapter === 'stdout') {
    if (environment.AUTH_ALERT_WEBHOOK_URL !== undefined) {
      throw new Error('AUTH_ALERT_WEBHOOK_URL is only valid with AUTH_ALERT_ADAPTER=https_webhook');
    }
    return { adapter, timeoutMs, rolloutMode: 'off', instanceId, stageId, snapshotPath };
  }
  if (adapter !== 'https_webhook') {
    throw new Error('AUTH_ALERT_ADAPTER must be stdout or https_webhook');
  }
  const rawUrl = environment.AUTH_ALERT_WEBHOOK_URL;
  if (!rawUrl) throw new Error('AUTH_ALERT_WEBHOOK_URL is required for https_webhook');
  let url: URL;
  try { url = new URL(rawUrl); } catch { throw new Error('AUTH_ALERT_WEBHOOK_URL must be an absolute HTTPS URL'); }
  if (url.protocol !== 'https:' || !url.hostname || url.username || url.password || url.search || url.hash) {
    throw new Error('AUTH_ALERT_WEBHOOK_URL must be HTTPS without credentials, query, or fragment');
  }
  return { adapter, timeoutMs, rolloutMode, url: url.toString(), instanceId, stageId, snapshotPath };
}

export function normalizePublicValidationBaseUrl(value: string) {
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    throw new Error('PUBLIC_VALIDATION_BASE_URL must be an absolute HTTPS URL');
  }

  if (url.protocol !== 'https:' || url.username || url.password || url.search || url.hash || !url.hostname) {
    throw new Error('PUBLIC_VALIDATION_BASE_URL must be an absolute HTTPS URL without credentials, query, or fragment');
  }

  return url.toString().replace(/\/$/, '');
}

export function getEnv(environment: NodeJS.ProcessEnv = process.env) {
  const nodeEnvironment = environment.NODE_ENV ?? 'development';
  if (!['development', 'test', 'staging', 'production'].includes(nodeEnvironment)) {
    throw new Error('NODE_ENV must be development, test, staging, or production');
  }
  const deployed = nodeEnvironment === 'staging' || nodeEnvironment === 'production';
  if (environment.HUMAN_AUTH_ENABLED !== undefined
    && !['true', 'false'].includes(environment.HUMAN_AUTH_ENABLED)) {
    throw new Error('HUMAN_AUTH_ENABLED must be true or false');
  }
  if (deployed && environment.HUMAN_AUTH_ENABLED === undefined) {
    throw new Error('HUMAN_AUTH_ENABLED must be explicitly true or false in staging and production');
  }
  const humanAuthEnabled = environment.HUMAN_AUTH_ENABLED === 'true';
  if (!humanAuthEnabled) {
    const stray = HUMAN_AUTH_VARIABLES.find((name) => environment[name] !== undefined);
    if (stray) throw new Error(`${stray} must be absent when HUMAN_AUTH_ENABLED=false`);
  }
  if (deployed && environment.LOCAL_DEVELOPMENT_AUTH === 'true') {
    throw new Error('LOCAL_DEVELOPMENT_AUTH is forbidden in staging and production');
  }

  const port = Number(environment.PORT ?? DEFAULT_PORT);

  if (!Number.isInteger(port) || port <= 0) {
    throw new Error('PORT must be a positive integer');
  }

  const databaseUrl = environment.DATABASE_URL;

  if (!databaseUrl) {
    throw new Error('DATABASE_URL is required');
  }
  validateDatabaseUrl(databaseUrl);

  const invitationTokenSecret = validateDeploymentSecret(
    environment.INVITATION_TOKEN_SECRET, 'INVITATION_TOKEN_SECRET'
  );
  const deviceApiKeySecret = validateDeploymentSecret(environment.DEVICE_API_KEY_SECRET, 'DEVICE_API_KEY_SECRET');
  const idempotencyCacheSecret = validateDeploymentSecret(
    environment.IDEMPOTENCY_CACHE_SECRET, 'IDEMPOTENCY_CACHE_SECRET'
  );
  const idempotencyTtlSeconds = Number(
    environment.IDEMPOTENCY_REPLAY_TTL_SECONDS ?? DEFAULT_IDEMPOTENCY_TTL_SECONDS
  );
  if (!Number.isSafeInteger(idempotencyTtlSeconds) || idempotencyTtlSeconds < 60
    || idempotencyTtlSeconds > 30 * 24 * 60 * 60) {
    throw new Error('IDEMPOTENCY_REPLAY_TTL_SECONDS must be an integer between 60 and 2592000');
  }

  const publicValidationBaseUrl = environment.PUBLIC_VALIDATION_BASE_URL
    ? normalizePublicValidationBaseUrl(environment.PUBLIC_VALIDATION_BASE_URL)
    : undefined;

  const oidc = oidcConfigFromEnvironment(environment);
  const sessions = sessionConfigFromEnvironment(environment);
  const humanAdministration = humanAdministrationConfigFromEnvironment(environment);
  const trustProxy = trustedProxyFromEnvironment(environment.TRUST_PROXY);
  if (humanAuthEnabled) {
    if (!oidc || !sessions || !humanAdministration) throw new Error('Human authentication configuration is incomplete');
    if (new URL(oidc.redirectUri).origin !== sessions.publicApplicationOrigin) {
      throw new Error('OIDC_REDIRECT_URI must use PUBLIC_APPLICATION_ORIGIN');
    }
    if (humanAdministration.publicApplicationOrigin !== sessions.publicApplicationOrigin) {
      throw new Error('Human authentication origins do not match');
    }
    if (!humanAdministration.recoveryWebhookIssuers.has(oidc.issuer)) {
      throw new Error('RECOVERY_WEBHOOK_ISSUERS must include OIDC_ISSUER');
    }
    if (deployed && trustProxy === false) {
      throw new Error('TRUST_PROXY must identify the HTTPS proxy allowlist when human authentication is enabled');
    }
  }

  const secretDomains = [invitationTokenSecret, deviceApiKeySecret, idempotencyCacheSecret]
    .map((value) => Buffer.from(value, 'utf8'));
  if (humanAuthEnabled) {
    secretDomains.push(
      Buffer.from(oidc!.clientSecret, 'utf8'),
      ...[...humanAdministration!.recoveryWebhookSecrets.values()].map((secret) => Buffer.from(secret)),
      ...[...oidc!.pkceKeys.values()].map((key) => Buffer.from(key)),
      ...[...sessions!.csrfKeys.values()].map((key) => Buffer.from(key))
    );
  }
  assertDistinctSecretMaterial(secretDomains);

  const authAlerts = authAlertConfigFromEnvironment(environment);
  if (authAlerts.rolloutMode === 'canary' && !humanAuthEnabled) {
    throw new Error('AUTH_ROLLOUT_MODE=canary requires HUMAN_AUTH_ENABLED=true');
  }

  return {
    nodeEnvironment,
    humanAuthEnabled,
    port,
    databaseUrl,
    invitationTokenSecret,
    idempotencyCacheSecret,
    idempotencyTtlMs: idempotencyTtlSeconds * 1000,
    deviceApiKeySecret,
    publicValidationBaseUrl,
    host: environment.HOST ?? (environment.LOCAL_DEVELOPMENT_AUTH === 'true' ? '127.0.0.1' : '0.0.0.0'),
    localDevelopmentAuth: environment.LOCAL_DEVELOPMENT_AUTH === 'true',
    secureValidationTransport: deployed,
    authAlerts,
    trustProxy,
    oidc,
    sessions,
    humanAdministration
  };
}
