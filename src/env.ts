import { oidcConfigFromEnvironment } from './oidc.js';
import { sessionConfigFromEnvironment } from './sessions.js';
import { humanAdministrationConfigFromEnvironment } from './human-administration.js';
import { trustedProxyFromEnvironment } from './client-ip.js';

const DEFAULT_PORT = 3000;
const DEFAULT_IDEMPOTENCY_TTL_SECONDS = 24 * 60 * 60;
const DEFAULT_AUTH_ALERT_TIMEOUT_MS = 5_000;

export type AuthAlertEnvironmentConfig =
  | { adapter: 'stdout'; timeoutMs: number }
  | { adapter: 'https_webhook'; timeoutMs: number; url: string };

export function authAlertConfigFromEnvironment(environment: NodeJS.ProcessEnv): AuthAlertEnvironmentConfig {
  const adapter = environment.AUTH_ALERT_ADAPTER ?? 'stdout';
  const timeoutMs = Number(environment.AUTH_ALERT_TIMEOUT_MS ?? DEFAULT_AUTH_ALERT_TIMEOUT_MS);
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 100 || timeoutMs > 10_000) {
    throw new Error('AUTH_ALERT_TIMEOUT_MS must be an integer between 100 and 10000');
  }
  if (adapter === 'stdout') {
    if (environment.AUTH_ALERT_WEBHOOK_URL !== undefined) {
      throw new Error('AUTH_ALERT_WEBHOOK_URL is only valid with AUTH_ALERT_ADAPTER=https_webhook');
    }
    return { adapter, timeoutMs };
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
  return { adapter, timeoutMs, url: url.toString() };
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
  const port = Number(environment.PORT ?? DEFAULT_PORT);

  if (!Number.isInteger(port) || port <= 0) {
    throw new Error('PORT must be a positive integer');
  }

  const databaseUrl = environment.DATABASE_URL;

  if (!databaseUrl) {
    throw new Error('DATABASE_URL is required');
  }

  const invitationTokenSecret = environment.INVITATION_TOKEN_SECRET;
  if (!invitationTokenSecret || Buffer.byteLength(invitationTokenSecret) < 32) {
    throw new Error('INVITATION_TOKEN_SECRET must be at least 32 bytes');
  }

  const deviceApiKeySecret = environment.DEVICE_API_KEY_SECRET;
  if (!deviceApiKeySecret || Buffer.byteLength(deviceApiKeySecret) < 32) {
    throw new Error('DEVICE_API_KEY_SECRET must be at least 32 bytes');
  }

  const idempotencyCacheSecret = environment.IDEMPOTENCY_CACHE_SECRET;
  if (!idempotencyCacheSecret || Buffer.byteLength(idempotencyCacheSecret) < 32) {
    throw new Error('IDEMPOTENCY_CACHE_SECRET must be at least 32 bytes');
  }
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

  return {
    port,
    databaseUrl,
    invitationTokenSecret,
    idempotencyCacheSecret,
    idempotencyTtlMs: idempotencyTtlSeconds * 1000,
    deviceApiKeySecret,
    publicValidationBaseUrl,
    host: environment.HOST ?? (environment.LOCAL_DEVELOPMENT_AUTH === 'true' ? '127.0.0.1' : '0.0.0.0'),
    localDevelopmentAuth: environment.LOCAL_DEVELOPMENT_AUTH === 'true',
    secureValidationTransport: environment.NODE_ENV === 'production',
    authAlerts: authAlertConfigFromEnvironment(environment),
    trustProxy: trustedProxyFromEnvironment(environment.TRUST_PROXY),
    oidc: oidcConfigFromEnvironment(environment),
    sessions: sessionConfigFromEnvironment(environment),
    humanAdministration: humanAdministrationConfigFromEnvironment(environment)
  };
}
