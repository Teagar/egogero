import { oidcConfigFromEnvironment } from './oidc.js';
import { sessionConfigFromEnvironment } from './sessions.js';
import { humanAdministrationConfigFromEnvironment } from './human-administration.js';
import { trustedProxyFromEnvironment } from './client-ip.js';

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
  'RECOVERY_WEBHOOK_SECRET',
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
    trustProxy,
    oidc,
    sessions,
    humanAdministration
  };
}
