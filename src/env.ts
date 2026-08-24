const DEFAULT_PORT = 3000;

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

  const publicValidationBaseUrl = environment.PUBLIC_VALIDATION_BASE_URL
    ? normalizePublicValidationBaseUrl(environment.PUBLIC_VALIDATION_BASE_URL)
    : undefined;

  return {
    port,
    databaseUrl,
    invitationTokenSecret,
    deviceApiKeySecret,
    publicValidationBaseUrl,
    host: environment.HOST ?? (environment.LOCAL_DEVELOPMENT_AUTH === 'true' ? '127.0.0.1' : '0.0.0.0'),
    localDevelopmentAuth: environment.LOCAL_DEVELOPMENT_AUTH === 'true',
    secureValidationTransport: environment.NODE_ENV === 'production',
    trustProxy: environment.TRUST_PROXY?.trim() || false
  };
}
