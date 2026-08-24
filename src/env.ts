const DEFAULT_PORT = 3000;

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

  return {
    port,
    databaseUrl,
    invitationTokenSecret,
    host: environment.HOST ?? (environment.LOCAL_DEVELOPMENT_AUTH === 'true' ? '127.0.0.1' : '0.0.0.0'),
    localDevelopmentAuth: environment.LOCAL_DEVELOPMENT_AUTH === 'true'
  };
}
