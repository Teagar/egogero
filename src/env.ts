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

  return {
    port,
    databaseUrl,
    host: environment.HOST ?? (environment.LOCAL_DEVELOPMENT_AUTH === 'true' ? '127.0.0.1' : '0.0.0.0'),
    localDevelopmentAuth: environment.LOCAL_DEVELOPMENT_AUTH === 'true'
  };
}
