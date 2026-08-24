const DEFAULT_PORT = 3000;

export function getEnv() {
  const port = Number(process.env.PORT ?? DEFAULT_PORT);

  if (!Number.isInteger(port) || port <= 0) {
    throw new Error('PORT must be a positive integer');
  }

  const databaseUrl = process.env.DATABASE_URL;

  if (!databaseUrl) {
    throw new Error('DATABASE_URL is required');
  }

  return {
    port,
    databaseUrl
  };
}
