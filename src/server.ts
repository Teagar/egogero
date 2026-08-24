import { pathToFileURL } from 'node:url';

import { createApp } from './app.js';
import { createDevelopmentHeaderAuthenticator, unauthenticatedAuthenticator } from './auth.js';
import { getEnv } from './env.js';

export async function startServer(environment: NodeJS.ProcessEnv = process.env) {
  const env = getEnv(environment);
  const authenticator = env.localDevelopmentAuth
    ? createDevelopmentHeaderAuthenticator(true)
    : unauthenticatedAuthenticator;
  const app = createApp({ authenticator });

  await app.listen({ host: env.host, port: env.port });
  return app;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try {
    await startServer();
  } catch (error) {
    console.error(error);
    process.exitCode = 1;
  }
}
