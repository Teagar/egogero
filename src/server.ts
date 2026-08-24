import { createApp } from './app.js';
import { createDevelopmentHeaderAuthenticator } from './auth.js';
import { getEnv } from './env.js';

const env = getEnv();
const app = createApp({ authenticator: createDevelopmentHeaderAuthenticator(process.env.NODE_ENV) });

try {
  await app.listen({ host: '0.0.0.0', port: env.port });
} catch (error) {
  app.log.error(error);
  process.exit(1);
}
