import { pathToFileURL } from 'node:url';

import { createApp } from './app.js';
import { createCompositeAuthenticator, createDevelopmentHeaderAuthenticator } from './auth.js';
import { createDevelopmentNotificationSender, createUnavailableNotificationSender } from './convites.js';
import { createDeviceAuthenticator, createPrismaDeviceRateLimiter, createPrismaDeviceStore } from './dispositivos.js';
import { getEnv } from './env.js';
import { prisma } from './lib/prisma.js';

export async function startServer(environment: NodeJS.ProcessEnv = process.env) {
  const env = getEnv(environment);
  const deviceStore = createPrismaDeviceStore(prisma, env.deviceApiKeySecret);
  const deviceAuthenticator = createDeviceAuthenticator(deviceStore);
  const authenticator = env.localDevelopmentAuth
    ? createCompositeAuthenticator(deviceAuthenticator, createDevelopmentHeaderAuthenticator(true))
    : deviceAuthenticator;
  const notificationSender = environment.NODE_ENV === 'development'
    ? createDevelopmentNotificationSender()
    : createUnavailableNotificationSender();
  const app = createApp({
    authenticator,
    invitationTokenSecret: env.invitationTokenSecret,
    idempotencyCacheSecret: env.idempotencyCacheSecret,
    idempotencyTtlMs: env.idempotencyTtlMs,
    deviceApiKeySecret: env.deviceApiKeySecret,
    deviceRateLimiter: createPrismaDeviceRateLimiter(prisma),
    notificationSender,
    publicValidationBaseUrl: env.publicValidationBaseUrl,
    secureValidationTransport: env.secureValidationTransport,
    trustProxy: env.trustProxy
  });

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
