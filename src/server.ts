import { pathToFileURL } from 'node:url';

import { createApp } from './app.js';
import { createCompositeAuthenticator, createDevelopmentHeaderAuthenticator } from './auth.js';
import {
  createDevelopmentNotificationSender,
  createPrismaInvitationStore,
  createUnavailableNotificationSender
} from './convites.js';
import { createDeviceAuthenticator, createPrismaDeviceRateLimiter, createPrismaDeviceStore } from './dispositivos.js';
import { getEnv } from './env.js';
import { prisma } from './lib/prisma.js';

export async function startServer(environment: NodeJS.ProcessEnv = process.env) {
  const env = getEnv(environment);
  const deviceStore = createPrismaDeviceStore(prisma, env.deviceApiKeySecret);
  const invitationStore = createPrismaInvitationStore(
    prisma,
    env.invitationTokenSecret,
    { idempotencySecret: env.idempotencyCacheSecret, idempotencyTtlMs: env.idempotencyTtlMs }
  );
  await invitationStore.verifyIdempotencyConfiguration!();
  const deviceAuthenticator = createDeviceAuthenticator(deviceStore);
  const authenticator = env.localDevelopmentAuth
    ? createCompositeAuthenticator(deviceAuthenticator, createDevelopmentHeaderAuthenticator(true))
    : deviceAuthenticator;
  const notificationSender = environment.NODE_ENV === 'development'
    ? createDevelopmentNotificationSender()
    : createUnavailableNotificationSender();
  const app = createApp({
    authenticator,
    invitationStore,
    deviceStore,
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
