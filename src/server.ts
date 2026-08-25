import { pathToFileURL } from 'node:url';
import path from 'node:path';

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
import { createOidcService, createPrismaOidcLoginStore } from './oidc.js';
import {
  createBrowserSessionService,
  createCredentialRouter,
  createPrismaBrowserSessionStore
} from './sessions.js';
import { createHumanAdministrationService } from './human-administration.js';
import { createPrismaAuthRateLimiter } from './auth-rate-limits.js';
import { createStructuredAuthTelemetry, registerAuthTelemetryLifecycle } from './auth-observability.js';

export async function startServer(environment: NodeJS.ProcessEnv = process.env) {
  const env = getEnv(environment);
  const deviceStore = createPrismaDeviceStore(prisma, env.deviceApiKeySecret);
  const invitationStore = createPrismaInvitationStore(
    prisma,
    env.invitationTokenSecret,
    { idempotencySecret: env.idempotencyCacheSecret, idempotencyTtlMs: env.idempotencyTtlMs }
  );
  await deviceStore.verifyConfiguration();
  await invitationStore.verifyIdempotencyConfiguration!();
  const deviceAuthenticator = createDeviceAuthenticator(deviceStore);
  const developmentAuthenticator = env.localDevelopmentAuth
    ? createDevelopmentHeaderAuthenticator(true)
    : undefined;
  const notificationSender = environment.NODE_ENV === 'development'
    ? createDevelopmentNotificationSender()
    : createUnavailableNotificationSender();
  const authTelemetry = createStructuredAuthTelemetry();
  const authRateLimiter = createPrismaAuthRateLimiter(prisma, authTelemetry.metrics, authTelemetry.alerts);
  const oidcService = env.oidc
    ? await createOidcService(env.oidc, createPrismaOidcLoginStore(prisma), fetch, {
        rateLimiter: authRateLimiter,
        metrics: authTelemetry.metrics,
        alerts: authTelemetry.alerts
      })
    : undefined;
  const humanAdministrationService = env.humanAdministration
    ? createHumanAdministrationService(prisma, env.humanAdministration)
    : undefined;
  const browserSessionStore = env.sessions
    ? createPrismaBrowserSessionStore(prisma, {
        ...env.sessions,
        mfaPolicy: env.humanAdministration?.mfaPolicy
      }, { rateLimiter: authRateLimiter, metrics: authTelemetry.metrics, alerts: authTelemetry.alerts })
    : undefined;
  const browserSessionService = browserSessionStore
    ? createBrowserSessionService(browserSessionStore)
    : undefined;
  const humanServicesComposed = !env.humanAuthEnabled || Boolean(
    oidcService && browserSessionService && browserSessionStore && humanAdministrationService && authRateLimiter
  );
  if (!humanServicesComposed) throw new Error('Human authentication services are incomplete');
  const authenticator = browserSessionStore
    ? createCredentialRouter(browserSessionStore, deviceAuthenticator, developmentAuthenticator, authRateLimiter)
    : developmentAuthenticator
      ? createCompositeAuthenticator(deviceAuthenticator, developmentAuthenticator)
      : deviceAuthenticator;
  const app = createApp({
    authenticator,
    invitationStore,
    deviceStore,
    deviceRateLimiter: createPrismaDeviceRateLimiter(prisma),
    notificationSender,
    publicValidationBaseUrl: env.publicValidationBaseUrl,
    secureValidationTransport: env.secureValidationTransport,
    trustProxy: env.trustProxy,
    oidcService,
    browserSessionService,
    browserSessionStore,
    humanAdministrationService,
    authRateLimiter,
    frontendRoot: path.resolve(process.cwd(), 'web/dist'),
    readiness: {
      deviceSecretValidated: true,
      humanAuthEnabled: env.humanAuthEnabled,
      oidcMetadataValidated: !env.humanAuthEnabled || Boolean(oidcService),
      requiredServicesComposed: humanServicesComposed,
      async checkDatabase() {
        await prisma.$queryRaw`SELECT 1`;
      }
    }
  });
  registerAuthTelemetryLifecycle(app, authTelemetry);

  await app.listen({ host: env.host, port: env.port });
  return app;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try {
    await startServer();
  } catch {
    console.error('Startup failed');
    process.exitCode = 1;
  }
}
