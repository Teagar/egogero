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
import {
  combineAuthAlertSinks,
  createAuthAlertStdoutAdapter,
  createAuthAlertWebhookAdapter,
  createRoutedAuthAlertSink,
  createStructuredAuthTelemetry,
  DEFAULT_AUTH_ALERT_ROUTES,
  registerAuthTelemetryLifecycle,
  type AuthAlertDeliveryAdapter,
  type AuthSnapshotSink
} from './auth-observability.js';
import type { AuthAlertEnvironmentConfig } from './env.js';

export function createServerAuthObservability(
  config: AuthAlertEnvironmentConfig,
  dependencies: {
    snapshotSink?: AuthSnapshotSink;
    alertAdapter?: AuthAlertDeliveryAdapter;
    request?: typeof fetch;
  } = {}
) {
  const telemetry = createStructuredAuthTelemetry(dependencies.snapshotSink);
  const adapter = dependencies.alertAdapter ?? (config.adapter === 'stdout'
    ? createAuthAlertStdoutAdapter()
    : createAuthAlertWebhookAdapter(config.url, dependencies.request));
  const routed = createRoutedAuthAlertSink(DEFAULT_AUTH_ALERT_ROUTES, adapter, {
    timeoutMs: config.timeoutMs,
    onGap: telemetry.recordObservabilityGap
  });
  return {
    telemetry,
    alerts: combineAuthAlertSinks(telemetry.alerts, routed.sink),
    routingState: routed.state
  };
}

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
  const developmentAuthenticator = env.localDevelopmentAuth
    ? createDevelopmentHeaderAuthenticator(true)
    : undefined;
  const notificationSender = environment.NODE_ENV === 'development'
    ? createDevelopmentNotificationSender()
    : createUnavailableNotificationSender();
  const authObservability = createServerAuthObservability(env.authAlerts);
  const authTelemetry = authObservability.telemetry;
  const authRateLimiter = createPrismaAuthRateLimiter(prisma, authTelemetry.metrics, authObservability.alerts);
  const oidcService = env.oidc
    ? await createOidcService(env.oidc, createPrismaOidcLoginStore(prisma), fetch, {
        rateLimiter: authRateLimiter,
        metrics: authTelemetry.metrics,
        alerts: authObservability.alerts
      })
    : undefined;
  const humanAdministrationService = env.humanAdministration
    ? createHumanAdministrationService(prisma, env.humanAdministration)
    : undefined;
  const browserSessionStore = env.sessions
    ? createPrismaBrowserSessionStore(prisma, {
        ...env.sessions,
        mfaPolicy: env.humanAdministration?.mfaPolicy
      }, { rateLimiter: authRateLimiter, metrics: authTelemetry.metrics, alerts: authObservability.alerts })
    : undefined;
  const browserSessionService = browserSessionStore
    ? createBrowserSessionService(browserSessionStore)
    : undefined;
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
    frontendRoot: path.resolve(process.cwd(), 'web/dist')
  });
  registerAuthTelemetryLifecycle(app, authTelemetry);

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
