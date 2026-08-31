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
  createAuthSnapshotFileSink,
  createRoutedAuthAlertSink,
  createStructuredAuthTelemetry,
  DEFAULT_AUTH_ALERT_ROUTES,
  prepareAuthSnapshotFile,
  registerAuthTelemetryLifecycle,
  type AuthAlertDeliveryAdapter,
  type AuthAlertSink,
  type AuthSnapshotSink
} from './auth-observability.js';
import type { AuthAlertEnvironmentConfig } from './env.js';
import { createHumanAuthRolloutService } from './human-auth-rollout.js';

export function createServerAuthObservability(
  config: AuthAlertEnvironmentConfig,
  dependencies: {
    snapshotSink?: AuthSnapshotSink;
    alertAdapter?: AuthAlertDeliveryAdapter;
    request?: typeof fetch;
  } = {}
) {
  const aggregateAlerts: { current?: AuthAlertSink } = {};
  const snapshotSink = dependencies.snapshotSink ?? (config.snapshotPath
    ? createAuthSnapshotFileSink(config.snapshotPath)
    : undefined);
  const telemetry = createStructuredAuthTelemetry(snapshotSink, {
    instanceId: config.instanceId, stageId: config.stageId,
    aggregateAlertSink: { emit(type, details) { return aggregateAlerts.current?.emit(type, details); } }
  });
  const adapter = dependencies.alertAdapter ?? (config.adapter === 'stdout'
    ? createAuthAlertStdoutAdapter()
    : createAuthAlertWebhookAdapter(config.url, dependencies.request));
  const routed = createRoutedAuthAlertSink(DEFAULT_AUTH_ALERT_ROUTES, adapter, {
    timeoutMs: config.timeoutMs,
    onGap: telemetry.recordObservabilityGap
  });
  aggregateAlerts.current = routed.sink;
  return {
    telemetry,
    alerts: combineAuthAlertSinks(telemetry.alerts, routed.sink),
    routingState: routed.state
  };
}

export async function startServer(environment: NodeJS.ProcessEnv = process.env) {
  const env = getEnv(environment);
  if (env.authAlerts.rolloutMode === 'canary') await prepareAuthSnapshotFile(env.authAlerts.snapshotPath!);
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
  const authObservability = createServerAuthObservability(env.authAlerts);
  const authTelemetry = authObservability.telemetry;
  const authRateLimiter = createPrismaAuthRateLimiter(prisma, authTelemetry.metrics, authObservability.alerts);
  const humanAuthRolloutService = env.oidc || env.sessions
    ? createHumanAuthRolloutService(prisma)
    : undefined;
  if (env.humanAuthEnabled) await humanAuthRolloutService!.verifyGlobalPolicy();
  const oidcService = env.oidc
    ? await createOidcService(env.oidc, createPrismaOidcLoginStore(prisma, humanAuthRolloutService!), fetch, {
        rateLimiter: authRateLimiter,
        metrics: authTelemetry.metrics,
        alerts: authObservability.alerts,
        rolloutGate: humanAuthRolloutService!
      })
    : undefined;
  const humanAdministrationService = env.humanAdministration
    ? createHumanAdministrationService(prisma, env.humanAdministration)
    : undefined;
  const browserSessionStore = env.sessions
    ? createPrismaBrowserSessionStore(prisma, {
        ...env.sessions,
        mfaPolicy: env.humanAdministration?.mfaPolicy
      }, { rateLimiter: authRateLimiter, metrics: authTelemetry.metrics, alerts: authObservability.alerts,
        rolloutGate: humanAuthRolloutService! })
    : undefined;
  const browserSessionService = browserSessionStore
    ? createBrowserSessionService(browserSessionStore)
    : undefined;
  const humanServicesComposed = !env.humanAuthEnabled || Boolean(
    oidcService && browserSessionService && browserSessionStore && humanAdministrationService && authRateLimiter
  );
  if (!humanServicesComposed) throw new Error('Human authentication services are incomplete');
  const baseAuthenticator = browserSessionStore
    ? createCredentialRouter(browserSessionStore, deviceAuthenticator, developmentAuthenticator, authRateLimiter)
    : developmentAuthenticator
      ? createCompositeAuthenticator(deviceAuthenticator, developmentAuthenticator)
      : deviceAuthenticator;
  const authenticator = {
    authenticate: baseAuthenticator.authenticate.bind(baseAuthenticator),
    authorizationAlerts: authObservability.alerts
  };
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
    humanAuthRolloutService,
    authRateLimiter,
    frontendRoot: path.resolve(process.cwd(), 'web/dist'),
    readiness: {
      deviceSecretValidated: true,
      humanAuthEnabled: env.humanAuthEnabled,
      oidcMetadataValidated: !env.humanAuthEnabled || Boolean(oidcService),
      requiredServicesComposed: humanServicesComposed,
      async checkDatabase() {
        await prisma.$queryRaw`SELECT 1`;
      },
      async checkHumanAuthRolloutPolicy() {
        await humanAuthRolloutService!.verifyGlobalPolicy();
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
