import { createHash } from 'node:crypto';

import { Prisma, type PrismaClient } from '@prisma/client';

import { noopAuthAlerts, noopAuthMetrics, safeAuthAlerts, safeAuthMetrics } from './auth-observability.js';
import type { AuthAlertSink, AuthMetrics } from './auth-observability.js';

export const AUTH_RATE_LIMIT_POLICIES = {
  login_ip: { limit: 5, windowMs: 10 * 60_000 },
  callback_failure_ip: { limit: 10, windowMs: 15 * 60_000 },
  session_creation_account: { limit: 10, windowMs: 15 * 60_000, backoffMs: 15 * 60_000 },
  recovery_ip: { limit: 3, windowMs: 30 * 60_000 },
  reauthentication_account: { limit: 5, windowMs: 10 * 60_000 },
  authentication_failure_ip: { limit: 60, windowMs: 60_000 }
} as const;

export type AuthRateLimitAction = keyof typeof AUTH_RATE_LIMIT_POLICIES;
export type AuthRateLimitDecision = { allowed: boolean; retryAfterSeconds: number; repeatedExcess: boolean };

export interface AuthRateLimiter {
  check(action: AuthRateLimitAction, subject: string, consume?: boolean): Promise<AuthRateLimitDecision>;
  cleanup?(): Promise<number>;
}

function boundedSubject(value: string) {
  return value.length <= 128 ? value : createHash('sha256').update(value).digest('hex');
}

export function createPrismaAuthRateLimiter(
  client: PrismaClient,
  metricsSink: AuthMetrics = noopAuthMetrics,
  alertSink: AuthAlertSink = noopAuthAlerts
): AuthRateLimiter {
  const metrics = safeAuthMetrics(metricsSink);
  const alerts = safeAuthAlerts(alertSink);
  return {
    async check(action, rawSubject, consume = true) {
      const policy = AUTH_RATE_LIMIT_POLICIES[action];
      const subject = boundedSubject(rawSubject);
      const rows = consume
        ? await client.$queryRaw<Array<{ allowed: boolean; retryAfterSeconds: number; deniedCount: number }>>(Prisma.sql`
            WITH db_clock AS MATERIALIZED (SELECT clock_timestamp() AS now), upserted AS (
              INSERT INTO "AuthenticationRateLimit" (
                action, subject, "windowStartedAt", count, "deniedCount", "blockedUntil", "updatedAt"
              ) SELECT ${action}, ${subject}, now, 1, 0, NULL, now FROM db_clock
              ON CONFLICT (action, subject) DO UPDATE SET
                "windowStartedAt" = CASE
                  WHEN "AuthenticationRateLimit"."windowStartedAt" + (${policy.windowMs} * interval '1 millisecond') <= clock_timestamp()
                    THEN clock_timestamp() ELSE "AuthenticationRateLimit"."windowStartedAt" END,
                count = CASE
                  WHEN "AuthenticationRateLimit"."windowStartedAt" + (${policy.windowMs} * interval '1 millisecond') <= clock_timestamp()
                    THEN 1 ELSE "AuthenticationRateLimit".count + 1 END,
                "deniedCount" = CASE
                  WHEN "AuthenticationRateLimit"."windowStartedAt" + (${policy.windowMs} * interval '1 millisecond') <= clock_timestamp()
                    THEN 0
                  WHEN "AuthenticationRateLimit".count >= ${policy.limit} THEN "AuthenticationRateLimit"."deniedCount" + 1
                  ELSE "AuthenticationRateLimit"."deniedCount" END,
                "blockedUntil" = CASE
                  WHEN ${'backoffMs' in policy ? policy.backoffMs : 0} > 0
                    AND "AuthenticationRateLimit".count >= ${policy.limit}
                    THEN GREATEST(COALESCE("AuthenticationRateLimit"."blockedUntil", clock_timestamp()), clock_timestamp())
                      + (POWER(2, LEAST(4, "AuthenticationRateLimit"."deniedCount"))
                        * ${'backoffMs' in policy ? policy.backoffMs : 0} * interval '1 millisecond')
                  WHEN "AuthenticationRateLimit"."windowStartedAt" + (${policy.windowMs} * interval '1 millisecond') <= clock_timestamp()
                    THEN NULL ELSE "AuthenticationRateLimit"."blockedUntil" END,
                "updatedAt" = clock_timestamp()
              RETURNING *
            )
            SELECT count <= ${policy.limit}
                AND COALESCE("blockedUntil", clock_timestamp()) <= clock_timestamp() AS allowed,
              GREATEST(1, CEIL(EXTRACT(EPOCH FROM (GREATEST(
                "windowStartedAt" + (${policy.windowMs} * interval '1 millisecond'),
                COALESCE("blockedUntil", clock_timestamp())
              ) - clock_timestamp())))::integer) AS "retryAfterSeconds",
              "deniedCount" FROM upserted
          `)
        : await client.$queryRaw<Array<{ allowed: boolean; retryAfterSeconds: number; deniedCount: number }>>(Prisma.sql`
            SELECT count < ${policy.limit}
                AND COALESCE("blockedUntil", clock_timestamp()) <= clock_timestamp() AS allowed,
              GREATEST(1, CEIL(EXTRACT(EPOCH FROM (GREATEST(
                "windowStartedAt" + (${policy.windowMs} * interval '1 millisecond'),
                COALESCE("blockedUntil", clock_timestamp())
              ) - clock_timestamp())))::integer) AS "retryAfterSeconds",
              "deniedCount" FROM "AuthenticationRateLimit"
            WHERE action = ${action} AND subject = ${subject}
              AND "windowStartedAt" + (${policy.windowMs} * interval '1 millisecond') > clock_timestamp()
          `);
      const row = rows[0];
      const decision = row
        ? { allowed: row.allowed, retryAfterSeconds: Math.min(3600, row.retryAfterSeconds), repeatedExcess: row.deniedCount >= 3 }
        : { allowed: true, retryAfterSeconds: 0, repeatedExcess: false };
      metrics.increment('auth_rate_limit_decisions_total', { operation: action, outcome: decision.allowed ? 'allowed' : 'denied' });
      if (!decision.allowed && decision.repeatedExcess) {
        alerts.emit('rate_limit_repeated_excess', { operation: action, outcome: 'denied' });
      }
      return decision;
    },
    async cleanup() {
      return client.$executeRaw`
        DELETE FROM "AuthenticationRateLimit"
        WHERE "updatedAt" < clock_timestamp() - interval '24 hours'
      `;
    }
  };
}
