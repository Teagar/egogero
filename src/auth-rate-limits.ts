import { createHash, randomUUID } from 'node:crypto';

import { Prisma, type PrismaClient } from '@prisma/client';

import { noopAuthAlerts, noopAuthMetrics, safeAuthAlerts, safeAuthMetrics } from './auth-observability.js';
import type { AuthAlertSink, AuthMetrics } from './auth-observability.js';

export const AUTH_RATE_LIMIT_POLICIES = {
  login_ip: { limit: 5, windowMs: 10 * 60_000, operation: 'Login initiation', dimension: 'IP prefix', behavior: 'Generic 429; bounded Retry-After' },
  callback_failure_ip: { limit: 10, windowMs: 15 * 60_000, operation: 'Failed OIDC callback', dimension: 'IP prefix', behavior: 'Consume state before provider exchange; reserve failure budget' },
  session_creation_account: { limit: 10, windowMs: 15 * 60_000, backoffMs: 15 * 60_000, operation: 'Session creation or rotation', dimension: 'Account', behavior: 'Deny; progressive backoff; repeated-excess alert' },
  recovery_ip: { limit: 3, windowMs: 30 * 60_000, operation: 'Recovery initiation', dimension: 'IP prefix', behavior: 'Generic 429; no account signal' },
  reauthentication_account: { limit: 5, windowMs: 10 * 60_000, operation: 'Reauthentication initiation', dimension: 'Account', behavior: 'Generic 429 after authenticated validation' },
  invitation_acceptance_ip: { limit: 10, windowMs: 60 * 60_000, backoffMs: 60_000, operation: 'Administrative invitation acceptance', dimension: 'IP prefix', behavior: 'Generic denial; exponential backoff; repeated-excess alert' },
  invitation_acceptance_digest: { limit: 5, windowMs: 60 * 60_000, backoffMs: 60_000, operation: 'Administrative invitation acceptance', dimension: 'Invitation digest', behavior: 'Generic denial; exponential backoff; repeated-excess alert' },
  human_validation_account: { limit: 20, windowMs: 60_000, operation: 'Human gate validation', dimension: 'Account', behavior: 'Generic 429 after authenticated validation' },
  authentication_failure_ip: { limit: 60, windowMs: 60_000, operation: 'CSRF or authentication failure', dimension: 'IP prefix', behavior: 'Generic 429 on sustained abuse' }
} as const;

export type AuthRateLimitAction = keyof typeof AUTH_RATE_LIMIT_POLICIES;
export type AuthReservationRateLimitAction = Extract<AuthRateLimitAction,
  'callback_failure_ip' | 'authentication_failure_ip' | 'invitation_acceptance_ip' | 'invitation_acceptance_digest'>;
export type AuthRateLimitDecision = { allowed: boolean; retryAfterSeconds: number; repeatedExcess: boolean };
export type AuthRateLimitReservation =
  | { allowed: true; retryAfterSeconds: 0; repeatedExcess: false; reservationId: string }
  | { allowed: false; retryAfterSeconds: number; repeatedExcess: boolean; reservationId?: never };

function policyWindow(windowMs: number) {
  if (windowMs % 3_600_000 === 0) {
    const hours = windowMs / 3_600_000;
    return `${hours} ${hours === 1 ? 'hour' : 'hours'}`;
  }
  if (windowMs % 60_000 === 0) {
    const minutes = windowMs / 60_000;
    return `${minutes} ${minutes === 1 ? 'minute' : 'minutes'}`;
  }
  const seconds = windowMs / 1000;
  return `${seconds} ${seconds === 1 ? 'second' : 'seconds'}`;
}

export const AUTH_RATE_LIMIT_POLICY_TABLE = [
  '| Operation | Dimension | Limit | External behavior |',
  '| --- | --- | --- | --- |',
  ...Object.values(AUTH_RATE_LIMIT_POLICIES).map((policy) =>
    `| ${policy.operation} | ${policy.dimension} | ${policy.limit} per ${policyWindow(policy.windowMs)} | ${policy.behavior} |`
  )
].join('\n');

export interface AuthRateLimiter {
  check(
    action: AuthRateLimitAction,
    subject: string,
    consume?: boolean,
    transaction?: Prisma.TransactionClient
  ): Promise<AuthRateLimitDecision>;
  reserve(action: AuthReservationRateLimitAction, subject: string): Promise<AuthRateLimitReservation>;
  finalize(reservationId: string, outcome: 'consume' | 'release'): Promise<void>;
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
  function observeDecision(action: AuthRateLimitAction, decision: AuthRateLimitDecision) {
    metrics.increment('auth_rate_limit_decisions_total', { operation: action, outcome: decision.allowed ? 'allowed' : 'denied' });
    if (!decision.allowed && decision.repeatedExcess) {
      alerts.emit('rate_limit_repeated_excess', { operation: action, outcome: 'denied' });
    }
  }
  return {
    async check(action, rawSubject, consume = true, transaction) {
      const policy = AUTH_RATE_LIMIT_POLICIES[action];
      const subject = boundedSubject(rawSubject);
      const database = transaction ?? client;
      const rows = consume
        ? await database.$queryRaw<Array<{ allowed: boolean; retryAfterSeconds: number; deniedCount: number }>>(Prisma.sql`
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
        : await database.$queryRaw<Array<{ allowed: boolean; retryAfterSeconds: number; deniedCount: number }>>(Prisma.sql`
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
      observeDecision(action, decision);
      return decision;
    },
    async reserve(action, rawSubject) {
      const policy = AUTH_RATE_LIMIT_POLICIES[action];
      const subject = boundedSubject(rawSubject);
      const reservationId = randomUUID();
      const result = await client.$transaction(async (transaction): Promise<AuthRateLimitReservation> => {
        await transaction.$executeRaw`
          INSERT INTO "AuthenticationRateLimit" (action, subject, "windowStartedAt", count, "deniedCount", "reservedCount", "updatedAt")
          VALUES (${action}, ${subject}, clock_timestamp(), 0, 0, 0, clock_timestamp())
          ON CONFLICT (action, subject) DO NOTHING
        `;
        const rows = await transaction.$queryRaw<Array<{
          windowStartedAt: Date;
          count: number;
          deniedCount: number;
          reservedCount: number;
          blockedUntil: Date | null;
          databaseNow: Date;
        }>>(Prisma.sql`
          SELECT "windowStartedAt", count, "deniedCount", "reservedCount", "blockedUntil",
                 clock_timestamp() AS "databaseNow"
          FROM "AuthenticationRateLimit"
          WHERE action = ${action} AND subject = ${subject}
          FOR UPDATE
        `);
        const row = rows[0]!;
        const windowEndsAt = new Date(row.windowStartedAt.getTime() + policy.windowMs);
        if (windowEndsAt <= row.databaseNow) {
          await transaction.$executeRaw`
            DELETE FROM "AuthenticationRateLimitReservation"
            WHERE action = ${action} AND subject = ${subject}
          `;
          row.windowStartedAt = row.databaseNow;
          row.count = 0;
          row.deniedCount = 0;
          row.reservedCount = 0;
          row.blockedUntil = null;
          await transaction.$executeRaw`
            UPDATE "AuthenticationRateLimit"
            SET "windowStartedAt" = ${row.databaseNow}, count = 0, "deniedCount" = 0,
                "reservedCount" = 0, "blockedUntil" = NULL, "updatedAt" = clock_timestamp()
            WHERE action = ${action} AND subject = ${subject}
          `;
        }
        const blocked = row.blockedUntil !== null && row.blockedUntil > row.databaseNow;
        if (blocked || row.count + row.reservedCount >= policy.limit) {
          const denied = await transaction.$queryRaw<Array<{ deniedCount: number; blockedUntil: Date | null }>>(Prisma.sql`
            UPDATE "AuthenticationRateLimit"
            SET "deniedCount" = "deniedCount" + 1,
                "blockedUntil" = CASE WHEN ${'backoffMs' in policy ? policy.backoffMs : 0} > 0
                  THEN LEAST(
                    "windowStartedAt" + (${policy.windowMs} * interval '1 millisecond'),
                    clock_timestamp() + (POWER(2, LEAST(4, "deniedCount"))
                      * ${'backoffMs' in policy ? policy.backoffMs : 0} * interval '1 millisecond')
                  ) ELSE "blockedUntil" END,
                "updatedAt" = clock_timestamp()
            WHERE action = ${action} AND subject = ${subject}
            RETURNING "deniedCount", "blockedUntil"
          `);
          const retryAt = Math.max(
            row.windowStartedAt.getTime() + policy.windowMs,
            denied[0]!.blockedUntil?.getTime() ?? 0
          );
          return {
            allowed: false,
            retryAfterSeconds: Math.min(3600, Math.max(1, Math.ceil((retryAt - row.databaseNow.getTime()) / 1000))),
            repeatedExcess: denied[0]!.deniedCount >= 3
          };
        }
        const expiresAt = new Date(row.windowStartedAt.getTime() + policy.windowMs);
        await transaction.$executeRaw`
          INSERT INTO "AuthenticationRateLimitReservation" (id, action, subject, "expiresAt")
          VALUES (${reservationId}::uuid, ${action}, ${subject}, ${expiresAt})
        `;
        await transaction.$executeRaw`
          UPDATE "AuthenticationRateLimit"
          SET "reservedCount" = "reservedCount" + 1, "updatedAt" = clock_timestamp()
          WHERE action = ${action} AND subject = ${subject}
        `;
        return { allowed: true, retryAfterSeconds: 0, repeatedExcess: false, reservationId };
      });
      observeDecision(action, result);
      return result;
    },
    async finalize(reservationId, outcome) {
      await client.$transaction(async (transaction) => {
        const reservations = await transaction.$queryRaw<Array<{
          action: string;
          subject: string;
          expiresAt: Date;
        }>>(Prisma.sql`
          SELECT action, subject, "expiresAt"
          FROM "AuthenticationRateLimitReservation"
          WHERE id = ${reservationId}::uuid
        `);
        const reservation = reservations[0];
        if (!reservation) return;
        const buckets = await transaction.$queryRaw<Array<{ windowStartedAt: Date; databaseNow: Date }>>(Prisma.sql`
          SELECT "windowStartedAt", clock_timestamp() AS "databaseNow"
          FROM "AuthenticationRateLimit"
          WHERE action = ${reservation.action} AND subject = ${reservation.subject}
          FOR UPDATE
        `);
        const bucket = buckets[0];
        if (!bucket) return;
        const deleted = await transaction.$queryRaw<Array<{ id: string }>>(Prisma.sql`
          DELETE FROM "AuthenticationRateLimitReservation"
          WHERE id = ${reservationId}::uuid
          RETURNING id
        `);
        if (!deleted[0]) return;
        const policy = AUTH_RATE_LIMIT_POLICIES[reservation.action as AuthReservationRateLimitAction];
        const consumeInCurrentWindow = policy !== undefined && outcome === 'consume'
          && reservation.expiresAt > bucket.databaseNow
          && bucket.windowStartedAt.getTime() + policy.windowMs > bucket.databaseNow.getTime();
        await transaction.$executeRaw`
          UPDATE "AuthenticationRateLimit"
          SET "reservedCount" = GREATEST(0, "reservedCount" - 1),
              count = count + ${consumeInCurrentWindow ? 1 : 0},
              "updatedAt" = clock_timestamp()
          WHERE action = ${reservation.action} AND subject = ${reservation.subject}
        `;
      });
    },
    async cleanup() {
      return client.$transaction(async (transaction) => {
        await transaction.$queryRaw`
          SELECT bucket.action, bucket.subject
          FROM "AuthenticationRateLimit" bucket
          WHERE EXISTS (
            SELECT 1 FROM "AuthenticationRateLimitReservation" reservation
            WHERE reservation.action = bucket.action AND reservation.subject = bucket.subject
              AND reservation."expiresAt" <= clock_timestamp()
          )
          FOR UPDATE
        `;
        await transaction.$executeRaw`
          WITH expired AS (
            DELETE FROM "AuthenticationRateLimitReservation"
            WHERE "expiresAt" <= clock_timestamp()
            RETURNING action, subject
          ), totals AS (
            SELECT action, subject, count(*)::integer AS count FROM expired GROUP BY action, subject
          )
          UPDATE "AuthenticationRateLimit" bucket
          SET "reservedCount" = GREATEST(0, bucket."reservedCount" - totals.count),
              "updatedAt" = clock_timestamp()
          FROM totals WHERE bucket.action = totals.action AND bucket.subject = totals.subject
        `;
        return transaction.$executeRaw`
          DELETE FROM "AuthenticationRateLimit"
          WHERE "updatedAt" < clock_timestamp() - interval '24 hours'
        `;
      });
    }
  };
}
