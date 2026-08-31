import { hostname } from 'node:os';
import { pathToFileURL } from 'node:url';
import { randomUUID } from 'node:crypto';

import { Prisma, PrismaClient } from '@prisma/client';

import type { AuthAlertSink } from '../auth-observability.js';

export const RECOVERY_REVOCATION_SLO_MS = 5_000;

export type RecoveryWorkerConfig = {
  batchSize: number;
  concurrency: number;
  leaseMs: number;
  pollMs: number;
  maxAttempts: number;
  baseBackoffMs: number;
  maxBackoffMs: number;
  adapterTimeoutMs: number;
};

export type ClaimedRecoveryRevocation = {
  id: string;
  accountId: string | null;
  attempts: number;
  leaseOwner: string;
  leaseToken: string;
};

export type RecoveryRevocationAdapter = {
  readonly supportsIdempotency: true;
  revoke(input: {
    transaction: Prisma.TransactionClient;
    accountId: string | null;
    idempotencyKey: string;
    signal: AbortSignal;
  }): Promise<{ acknowledged: boolean; revokedSessions: number }>;
};

type RecoveryClient = Pick<PrismaClient, '$transaction' | '$executeRaw'>;

function integerSetting(value: string | undefined, fallback: number, min: number, max: number, name: string) {
  const parsed = value === undefined ? fallback : Number(value);
  if (!Number.isSafeInteger(parsed) || parsed < min || parsed > max) {
    throw new Error(`${name} must be an integer between ${min} and ${max}`);
  }
  return parsed;
}

export function recoveryWorkerConfig(environment: NodeJS.ProcessEnv = process.env): RecoveryWorkerConfig {
  const baseBackoffMs = integerSetting(environment.RECOVERY_BASE_BACKOFF_MS, 100, 10, 5_000, 'RECOVERY_BASE_BACKOFF_MS');
  const maxBackoffMs = integerSetting(environment.RECOVERY_MAX_BACKOFF_MS, 1_000, 10, 5_000, 'RECOVERY_MAX_BACKOFF_MS');
  const batchSize = integerSetting(environment.RECOVERY_BATCH_SIZE, 20, 1, 100, 'RECOVERY_BATCH_SIZE');
  const concurrency = integerSetting(environment.RECOVERY_CONCURRENCY, 5, 1, 20, 'RECOVERY_CONCURRENCY');
  const leaseMs = integerSetting(environment.RECOVERY_LEASE_MS, 2_000, 250, 30_000, 'RECOVERY_LEASE_MS');
  const adapterTimeoutMs = integerSetting(environment.RECOVERY_ADAPTER_TIMEOUT_MS, 1_000, 50, 4_000, 'RECOVERY_ADAPTER_TIMEOUT_MS');
  if (maxBackoffMs < baseBackoffMs) throw new Error('RECOVERY_MAX_BACKOFF_MS must not be less than RECOVERY_BASE_BACKOFF_MS');
  if (concurrency > batchSize) throw new Error('RECOVERY_CONCURRENCY must not exceed RECOVERY_BATCH_SIZE');
  if (leaseMs < adapterTimeoutMs + 250) throw new Error('RECOVERY_LEASE_MS must exceed RECOVERY_ADAPTER_TIMEOUT_MS by at least 250ms');
  return {
    batchSize,
    concurrency,
    leaseMs,
    pollMs: integerSetting(environment.RECOVERY_POLL_MS, 100, 25, 5_000, 'RECOVERY_POLL_MS'),
    maxAttempts: integerSetting(environment.RECOVERY_MAX_ATTEMPTS, 5, 1, 20, 'RECOVERY_MAX_ATTEMPTS'),
    adapterTimeoutMs,
    baseBackoffMs,
    maxBackoffMs
  };
}

export function recoveryRetryDelayMs(
  attempt: number,
  config: Pick<RecoveryWorkerConfig, 'baseBackoffMs' | 'maxBackoffMs'>,
  random = Math.random
) {
  const exponential = config.baseBackoffMs * 2 ** Math.max(0, attempt - 1);
  return Math.min(config.maxBackoffMs, Math.round(exponential * (0.8 + random() * 0.4)));
}

export function createPostgresRecoveryRevocationAdapter(): RecoveryRevocationAdapter {
  return {
    supportsIdempotency: true,
    async revoke({ transaction, accountId, signal }) {
      if (signal.aborted) throw new Error('adapter_aborted');
      if (!accountId) return { acknowledged: true, revokedSessions: 0 };
      await transaction.$queryRaw`SELECT id FROM "HumanAccount" WHERE id = ${accountId}::uuid FOR UPDATE`;
      await transaction.$executeRaw`
        UPDATE "HumanAccount"
        SET "sessionVersion" = "sessionVersion" + 1, "updatedAt" = clock_timestamp()
        WHERE id = ${accountId}::uuid
      `;
      const revokedSessions = await transaction.$executeRaw`
        UPDATE "BrowserSession"
        SET "revokedAt" = clock_timestamp(), "revokeReason" = 'provider_recovery_event'
        WHERE "accountId" = ${accountId}::uuid AND "revokedAt" IS NULL
      `;
      const remaining = await transaction.$queryRaw<Array<{ active: bigint }>>`
        SELECT count(*) AS active FROM "BrowserSession"
        WHERE "accountId" = ${accountId}::uuid AND "revokedAt" IS NULL
      `;
      return { acknowledged: remaining[0]?.active === 0n, revokedSessions };
    }
  };
}

export async function claimRecoveryRevocations(
  client: Pick<PrismaClient, '$transaction'>,
  input: { workerId: string; batchSize: number; leaseMs: number; maxAttempts: number }
) {
  return client.$transaction(async (transaction) => {
    await transaction.$executeRaw`
      WITH expired AS (
        SELECT id FROM "RecoveryWebhookEvent"
        WHERE status IN ('pending', 'retry', 'processing') AND "expiresAt" <= clock_timestamp()
        ORDER BY "expiresAt", id FOR UPDATE SKIP LOCKED LIMIT ${input.batchSize}
      )
      UPDATE "RecoveryWebhookEvent" event
      SET status = 'expired', "failedAt" = clock_timestamp(), "lastError" = 'event_expired',
          "leaseOwner" = NULL, "leaseToken" = NULL, "leaseExpiresAt" = NULL
      FROM expired WHERE event.id = expired.id
    `;
    await transaction.$executeRaw`
      WITH exhausted AS (
        SELECT id FROM "RecoveryWebhookEvent"
        WHERE status = 'processing' AND "leaseExpiresAt" <= clock_timestamp()
          AND attempts >= ${input.maxAttempts} AND "expiresAt" > clock_timestamp()
        ORDER BY "leaseExpiresAt", id FOR UPDATE SKIP LOCKED LIMIT ${input.batchSize}
      )
      UPDATE "RecoveryWebhookEvent" event
      SET status = 'failed', "failedAt" = clock_timestamp(), "lastError" = 'attempts_exhausted',
          "leaseOwner" = NULL, "leaseToken" = NULL, "leaseExpiresAt" = NULL
      FROM exhausted WHERE event.id = exhausted.id
    `;
    return transaction.$queryRaw<ClaimedRecoveryRevocation[]>(Prisma.sql`
      WITH candidates AS (
        SELECT id FROM "RecoveryWebhookEvent"
        WHERE attempts < ${input.maxAttempts} AND "expiresAt" > clock_timestamp()
          AND (
            (status IN ('pending', 'retry') AND "nextAttemptAt" <= clock_timestamp())
            OR (status = 'processing' AND "leaseExpiresAt" <= clock_timestamp())
          )
        ORDER BY "nextAttemptAt", "createdAt", id
        FOR UPDATE SKIP LOCKED
        LIMIT ${input.batchSize}
      )
      UPDATE "RecoveryWebhookEvent" event
      SET status = 'processing', attempts = attempts + 1,
          "leaseOwner" = ${input.workerId}, "leaseToken" = gen_random_uuid(),
          "leaseExpiresAt" = clock_timestamp() + (${input.leaseMs} * interval '1 millisecond'),
          "lastError" = NULL
      FROM candidates WHERE event.id = candidates.id
      RETURNING event.id, event."accountId", event.attempts, event."leaseOwner", event."leaseToken"
    `);
  });
}

async function failClaim(
  client: Pick<PrismaClient, '$executeRaw'>,
  claim: ClaimedRecoveryRevocation,
  input: { code: 'adapter_timeout' | 'adapter_nack' | 'adapter_failure'; maxAttempts: number; retryDelayMs: number }
) {
  const terminal = claim.attempts >= input.maxAttempts;
  await client.$executeRaw`
    UPDATE "RecoveryWebhookEvent"
    SET status = ${terminal ? 'failed' : 'retry'}::"RecoveryRevocationStatus",
        "failedAt" = CASE WHEN ${terminal} THEN clock_timestamp() ELSE NULL END,
        "lastError" = ${terminal ? 'attempts_exhausted' : input.code},
        "nextAttemptAt" = clock_timestamp() + (${input.retryDelayMs} * interval '1 millisecond'),
        "leaseOwner" = NULL, "leaseToken" = NULL, "leaseExpiresAt" = NULL
    WHERE id = ${claim.id}::uuid AND status = 'processing'
      AND "leaseOwner" = ${claim.leaseOwner} AND "leaseToken" = ${claim.leaseToken}::uuid
  `;
  return terminal;
}

async function processRecoveryClaimStarted(
  client: RecoveryClient,
  adapter: RecoveryRevocationAdapter,
  claim: ClaimedRecoveryRevocation,
  config: RecoveryWorkerConfig,
  random = Math.random,
  onTransactionStart: () => void = () => {}
) {
  const controller = new AbortController();
  let timedOut = false;
  let timer: NodeJS.Timeout | undefined;
  try {
    const result = await client.$transaction(async (transaction) => {
      onTransactionStart();
      timer = setTimeout(() => { timedOut = true; controller.abort(); }, config.adapterTimeoutMs);
      const current = await transaction.$queryRaw<Array<{ id: string }>>(Prisma.sql`
        SELECT id FROM "RecoveryWebhookEvent"
        WHERE id = ${claim.id}::uuid AND status = 'processing'
          AND "leaseOwner" = ${claim.leaseOwner} AND "leaseToken" = ${claim.leaseToken}::uuid
          AND "leaseExpiresAt" > clock_timestamp() AND "expiresAt" > clock_timestamp()
        FOR UPDATE
      `);
      if (!current[0]) return null;
      if (controller.signal.aborted) throw new Error('adapter_timeout');
      const outcome = await Promise.race([
        adapter.revoke({ transaction, accountId: claim.accountId, idempotencyKey: claim.id, signal: controller.signal }),
        new Promise<never>((_, reject) => controller.signal.addEventListener('abort', () => reject(new Error('adapter_timeout')), { once: true }))
      ]);
      if (!outcome.acknowledged) throw new Error('adapter_nack');
      await transaction.$executeRaw`
        UPDATE "RecoveryWebhookEvent"
        SET status = 'acknowledged', "acknowledgedAt" = clock_timestamp(), "lastError" = NULL,
            "leaseOwner" = NULL, "leaseToken" = NULL, "leaseExpiresAt" = NULL
        WHERE id = ${claim.id}::uuid AND status = 'processing'
          AND "leaseOwner" = ${claim.leaseOwner} AND "leaseToken" = ${claim.leaseToken}::uuid
      `;
      return outcome;
    }, { timeout: Math.max(5_000, config.adapterTimeoutMs + 1_000) });
    return result ? { outcome: 'acknowledged' as const, revokedSessions: result.revokedSessions } : { outcome: 'lost_lease' as const };
  } catch (error) {
    const code = timedOut || (error instanceof Error && error.message === 'adapter_timeout')
      ? 'adapter_timeout'
      : error instanceof Error && error.message === 'adapter_nack' ? 'adapter_nack' : 'adapter_failure';
    const terminal = await failClaim(client, claim, {
      code, maxAttempts: config.maxAttempts,
      retryDelayMs: recoveryRetryDelayMs(claim.attempts, config, random)
    });
    return { outcome: terminal ? 'failed' as const : 'retry' as const, code };
  } finally {
    if (timer) clearTimeout(timer);
  }
}

export function processRecoveryClaim(
  client: RecoveryClient,
  adapter: RecoveryRevocationAdapter,
  claim: ClaimedRecoveryRevocation,
  config: RecoveryWorkerConfig,
  random = Math.random
) {
  return processRecoveryClaimStarted(client, adapter, claim, config, random);
}

export async function alertOverdueRecoveryRevocations(
  client: Pick<PrismaClient, '$transaction'>,
  alerts: AuthAlertSink
) {
  return client.$transaction(async (transaction) => {
    const locks = await transaction.$queryRaw<Array<{ acquired: boolean }>>`
      SELECT pg_try_advisory_xact_lock(hashtextextended('recovery_revocation_slo_alert', 0)) AS acquired
    `;
    if (locks[0]?.acquired !== true) return 0;
    const rows = await transaction.$queryRaw<Array<{ id: string; status: string }>>(Prisma.sql`
      SELECT id, status::text FROM "RecoveryWebhookEvent"
      WHERE status <> 'acknowledged' AND "sloAlertedAt" IS NULL
        AND "createdAt" <= clock_timestamp() - (${RECOVERY_REVOCATION_SLO_MS} * interval '1 millisecond')
      ORDER BY "createdAt", id LIMIT 100
    `);
    if (rows.length === 0) return 0;
    try {
      await alerts.emit('recovery_revocation_slo_breach', {
        severity: 'critical', thresholdSeconds: 5, affectedEvents: rows.length,
        terminalEvents: rows.filter(({ status }) => status === 'failed' || status === 'expired').length
      });
    } catch {
      return 0;
    }
    await transaction.$executeRaw(Prisma.sql`
      UPDATE "RecoveryWebhookEvent" SET "sloAlertedAt" = clock_timestamp()
      WHERE id IN (${Prisma.join(rows.map(({ id }) => Prisma.sql`${id}::uuid`))})
        AND "sloAlertedAt" IS NULL
    `);
    return rows.length;
  }, { maxWait: 5_000, timeout: 30_000 });
}

export async function runRecoveryBatch(input: {
  client: RecoveryClient & Pick<PrismaClient, '$queryRaw'>;
  adapter: RecoveryRevocationAdapter;
  alerts: AuthAlertSink;
  workerId: string;
  config: RecoveryWorkerConfig;
  random?: () => number;
}) {
  await alertOverdueRecoveryRevocations(input.client, input.alerts);
  const outcomes: Awaited<ReturnType<typeof processRecoveryClaim>>[] = [];
  const active = new Set<Promise<void>>();
  let claimed = 0;
  while (claimed < input.config.batchSize) {
    if (active.size >= input.config.concurrency) await Promise.race(active);
    const claims = await claimRecoveryRevocations(input.client, {
      workerId: input.workerId, batchSize: 1,
      leaseMs: input.config.leaseMs, maxAttempts: input.config.maxAttempts
    });
    if (claims.length === 0) break;
    claimed += 1;
    let transactionStarted!: () => void;
    const started = new Promise<void>((resolve) => { transactionStarted = resolve; });
    const processing = processRecoveryClaimStarted(
      input.client, input.adapter, claims[0], input.config, input.random, transactionStarted
    ).then((outcome) => { outcomes.push(outcome); }).finally(() => { active.delete(processing); });
    active.add(processing);
    await Promise.race([started, processing]);
  }
  await Promise.all(active);
  await alertOverdueRecoveryRevocations(input.client, input.alerts);
  return outcomes;
}

async function main() {
  const { authAlertConfigFromEnvironment } = await import('../env.js');
  const {
    createAuthAlertStdoutAdapter, createAuthAlertWebhookAdapter, createRoutedAuthAlertSink, DEFAULT_AUTH_ALERT_ROUTES
  } = await import('../auth-observability.js');
  const config = recoveryWorkerConfig();
  const client = new PrismaClient();
  const alertConfig = authAlertConfigFromEnvironment(process.env);
  const delivery = alertConfig.adapter === 'stdout'
    ? createAuthAlertStdoutAdapter()
    : createAuthAlertWebhookAdapter(alertConfig.url);
  const routing = createRoutedAuthAlertSink(DEFAULT_AUTH_ALERT_ROUTES, delivery, { timeoutMs: alertConfig.timeoutMs });
  const alerts: AuthAlertSink = { emit(type) { return routing.deliver(type); } };
  const workerId = `${hostname()}:${process.pid}:${randomUUID()}`;
  const adapter = createPostgresRecoveryRevocationAdapter();
  let stopping = false;
  process.once('SIGINT', () => { stopping = true; });
  process.once('SIGTERM', () => { stopping = true; });
  try {
    while (!stopping) {
      await runRecoveryBatch({ client, adapter, alerts, workerId, config });
      await new Promise((resolve) => setTimeout(resolve, config.pollMs));
    }
  } finally {
    await client.$disconnect();
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch(() => {
    console.error('Recovery revocation worker failed');
    process.exitCode = 1;
  });
}
