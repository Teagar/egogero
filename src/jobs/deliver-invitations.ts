import { createDecipheriv, createHash, randomUUID } from 'node:crypto';
import { hostname } from 'node:os';
import { pathToFileURL } from 'node:url';

import { Prisma, PrismaClient, type DeliveryChannel } from '@prisma/client';

const KEY_VERSION = 1;
const ERROR_CODES = {
  transient: 'provider_transient',
  permanent: 'provider_permanent',
  unavailable: 'provider_unavailable',
  timeout: 'provider_timeout',
  invalid: 'payload_invalid',
  decryption: 'payload_decryption_failed',
  exhausted: 'attempts_exhausted'
} as const;

type ErrorCode = (typeof ERROR_CODES)[keyof typeof ERROR_CODES];
type DeliveryClient = Pick<PrismaClient, '$queryRaw' | '$executeRaw' | '$transaction'>;

export type DeliveryPayload = {
  intentId: string;
  invitationId: string;
  to: string;
  subject?: string;
  body: string;
};

export interface DeliveryProvider {
  readonly supportsIdempotency: true;
  send(input: {
    channel: DeliveryChannel;
    idempotencyKey: string;
    payload: DeliveryPayload;
    signal: AbortSignal;
  }): Promise<void>;
}

export class PermanentDeliveryError extends Error {}
export class DeliveryProviderUnavailableError extends Error {}
export class DeliveryProviderTimeoutError extends Error {}
class DeliveryAbortedError extends Error {}

export type DeliveryWorkerConfig = {
  batchSize: number;
  concurrency: number;
  leaseMs: number;
  pollMs: number;
  maxAttempts: number;
  baseBackoffMs: number;
  maxBackoffMs: number;
  providerTimeoutMs: number;
};

export type ClaimedDelivery = {
  id: string;
  conviteId: string;
  channel: DeliveryChannel;
  payloadCiphertext: Buffer;
  payloadIv: Buffer;
  payloadAuthTag: Buffer;
  keyVersion: number;
  attempts: number;
  leaseOwner: string;
  leaseToken: string;
};

function integerSetting(value: string | undefined, fallback: number, min: number, max: number, name: string) {
  const parsed = value === undefined ? fallback : Number(value);
  if (!Number.isSafeInteger(parsed) || parsed < min || parsed > max) {
    throw new Error(`${name} must be an integer between ${min} and ${max}`);
  }
  return parsed;
}

export function deliveryWorkerConfig(environment: NodeJS.ProcessEnv = process.env): DeliveryWorkerConfig {
  const batchSize = integerSetting(environment.DELIVERY_BATCH_SIZE, 50, 1, 100, 'DELIVERY_BATCH_SIZE');
  const concurrency = integerSetting(environment.DELIVERY_CONCURRENCY, 5, 1, 100, 'DELIVERY_CONCURRENCY');
  const baseBackoffMs = integerSetting(environment.DELIVERY_BASE_BACKOFF_MS, 1_000, 100, 3_600_000, 'DELIVERY_BASE_BACKOFF_MS');
  const maxBackoffMs = integerSetting(environment.DELIVERY_MAX_BACKOFF_MS, 300_000, 100, 86_400_000, 'DELIVERY_MAX_BACKOFF_MS');
  if (concurrency > batchSize) throw new Error('DELIVERY_CONCURRENCY must not exceed DELIVERY_BATCH_SIZE');
  if (maxBackoffMs < baseBackoffMs) throw new Error('DELIVERY_MAX_BACKOFF_MS must not be less than DELIVERY_BASE_BACKOFF_MS');
  return {
    batchSize,
    concurrency,
    leaseMs: integerSetting(environment.DELIVERY_LEASE_MS, 60_000, 1_000, 3_600_000, 'DELIVERY_LEASE_MS'),
    pollMs: integerSetting(environment.DELIVERY_POLL_MS, 1_000, 50, 60_000, 'DELIVERY_POLL_MS'),
    maxAttempts: integerSetting(environment.DELIVERY_MAX_ATTEMPTS, 8, 1, 100, 'DELIVERY_MAX_ATTEMPTS'),
    providerTimeoutMs: integerSetting(environment.DELIVERY_PROVIDER_TIMEOUT_MS, 30_000, 1_000, 300_000, 'DELIVERY_PROVIDER_TIMEOUT_MS'),
    baseBackoffMs,
    maxBackoffMs
  };
}

function safeWorkerId(value: string) {
  if (value.length > 128 || !/^[A-Za-z0-9._:-]+$/.test(value)) {
    throw new Error('DELIVERY_WORKER_ID must contain only letters, digits, dot, underscore, colon, or hyphen');
  }
  return value;
}

export async function verifyDeliverySecret(client: Pick<PrismaClient, '$queryRaw'>, secret: string) {
  if (Buffer.byteLength(secret) < 32) throw new Error('IDEMPOTENCY_CACHE_SECRET must be at least 32 bytes');
  const fingerprint = createHash('sha256').update(`idempotency-cache:${secret}`).digest('hex');
  const configured = await client.$queryRaw<Array<{ fingerprint: string }>>`
    SELECT fingerprint FROM "SecurityKey" WHERE name = 'idempotency-cache-v1'
  `;
  if (configured[0]?.fingerprint.trim() !== fingerprint) {
    throw new Error('Delivery encryption key does not match the configured key');
  }
}

export async function verifyDeliveryPolicy(
  client: Pick<PrismaClient, '$queryRaw' | '$executeRaw'>,
  maxAttempts: number
) {
  const fingerprint = createHash('sha256').update(`delivery-worker-policy-v1:max-attempts:${maxAttempts}`).digest('hex');
  await client.$executeRaw`
    INSERT INTO "SecurityKey" (name, fingerprint)
    VALUES ('delivery-worker-policy-v1', ${fingerprint})
    ON CONFLICT (name) DO NOTHING
  `;
  const configured = await client.$queryRaw<Array<{ fingerprint: string }>>`
    SELECT fingerprint FROM "SecurityKey" WHERE name = 'delivery-worker-policy-v1'
  `;
  if (configured[0]?.fingerprint.trim() !== fingerprint) {
    throw new Error('Delivery worker attempt policy does not match the configured policy');
  }
}

export async function claimDeliveries(
  client: Pick<PrismaClient, '$transaction'>,
  input: { workerId: string; batchSize: number; leaseMs: number; maxAttempts: number }
) {
  return client.$transaction(async (transaction) => {
    await transaction.$executeRaw`
      UPDATE "DeliveryIntent"
      SET status = 'dead_letter', "lastError" = 'attempts_exhausted',
          "leaseOwner" = NULL, "leaseToken" = NULL, "leaseExpiresAt" = NULL
      WHERE status = 'processing' AND "leaseExpiresAt" <= clock_timestamp()
        AND attempts >= ${input.maxAttempts}
    `;
    return transaction.$queryRaw<ClaimedDelivery[]>(Prisma.sql`
      WITH candidates AS (
        SELECT id
        FROM "DeliveryIntent"
        WHERE "deliveredAt" IS NULL
          AND attempts < ${input.maxAttempts}
          AND (
            (status IN ('pending', 'retry') AND "nextAttemptAt" <= clock_timestamp())
            OR (status = 'processing' AND "leaseExpiresAt" <= clock_timestamp())
          )
        ORDER BY "nextAttemptAt", "createdAt", id
        FOR UPDATE SKIP LOCKED
        LIMIT ${input.batchSize}
      )
      UPDATE "DeliveryIntent" AS intent
      SET status = 'processing',
          "leaseOwner" = ${input.workerId},
          "leaseToken" = gen_random_uuid(),
          "leaseExpiresAt" = clock_timestamp() + (${input.leaseMs} * interval '1 millisecond'),
          "lastError" = NULL
      FROM candidates
      WHERE intent.id = candidates.id
      RETURNING intent.id, intent."conviteId", intent.channel, intent."payloadCiphertext",
                intent."payloadIv", intent."payloadAuthTag", intent."keyVersion", intent.attempts,
                intent."leaseOwner", intent."leaseToken"
    `);
  });
}

export async function renewDeliveryLease(
  client: Pick<PrismaClient, '$executeRaw'>,
  claim: ClaimedDelivery,
  leaseMs: number
) {
  const updated = await client.$executeRaw`
    UPDATE "DeliveryIntent"
    SET "leaseExpiresAt" = clock_timestamp() + (${leaseMs} * interval '1 millisecond')
    WHERE id = ${claim.id}::uuid AND status = 'processing'
      AND "leaseOwner" = ${claim.leaseOwner} AND "leaseToken" = ${claim.leaseToken}::uuid
  `;
  return updated === 1;
}

export async function completeDelivery(client: Pick<PrismaClient, '$executeRaw'>, claim: ClaimedDelivery) {
  const updated = await client.$executeRaw`
    UPDATE "DeliveryIntent"
    SET status = 'delivered', attempts = attempts + 1, "deliveredAt" = clock_timestamp(),
        "leaseOwner" = NULL, "leaseToken" = NULL, "leaseExpiresAt" = NULL, "lastError" = NULL
    WHERE id = ${claim.id}::uuid AND status = 'processing'
      AND "leaseOwner" = ${claim.leaseOwner} AND "leaseToken" = ${claim.leaseToken}::uuid
  `;
  return updated === 1;
}

export function retryDelayMs(attempt: number, config: Pick<DeliveryWorkerConfig, 'baseBackoffMs' | 'maxBackoffMs'>, random = Math.random) {
  const exponential = config.baseBackoffMs * 2 ** Math.max(0, attempt - 1);
  return Math.min(config.maxBackoffMs, Math.round(exponential * (0.8 + random() * 0.4)));
}

export async function failDelivery(
  client: Pick<PrismaClient, '$executeRaw'>,
  claim: ClaimedDelivery,
  input: { code: ErrorCode; permanent: boolean; maxAttempts: number; retryDelayMs: number }
) {
  const terminal = input.permanent || claim.attempts + 1 >= input.maxAttempts;
  const updated = await client.$executeRaw`
    UPDATE "DeliveryIntent"
    SET status = ${terminal ? 'dead_letter' : 'retry'}::"DeliveryStatus",
        "nextAttemptAt" = clock_timestamp() + (${input.retryDelayMs} * interval '1 millisecond'),
        "lastError" = ${input.code}, attempts = attempts + 1,
        "leaseOwner" = NULL, "leaseToken" = NULL, "leaseExpiresAt" = NULL
    WHERE id = ${claim.id}::uuid AND status = 'processing'
      AND "leaseOwner" = ${claim.leaseOwner} AND "leaseToken" = ${claim.leaseToken}::uuid
  `;
  return { updated: updated === 1, terminal };
}

function decryptPayload(claim: ClaimedDelivery, secret: string): DeliveryPayload {
  if (claim.keyVersion !== KEY_VERSION) throw new PermanentDeliveryError(ERROR_CODES.decryption);
  try {
    const key = createHash('sha256').update(secret).digest();
    try {
      const decipher = createDecipheriv('aes-256-gcm', key, claim.payloadIv);
      decipher.setAAD(Buffer.from(`delivery:${claim.id}:${claim.conviteId}:${claim.channel}:v${claim.keyVersion}`));
      decipher.setAuthTag(claim.payloadAuthTag);
      const plaintext = Buffer.concat([decipher.update(claim.payloadCiphertext), decipher.final()]);
      try {
        const parsed: unknown = JSON.parse(plaintext.toString('utf8'));
        if (!parsed || typeof parsed !== 'object') throw new Error();
        const payload = parsed as Record<string, unknown>;
        if (payload.intentId !== claim.id || payload.invitationId !== claim.conviteId
          || typeof payload.to !== 'string' || payload.to.length === 0
          || typeof payload.body !== 'string' || payload.body.length === 0
          || (claim.channel === 'email' && (typeof payload.subject !== 'string' || payload.subject.length === 0))) {
          throw new PermanentDeliveryError(ERROR_CODES.invalid);
        }
        return payload as DeliveryPayload;
      } finally {
        plaintext.fill(0);
      }
    } finally {
      key.fill(0);
    }
  } catch (error) {
    if (error instanceof PermanentDeliveryError) throw error;
    throw new PermanentDeliveryError(ERROR_CODES.decryption);
  }
}

function classifyFailure(error: unknown): { code: ErrorCode; permanent: boolean } {
  if (error instanceof DeliveryProviderUnavailableError) return { code: ERROR_CODES.unavailable, permanent: false };
  if (error instanceof DeliveryProviderTimeoutError) return { code: ERROR_CODES.timeout, permanent: false };
  if (error instanceof PermanentDeliveryError) {
    const code = Object.values(ERROR_CODES).includes(error.message as ErrorCode)
      ? error.message as ErrorCode
      : ERROR_CODES.permanent;
    return { code, permanent: true };
  }
  return { code: ERROR_CODES.transient, permanent: false };
}

async function maintainLease(
  client: Pick<PrismaClient, '$executeRaw'>,
  claim: ClaimedDelivery,
  leaseMs: number,
  signal: AbortSignal
) {
  const intervalMs = Math.max(250, Math.floor(leaseMs / 3));
  while (!signal.aborted) {
    await sleep(intervalMs, signal);
    try {
      if (!signal.aborted && !await renewDeliveryLease(client, claim, leaseMs)) return false;
    } catch {
      return false;
    }
  }
  return true;
}

async function sendWithDeadline(input: {
  provider: DeliveryProvider;
  channel: DeliveryChannel;
  idempotencyKey: string;
  payload: DeliveryPayload;
  timeoutMs: number;
  shutdownSignal?: AbortSignal;
}) {
  if (input.provider.supportsIdempotency !== true) {
    throw new PermanentDeliveryError('provider must support stable idempotency keys');
  }
  const controller = new AbortController();
  let timedOut = false;
  const timeout = setTimeout(() => {
    timedOut = true;
    controller.abort();
  }, input.timeoutMs);
  const shutdown = () => controller.abort();
  const aborted = new Promise<never>((_, reject) => {
    controller.signal.addEventListener('abort', () => {
      reject(timedOut ? new DeliveryProviderTimeoutError() : new DeliveryAbortedError());
    }, { once: true });
  });
  input.shutdownSignal?.addEventListener('abort', shutdown, { once: true });
  try {
    if (input.shutdownSignal?.aborted) controller.abort();
    if (controller.signal.aborted) await aborted;
    await Promise.race([
      input.provider.send({
        channel: input.channel,
        idempotencyKey: input.idempotencyKey,
        payload: input.payload,
        signal: controller.signal
      }),
      aborted
    ]);
  } finally {
    clearTimeout(timeout);
    input.shutdownSignal?.removeEventListener('abort', shutdown);
  }
}

export async function runDeliveryBatch(input: {
  client: DeliveryClient;
  provider: DeliveryProvider;
  secret: string;
  workerId: string;
  config: DeliveryWorkerConfig;
  random?: () => number;
  shutdownSignal?: AbortSignal;
}) {
  await verifyDeliverySecret(input.client, input.secret);
  await verifyDeliveryPolicy(input.client, input.config.maxAttempts);
  const claims = await claimDeliveries(input.client, {
    workerId: safeWorkerId(input.workerId),
    batchSize: input.config.batchSize,
    leaseMs: input.config.leaseMs,
    maxAttempts: input.config.maxAttempts
  });
  const outcomes = { delivered: 0, retry: 0, deadLetter: 0, deferred: 0, stale: 0, email: 0, sms: 0 };
  const leases = new Map(claims.map((claim) => {
    const controller = new AbortController();
    const lease = {
      controller,
      lost: false,
      maintained: Promise.resolve(true)
    };
    lease.maintained = maintainLease(input.client, claim, input.config.leaseMs, controller.signal)
      .then((maintained) => {
        lease.lost = !maintained;
        return maintained;
      });
    return [claim.id, lease];
  }));
  let cursor = 0;
  const processNext = async () => {
    while (cursor < claims.length) {
      const claim = claims[cursor++]!;
      outcomes[claim.channel]++;
      const lease = leases.get(claim.id)!;
      if (lease.lost) {
        outcomes.stale++;
        continue;
      }
      try {
        const payload = decryptPayload(claim, input.secret);
        await sendWithDeadline({
          provider: input.provider,
          channel: claim.channel,
          idempotencyKey: claim.id,
          payload,
          timeoutMs: input.config.providerTimeoutMs,
          shutdownSignal: input.shutdownSignal
        });
        lease.controller.abort();
        if (!await lease.maintained || !await completeDelivery(input.client, claim)) outcomes.stale++;
        else outcomes.delivered++;
      } catch (error) {
        lease.controller.abort();
        const retainedLease = await lease.maintained;
        if (error instanceof DeliveryAbortedError) {
          outcomes.deferred++;
          continue;
        }
        const failure = classifyFailure(error);
        const delay = retryDelayMs(claim.attempts + 1, input.config, input.random);
        const result = retainedLease ? await failDelivery(input.client, claim, {
          ...failure,
          maxAttempts: input.config.maxAttempts,
          retryDelayMs: delay
        }) : { updated: false, terminal: false };
        if (!result.updated) outcomes.stale++;
        else if (result.terminal) outcomes.deadLetter++;
        else outcomes.retry++;
      }
    }
  };
  try {
    await Promise.all(Array.from({ length: Math.min(input.config.concurrency, claims.length) }, processNext));
  } finally {
    for (const lease of leases.values()) lease.controller.abort();
    await Promise.all([...leases.values()].map(({ maintained }) => maintained));
  }
  return { claimed: claims.length, ...outcomes };
}

export function createDevelopmentDeliveryProvider(): DeliveryProvider {
  return { supportsIdempotency: true, async send() {} };
}

export function createUnavailableDeliveryProvider(): DeliveryProvider {
  return {
    supportsIdempotency: true,
    async send() { throw new DeliveryProviderUnavailableError('Delivery provider is unavailable'); }
  };
}

function sleep(ms: number, signal: AbortSignal) {
  return new Promise<void>((resolve) => {
    const timer = setTimeout(resolve, ms);
    signal.addEventListener('abort', () => { clearTimeout(timer); resolve(); }, { once: true });
  });
}

async function run() {
  if (!process.env.DATABASE_URL) throw new Error('DATABASE_URL is required');
  const secret = process.env.IDEMPOTENCY_CACHE_SECRET;
  if (!secret) throw new Error('IDEMPOTENCY_CACHE_SECRET is required');
  const config = deliveryWorkerConfig();
  const workerId = safeWorkerId(process.env.DELIVERY_WORKER_ID ?? `${hostname()}:${process.pid}:${randomUUID()}`);
  const provider = process.env.NODE_ENV === 'development'
    ? createDevelopmentDeliveryProvider()
    : createUnavailableDeliveryProvider();
  const client = new PrismaClient();
  const stopping = new AbortController();
  const stop = () => stopping.abort();
  process.once('SIGINT', stop);
  process.once('SIGTERM', stop);
  try {
    while (!stopping.signal.aborted) {
      const startedAt = Date.now();
      const result = await runDeliveryBatch({
        client, provider, secret, workerId, config, shutdownSignal: stopping.signal
      });
      console.log(JSON.stringify({ event: 'delivery_batch', ...result, durationMs: Date.now() - startedAt }));
      if (result.claimed === 0) await sleep(config.pollMs, stopping.signal);
    }
  } finally {
    process.off('SIGINT', stop);
    process.off('SIGTERM', stop);
    await client.$disconnect();
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try {
    await run();
  } catch (error) {
    console.error(error instanceof Error ? error.message : 'Delivery worker failed');
    process.exitCode = 1;
  }
}
