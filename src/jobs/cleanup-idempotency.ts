import { pathToFileURL } from 'node:url';

import { Prisma, PrismaClient } from '@prisma/client';

const DEFAULT_BATCH_SIZE = 500;

export async function cleanupExpiredIdempotencyRecords(
  client: Pick<PrismaClient, '$queryRaw'>,
  batchSize = DEFAULT_BATCH_SIZE
) {
  if (!Number.isSafeInteger(batchSize) || batchSize < 1 || batchSize > 10_000) {
    throw new RangeError('Idempotency cleanup batch size must be between 1 and 10000');
  }
  const deleted = await client.$queryRaw<Array<{ id: string }>>(Prisma.sql`
    WITH expired AS (
      SELECT id
      FROM "IdempotencyRecord"
      WHERE "confirmedAt" IS NOT NULL
        AND "expiresAt" <= clock_timestamp()
      ORDER BY "expiresAt", id
      FOR UPDATE SKIP LOCKED
      LIMIT ${batchSize}
    )
    DELETE FROM "IdempotencyRecord" AS record
    USING expired
    WHERE record.id = expired.id
      AND record."confirmedAt" IS NOT NULL
      AND record."expiresAt" <= clock_timestamp()
    RETURNING record.id
  `);
  return deleted.length;
}

async function run() {
  if (!process.env.DATABASE_URL) throw new Error('DATABASE_URL is required');
  const batchSize = Number(process.env.IDEMPOTENCY_CLEANUP_BATCH_SIZE ?? DEFAULT_BATCH_SIZE);
  const prisma = new PrismaClient();
  const startedAt = Date.now();
  try {
    const deleted = await cleanupExpiredIdempotencyRecords(prisma, batchSize);
    console.log(JSON.stringify({
      event: 'idempotency_cleanup',
      deleted,
      batchSize,
      durationMs: Date.now() - startedAt,
      hasMore: deleted === batchSize
    }));
  } finally {
    await prisma.$disconnect();
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try {
    await run();
  } catch (error) {
    console.error(error instanceof Error ? error.message : 'Idempotency cleanup failed');
    process.exitCode = 1;
  }
}
