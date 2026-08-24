import { pathToFileURL } from 'node:url';

import { Prisma, type PrismaClient } from '@prisma/client';

import { disconnectPrisma, prisma } from '../lib/prisma.js';

export const ANONYMIZED_GUEST_NAME = 'Convidado anonimizado';
export const ANONYMIZED_ENTRY_MESSAGE = 'Visitante anonimizado entrou no condomínio';

type AnonymizationClient = Pick<PrismaClient, '$transaction' | '$queryRaw'>;

export type AnonymizationOptions = {
  cutoff: Date;
  batchSize?: number;
  anonymizedAt?: Date;
};

function positiveInteger(value: string | undefined, fallback: number, maximum: number, name: string) {
  const parsed = value === undefined ? fallback : Number(value);
  if (!Number.isSafeInteger(parsed) || parsed < 1 || parsed > maximum) {
    throw new Error(`${name} must be an integer between 1 and ${maximum}`);
  }
  return parsed;
}

export function anonymizationConfig(environment: NodeJS.ProcessEnv = process.env) {
  return {
    retentionMonths: positiveInteger(environment.ANONYMIZATION_RETENTION_MONTHS, 12, 120, 'ANONYMIZATION_RETENTION_MONTHS'),
    batchSize: positiveInteger(environment.ANONYMIZATION_BATCH_SIZE, 500, 1000, 'ANONYMIZATION_BATCH_SIZE')
  };
}

export function subtractUtcMonths(now: Date, months: number) {
  if (!Number.isSafeInteger(months) || months < 1) throw new RangeError('Retention months must be a positive integer');
  const cutoff = new Date(now);
  const day = cutoff.getUTCDate();
  cutoff.setUTCDate(1);
  cutoff.setUTCMonth(cutoff.getUTCMonth() - months);
  const lastDay = new Date(Date.UTC(cutoff.getUTCFullYear(), cutoff.getUTCMonth() + 1, 0)).getUTCDate();
  cutoff.setUTCDate(Math.min(day, lastDay));
  return cutoff;
}

export async function anonymizeOldGuestData(client: AnonymizationClient, options: AnonymizationOptions) {
  const batchSize = options.batchSize ?? 500;
  const anonymizedAt = options.anonymizedAt ?? new Date();
  if (Number.isNaN(options.cutoff.getTime()) || Number.isNaN(anonymizedAt.getTime())) {
    throw new RangeError('Anonymization dates must be valid');
  }
  if (!Number.isSafeInteger(batchSize) || batchSize < 1 || batchSize > 1000) {
    throw new RangeError('Anonymization batch size must be between 1 and 1000');
  }

  return client.$transaction(async (transaction) => {
    // SKIP LOCKED lets multiple scheduler instances cooperate and avoids racing invitation issuance,
    // which already locks the guest row before creating an invitation.
    const candidates = await transaction.$queryRaw<Array<{ id: string }>>`
      SELECT convidado.id
      FROM "Convidado" AS convidado
      WHERE convidado."anonymizedAt" IS NULL
        AND (
          (
            EXISTS (
              SELECT 1 FROM "Convite" AS convite
              WHERE convite."convidadoId" = convidado.id
                AND convite."condominioId" = convidado."condominioId"
            )
            AND NOT EXISTS (
              SELECT 1 FROM "Convite" AS convite
              WHERE convite."convidadoId" = convidado.id
                AND convite."condominioId" = convidado."condominioId"
                AND (convite."expiresAt" IS NULL OR convite."expiresAt" > ${options.cutoff})
            )
          )
          OR (
            convidado."createdAt" <= ${options.cutoff}
            AND NOT EXISTS (
              SELECT 1 FROM "Convite" AS convite
              WHERE convite."convidadoId" = convidado.id
                AND convite."condominioId" = convidado."condominioId"
            )
          )
        )
      ORDER BY convidado.id
      LIMIT ${batchSize}
      FOR UPDATE OF convidado SKIP LOCKED
    `;

    if (candidates.length === 0) return { count: 0 };
    const ids = candidates.map(({ id }) => id);
    const anonymized = await transaction.$queryRaw<Array<{ id: string }>>(Prisma.sql`
      UPDATE "Convidado"
      SET nome = ${ANONYMIZED_GUEST_NAME},
          email = NULL,
          telefone = NULL,
          "anonymizedAt" = ${anonymizedAt}
      WHERE id IN (${Prisma.join(ids)})
        AND "anonymizedAt" IS NULL
      RETURNING id
    `);

    if (anonymized.length > 0) {
      const anonymizedIds = anonymized.map(({ id }) => id);
      await transaction.$executeRaw(Prisma.sql`
        UPDATE "Notificacao"
        SET "nomeConvidado" = ${ANONYMIZED_GUEST_NAME},
            mensagem = ${ANONYMIZED_ENTRY_MESSAGE}
        WHERE "convidadoId" IN (${Prisma.join(anonymizedIds)})
      `);
    }

    return { count: anonymized.length };
  });
}

async function countEligibleGuests(client: AnonymizationClient, cutoff: Date) {
  const [{ count }] = await client.$queryRaw<Array<{ count: bigint }>>`
    SELECT COUNT(*)::bigint AS count
    FROM "Convidado" AS convidado
    WHERE convidado."anonymizedAt" IS NULL
      AND (
        (
          EXISTS (
            SELECT 1 FROM "Convite" AS convite
            WHERE convite."convidadoId" = convidado.id
              AND convite."condominioId" = convidado."condominioId"
          )
          AND NOT EXISTS (
            SELECT 1 FROM "Convite" AS convite
            WHERE convite."convidadoId" = convidado.id
              AND convite."condominioId" = convidado."condominioId"
              AND (convite."expiresAt" IS NULL OR convite."expiresAt" > ${cutoff})
          )
        )
        OR (
          convidado."createdAt" <= ${cutoff}
          AND NOT EXISTS (
            SELECT 1 FROM "Convite" AS convite
            WHERE convite."convidadoId" = convidado.id
              AND convite."condominioId" = convidado."condominioId"
          )
        )
      )
  `;
  return count;
}

export async function runAnonymizationJob(
  environment: NodeJS.ProcessEnv = process.env,
  now = new Date(),
  client: AnonymizationClient = prisma
) {
  const config = anonymizationConfig(environment);
  const cutoff = subtractUtcMonths(now, config.retentionMonths);
  let count = 0;
  let batchCount: number;
  do {
    const batch = await anonymizeOldGuestData(client, { cutoff, batchSize: config.batchSize, anonymizedAt: now });
    batchCount = batch.count;
    count += batchCount;
  } while (batchCount === config.batchSize);
  const remaining = await countEligibleGuests(client, cutoff);
  if (remaining > 0n) {
    throw new Error(`Anonymization left ${remaining} eligible guests locked; retry the job`);
  }
  return { count, cutoff };
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try {
    const result = await runAnonymizationJob();
    console.log(JSON.stringify({ anonymizedGuests: result.count, cutoff: result.cutoff.toISOString() }));
  } catch (error) {
    console.error(error);
    process.exitCode = 1;
  } finally {
    await disconnectPrisma();
  }
}
