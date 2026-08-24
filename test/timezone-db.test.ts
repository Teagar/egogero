import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import test from 'node:test';

import { Client } from 'pg';

const runDatabaseTests = process.env.RUN_DATABASE_TESTS === 'true';
const migrationPath = new URL('../prisma/migrations/0016_add_condominium_timezone_and_timestamptz/migration.sql', import.meta.url);
const timestampColumns = {
  Condominio: ['createdAt', 'deletedAt'],
  Morador: ['createdAt', 'deletedAt'],
  Convidado: ['createdAt', 'deletedAt', 'ultimoUsoEm', 'anonymizedAt'],
  Convite: ['createdAt', 'deletedAt', 'expiresAt', 'usedAt', 'revokedAt'],
  AuditoriaAcesso: ['createdAt'],
  Dispositivo: ['createdAt', 'deletedAt', 'ultimoUsoEm'],
  DispositivoRateLimit: ['blockedUntil'],
  Notificacao: ['createdAt', 'deletedAt', 'lidaEm', 'entrouEm']
} as const;

test('seeded migration preserves every UTC epoch under a non-UTC database session', { skip: !runDatabaseTests }, async () => {
  const client = new Client({ connectionString: process.env.DATABASE_URL });
  const schema = `pc21_${randomUUID().replaceAll('-', '')}`;
  const instant = '2026-01-02 03:04:05.678';
  await client.connect();
  try {
    await client.query(`CREATE SCHEMA "${schema}"`);
    await client.query(`SET search_path TO "${schema}"`);
    await client.query(`SET TIME ZONE 'Pacific/Honolulu'`);
    await client.query(`
      CREATE TABLE "Condominio" (id text PRIMARY KEY, "createdAt" timestamp(3), "deletedAt" timestamp(3));
      CREATE TABLE "Morador" (id text PRIMARY KEY, "createdAt" timestamp(3), "deletedAt" timestamp(3));
      CREATE TABLE "Convidado" (id text PRIMARY KEY, "createdAt" timestamp(3), "deletedAt" timestamp(3), "ultimoUsoEm" timestamp(3), "anonymizedAt" timestamp(3));
      CREATE TABLE "Convite" (id text PRIMARY KEY, "createdAt" timestamp(3), "deletedAt" timestamp(3), "expiresAt" timestamp(3), "usedAt" timestamp(3), "revokedAt" timestamp(3));
      CREATE TABLE "AuditoriaAcesso" (id text PRIMARY KEY, "createdAt" timestamp(3));
      CREATE TABLE "Dispositivo" (id text PRIMARY KEY, "createdAt" timestamp(3), "deletedAt" timestamp(3), "ultimoUsoEm" timestamp(3));
      CREATE TABLE "DispositivoRateLimit" (id text PRIMARY KEY, attempts timestamp(3)[], "blockedUntil" timestamp(3));
      CREATE TABLE "Notificacao" (id text PRIMARY KEY, "createdAt" timestamp(3), "deletedAt" timestamp(3), "lidaEm" timestamp(3), "entrouEm" timestamp(3));
    `);
    for (const [table, columns] of Object.entries(timestampColumns)) {
      await client.query(
        `INSERT INTO "${table}" (id, ${columns.map((column) => `"${column}"`).join(', ')}) VALUES ('row', ${columns.map(() => '$1::timestamp').join(', ')})`,
        [instant]
      );
    }
    await client.query('UPDATE "DispositivoRateLimit" SET attempts = ARRAY[$1::timestamp, $2::timestamp]', [instant, '2026-11-01 05:30:00.123']);

    const before = new Map<string, string>();
    for (const [table, columns] of Object.entries(timestampColumns)) {
      const row = await client.query<Record<string, string>>(
        `SELECT ${columns.map((column) => `extract(epoch FROM "${column}" AT TIME ZONE 'UTC')::text AS "${column}"`).join(', ')} FROM "${table}"`
      );
      for (const column of columns) before.set(`${table}.${column}`, row.rows[0]![column]!);
    }
    const attemptsBefore = await client.query<{ first: string; second: string }>(`
      SELECT extract(epoch FROM attempts[1] AT TIME ZONE 'UTC')::text AS first,
             extract(epoch FROM attempts[2] AT TIME ZONE 'UTC')::text AS second
      FROM "DispositivoRateLimit"
    `);

    await client.query(await readFile(migrationPath, 'utf8'));

    for (const [table, columns] of Object.entries(timestampColumns)) {
      const row = await client.query<Record<string, string>>(
        `SELECT ${columns.map((column) => `extract(epoch FROM "${column}")::text AS "${column}"`).join(', ')} FROM "${table}"`
      );
      for (const column of columns) assert.equal(row.rows[0]![column], before.get(`${table}.${column}`), `${table}.${column}`);
    }
    const attemptsAfter = await client.query<{ first: string; second: string }>(`
      SELECT extract(epoch FROM attempts[1])::text AS first, extract(epoch FROM attempts[2])::text AS second
      FROM "DispositivoRateLimit"
    `);
    assert.deepEqual(attemptsAfter.rows[0], attemptsBefore.rows[0]);
    assert.equal((await client.query('SELECT timezone FROM "Condominio"')).rows[0]!.timezone, 'America/Sao_Paulo');
    for (const timeZone of ['UTC', 'EST5EDT', 'CST6CDT', 'PST8PDT', 'GMT0']) {
      await client.query('UPDATE "Condominio" SET timezone = $1', [timeZone]);
      assert.equal((await client.query('SELECT timezone FROM "Condominio"')).rows[0]!.timezone, timeZone);
    }
    await assert.rejects(
      client.query(`UPDATE "Condominio" SET timezone = 'Mars/Olympus'`),
      (error: unknown) => Boolean(error && typeof error === 'object' && (error as { code?: string }).code === '22023')
    );
    const types = await client.query<{ data_type: string; udt_name: string }>(`
      SELECT data_type, udt_name FROM information_schema.columns
      WHERE table_schema = $1 AND (data_type LIKE 'timestamp%' OR data_type = 'ARRAY')
    `, [schema]);
    assert.ok(types.rows.every(({ data_type, udt_name }) =>
      data_type === 'timestamp with time zone' || (data_type === 'ARRAY' && udt_name === '_timestamptz')
    ));
  } finally {
    await client.query('RESET search_path').catch(() => undefined);
    await client.query(`DROP SCHEMA IF EXISTS "${schema}" CASCADE`).catch(() => undefined);
    await client.end();
  }
});
