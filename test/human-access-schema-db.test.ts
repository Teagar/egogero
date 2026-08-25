import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import test from 'node:test';
import pg from 'pg';

const databaseUrl = process.env.DATABASE_URL;
const enabled = process.env.RUN_DATABASE_TESTS === 'true' && Boolean(databaseUrl);

test('PostgreSQL preserves human gatehouse audit rows as immutable historical actor records', { skip: !enabled }, async () => {
  const client = new pg.Client({ connectionString: databaseUrl });
  await client.connect();
  const id = randomUUID();
  try {
    await client.query(
      `INSERT INTO "AuditoriaAcessoHumano"
         (id, "condominioId", "accountId", "membershipId", "tipoAcesso", resultado)
       VALUES ($1, $2, $3, $4, 'pedestre', 'negado')`,
      [id, randomUUID(), randomUUID(), randomUUID()]
    );
    for (const statement of [
      `UPDATE "AuditoriaAcessoHumano" SET resultado = 'permitido' WHERE id = $1`,
      `DELETE FROM "AuditoriaAcessoHumano" WHERE id = $1`
    ]) {
      await assert.rejects(client.query(statement, [id]), (error: unknown) =>
        typeof error === 'object' && error !== null && 'code' in error && error.code === '55000');
    }
    await assert.rejects(client.query('TRUNCATE "AuditoriaAcessoHumano"'), (error: unknown) =>
      typeof error === 'object' && error !== null && 'code' in error && error.code === '55000');
  } finally {
    await client.end();
  }
});
