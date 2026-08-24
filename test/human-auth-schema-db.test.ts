import assert from 'node:assert/strict';
import { randomBytes, randomUUID } from 'node:crypto';
import test from 'node:test';
import pg from 'pg';

const databaseUrl = process.env.DATABASE_URL;
const runDatabaseTests = process.env.RUN_DATABASE_TESTS === 'true';

async function rejectsWithCode(client: pg.Client, text: string, values: unknown[], codes: string[]) {
  await assert.rejects(
    client.query(text, values),
    (error: unknown) =>
      typeof error === 'object' && error !== null && 'code' in error && codes.includes(String(error.code))
  );
}

test(
  'PostgreSQL enforces human auth tenancy, crypto, uniqueness, and immutable audit invariants',
  { skip: !runDatabaseTests || !databaseUrl },
  async () => {
    const client = new pg.Client({ connectionString: databaseUrl });
    const concurrentClient = new pg.Client({ connectionString: databaseUrl });
    await client.connect();
    await concurrentClient.connect();

    const accountA = randomUUID();
    const accountB = randomUUID();
    const condominioA = randomUUID();
    const condominioB = randomUUID();
    const condominioRace = randomUUID();
    const residentA = randomUUID();
    const residentB = randomUUID();
    const providerMembership = randomUUID();
    const residentMembership = randomUUID();
    const now = new Date();

    try {
      await client.query(
        `INSERT INTO "Condominio" (id, nome, responsavel, tipo, timezone)
         VALUES ($1, 'Auth A', 'Responsible A', 'residencial', 'UTC'),
                ($2, 'Auth B', 'Responsible B', 'residencial', 'UTC'),
                ($3, 'Auth Race', 'Responsible Race', 'residencial', 'UTC')`,
        [condominioA, condominioB, condominioRace]
      );
      await client.query(
        `INSERT INTO "Morador" (id, nome, "condominioId")
         VALUES ($1, 'Resident A', $2), ($3, 'Resident B', $4)`,
        [residentA, condominioA, residentB, condominioB]
      );
      await client.query(
        `INSERT INTO "HumanAccount" (id, "updatedAt", "displayName", status)
         VALUES ($1, $3, 'Account A', 'active'), ($2, $3, 'Account B', 'active')`,
        [accountA, accountB, now]
      );

      await rejectsWithCode(
        client,
        `INSERT INTO "HumanAccount" (id, "updatedAt", "displayName", "sessionVersion")
         VALUES ($1, $2, 'Invalid', -1)`,
        [randomUUID(), now],
        ['23514']
      );
      await concurrentClient.query('BEGIN');
      await concurrentClient.query(`UPDATE "Condominio" SET "deletedAt" = $1 WHERE id = $2`, [
        now,
        condominioRace
      ]);
      const concurrentMembership = rejectsWithCode(
        client,
        `INSERT INTO "HumanMembership" (id, "accountId", "condominioId", role, status)
         VALUES ($1, $2, $3, 'sindico', 'active')`,
        [randomUUID(), accountA, condominioRace],
        ['23514']
      );
      await new Promise((resolve) => setTimeout(resolve, 25));
      await concurrentClient.query('COMMIT');
      await concurrentMembership;
      await rejectsWithCode(
        client,
        `INSERT INTO "HumanAccount" (id, "updatedAt", "displayName", status)
         VALUES ($1, $2, 'Invalid', 'disabled')`,
        [randomUUID(), now],
        ['23514']
      );

      const issuer = 'https://identity.example.test';
      const subject = `subject-${randomUUID()}`;
      await client.query(
        `INSERT INTO "ExternalIdentity" (id, "accountId", issuer, subject)
         VALUES ($1, $2, $3, $4)`,
        [randomUUID(), accountA, issuer, subject]
      );
      await rejectsWithCode(
        client,
        `INSERT INTO "ExternalIdentity" (id, "accountId", issuer, subject)
         VALUES ($1, $2, $3, $4)`,
        [randomUUID(), accountB, issuer, subject],
        ['23505']
      );

      await rejectsWithCode(
        client,
        `INSERT INTO "HumanMembership" (id, "accountId", "condominioId", role, status)
         VALUES ($1, $2, $3, 'provedor', 'active')`,
        [randomUUID(), accountA, condominioA],
        ['23514']
      );
      await rejectsWithCode(
        client,
        `INSERT INTO "HumanMembership" (id, "accountId", role, status)
         VALUES ($1, $2, 'sindico', 'active')`,
        [randomUUID(), accountA],
        ['23514']
      );
      await rejectsWithCode(
        client,
        `INSERT INTO "HumanMembership" (id, "accountId", "condominioId", "residentId", role, status)
         VALUES ($1, $2, $3, $4, 'morador', 'active')`,
        [randomUUID(), accountA, condominioA, residentB],
        ['23514']
      );
      await client.query(`UPDATE "Morador" SET "deletedAt" = $1 WHERE id = $2`, [now, residentB]);
      await rejectsWithCode(
        client,
        `INSERT INTO "HumanMembership" (id, "accountId", "condominioId", "residentId", role, status)
         VALUES ($1, $2, $3, $4, 'morador', 'active')`,
        [randomUUID(), accountB, condominioB, residentB],
        ['23514']
      );
      await client.query(`UPDATE "Condominio" SET "deletedAt" = $1 WHERE id = $2`, [now, condominioB]);
      await rejectsWithCode(
        client,
        `INSERT INTO "HumanMembership" (id, "accountId", "condominioId", role, status)
         VALUES ($1, $2, $3, 'sindico', 'active')`,
        [randomUUID(), accountB, condominioB],
        ['23514']
      );

      await client.query(
        `INSERT INTO "HumanMembership" (id, "accountId", role, status)
         VALUES ($1, $2, 'provedor', 'active')`,
        [providerMembership, accountA]
      );
      await rejectsWithCode(
        client,
        `INSERT INTO "HumanMembership" (id, "accountId", role, status)
         VALUES ($1, $2, 'provedor', 'active')`,
        [randomUUID(), accountA],
        ['23505']
      );
      await client.query(
        `INSERT INTO "HumanMembership" (id, "accountId", role, status, "disabledAt")
         VALUES ($1, $2, 'provedor', 'disabled', $3)`,
        [randomUUID(), accountA, new Date(now.getTime() + 1_000)]
      );
      await client.query(
        `INSERT INTO "HumanMembership" (id, "accountId", "condominioId", "residentId", role, status)
         VALUES ($1, $2, $3, $4, 'morador', 'active')`,
        [residentMembership, accountA, condominioA, residentA]
      );
      const disabledMembership = randomUUID();
      const activeMembershipB = randomUUID();
      await client.query(
        `INSERT INTO "HumanMembership" (id, "accountId", role, status, "disabledAt")
         VALUES ($1, $2, 'provedor', 'disabled', $3)`,
        [disabledMembership, accountB, new Date(now.getTime() + 1_000)]
      );
      await client.query(
        `INSERT INTO "HumanMembership" (id, "accountId", role, status)
         VALUES ($1, $2, 'provedor', 'active')`,
        [activeMembershipB, accountB]
      );

      const stateDigest = randomBytes(32);
      await client.query(
        `INSERT INTO "OidcLoginTransaction"
           (id, "expiresAt", "stateDigest", "nonceDigest", "pkceVerifierCiphertext",
            "pkceVerifierNonce", "pkceVerifierAuthTag", "pkceKeyVersion", issuer,
            "clientId", "redirectUri", "returnTo")
         VALUES ($1, $2, $3, $4, $5, $6, $7, 1, $8, 'client', $9, '/home')`,
        [
          randomUUID(),
          new Date(now.getTime() + 600_000),
          stateDigest,
          Buffer.alloc(32, 2),
          Buffer.alloc(64, 3),
          Buffer.alloc(12, 4),
          Buffer.alloc(16, 5),
          issuer,
          'https://app.example.test/auth/callback'
        ]
      );
      await rejectsWithCode(
        client,
        `INSERT INTO "OidcLoginTransaction"
           (id, "expiresAt", "stateDigest", "nonceDigest", "pkceVerifierCiphertext",
            "pkceVerifierNonce", "pkceVerifierAuthTag", "pkceKeyVersion", issuer,
            "clientId", "redirectUri", "returnTo")
         VALUES ($1, $2, $3, $4, $5, $6, $7, 1, $8, 'client', $9, '/home')`,
        [
          randomUUID(),
          new Date(now.getTime() + 600_000),
          Buffer.alloc(32, 6),
          Buffer.alloc(32, 7),
          Buffer.alloc(64, 8),
          Buffer.alloc(11, 9),
          Buffer.alloc(16, 10),
          issuer,
          'https://app.example.test/auth/callback'
        ],
        ['23514']
      );

      const sessionSql = `INSERT INTO "BrowserSession"
        (id, "familyId", "createdAt", "lastSeenAt", "idleExpiresAt", "absoluteExpiresAt",
         "authenticatedAt", "tokenDigest", "csrfDigest", "csrfCiphertext", "csrfNonce",
         "csrfAuthTag", "csrfKeyVersion", "accountId", "accountSessionVersion", "activeMembershipId")
        VALUES ($1, $2, $3, $3, $4, $5, $6, $7, $8, $9, $10, $11, 1, $12, 0, $13)`;
      const sessionTimes = [
        now,
        new Date(now.getTime() + 1_800_000),
        new Date(now.getTime() + 43_200_000),
        new Date(now.getTime() - 60_000)
      ];
      const tokenDigest = randomBytes(32);
      await client.query(sessionSql, [
        randomUUID(),
        randomUUID(),
        ...sessionTimes,
        tokenDigest,
        Buffer.alloc(32, 12),
        Buffer.alloc(32, 13),
        Buffer.alloc(12, 14),
        Buffer.alloc(16, 15),
        accountA,
        residentMembership
      ]);
      await rejectsWithCode(
        client,
        sessionSql,
        [
          randomUUID(),
          randomUUID(),
          ...sessionTimes,
          tokenDigest,
          Buffer.alloc(32, 16),
          Buffer.alloc(32, 17),
          Buffer.alloc(12, 18),
          Buffer.alloc(16, 19),
          accountA,
          providerMembership
        ],
        ['23505']
      );
      await rejectsWithCode(
        client,
        sessionSql,
        [
          randomUUID(),
          randomUUID(),
          ...sessionTimes,
          Buffer.alloc(32, 20),
          Buffer.alloc(32, 21),
          Buffer.alloc(32, 22),
          Buffer.alloc(12, 23),
          Buffer.alloc(16, 24),
          accountB,
          residentMembership
        ],
        ['23514']
      );
      await rejectsWithCode(
        client,
        sessionSql,
        [
          randomUUID(),
          randomUUID(),
          ...sessionTimes,
          Buffer.alloc(31, 25),
          Buffer.alloc(32, 26),
          Buffer.alloc(32, 27),
          Buffer.alloc(12, 28),
          Buffer.alloc(16, 29),
          accountA,
          providerMembership
        ],
        ['23514']
      );
      await rejectsWithCode(
        client,
        sessionSql,
        [
          randomUUID(),
          randomUUID(),
          ...sessionTimes,
          randomBytes(32),
          Buffer.alloc(32, 30),
          Buffer.alloc(32, 31),
          Buffer.alloc(12, 32),
          Buffer.alloc(16, 33),
          accountB,
          disabledMembership
        ],
        ['23514']
      );
      await concurrentClient.query('BEGIN');
      await concurrentClient.query(`UPDATE "HumanAccount" SET status = 'suspended' WHERE id = $1`, [accountB]);
      const concurrentSession = rejectsWithCode(
        client,
        sessionSql,
        [
          randomUUID(),
          randomUUID(),
          ...sessionTimes,
          randomBytes(32),
          Buffer.alloc(32, 34),
          Buffer.alloc(32, 35),
          Buffer.alloc(12, 36),
          Buffer.alloc(16, 37),
          accountB,
          activeMembershipB
        ],
        ['23514']
      );
      await new Promise((resolve) => setTimeout(resolve, 25));
      await concurrentClient.query('COMMIT');
      await concurrentSession;

      const auditId = randomUUID();
      await client.query('SET ROLE egogero_application');
      await client.query(
        `INSERT INTO "AuthenticationAuditEvent"
           (id, "eventType", outcome, "accountId", "actorType", "actorId", "requestCorrelationId", metadata)
         VALUES ($1, 'session_issued', 'success', $2::uuid, 'human', $2::text, $3, $4::jsonb)`,
        [auditId, accountA, randomUUID(), JSON.stringify({ authenticationMethod: 'oidc' })]
      );
      await rejectsWithCode(
        client,
        `UPDATE "AuthenticationAuditEvent" SET outcome = 'failure' WHERE id = $1`,
        [auditId],
        ['42501']
      );
      await rejectsWithCode(
        client,
        `DELETE FROM "AuthenticationAuditEvent" WHERE id = $1`,
        [auditId],
        ['42501']
      );
      await rejectsWithCode(client, `TRUNCATE "AuthenticationAuditEvent"`, [], ['42501']);

      const applicationPrivileges = await client.query<{ privilege_type: string }>(
        `SELECT privilege_type
         FROM information_schema.role_table_grants
         WHERE table_schema = current_schema()
           AND table_name = 'AuthenticationAuditEvent'
           AND grantee = 'egogero_application'
         ORDER BY privilege_type`
      );
      assert.deepEqual(applicationPrivileges.rows, [
        { privilege_type: 'INSERT' },
        { privilege_type: 'SELECT' }
      ]);
      const migrationLedgerPrivilege = await client.query<{ allowed: boolean }>(
        `SELECT has_table_privilege(current_user, 'public._prisma_migrations', 'SELECT') AS allowed`
      );
      assert.equal(migrationLedgerPrivilege.rows[0]?.allowed, false);
      await client.query('RESET ROLE');
      await rejectsWithCode(
        client,
        `UPDATE "AuthenticationAuditEvent" SET outcome = 'failure' WHERE id = $1`,
        [auditId],
        ['55000']
      );
    } finally {
      await client.query('RESET ROLE').catch(() => undefined);
      await concurrentClient.query('ROLLBACK').catch(() => undefined);
      await client
        .query(`DELETE FROM "BrowserSession" WHERE "accountId" IN ($1, $2)`, [accountA, accountB])
        .catch(() => undefined);
      await client
        .query(`DELETE FROM "ExternalIdentity" WHERE "accountId" IN ($1, $2)`, [accountA, accountB])
        .catch(() => undefined);
      await client
        .query(`DELETE FROM "HumanMembership" WHERE "accountId" IN ($1, $2)`, [accountA, accountB])
        .catch(() => undefined);
      await client.query(`DELETE FROM "HumanAccount" WHERE id IN ($1, $2)`, [accountA, accountB]).catch(() => undefined);
      await client.query(`DELETE FROM "Morador" WHERE id IN ($1, $2)`, [residentA, residentB]).catch(() => undefined);
      await client
        .query(`DELETE FROM "Condominio" WHERE id IN ($1, $2, $3)`, [condominioA, condominioB, condominioRace])
        .catch(() => undefined);
      await concurrentClient.end();
      await client.end();
    }
  }
);
