import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';

import { AUTH_RATE_LIMIT_POLICIES, AUTH_RATE_LIMIT_POLICY_TABLE } from '../src/auth-rate-limits.js';

function documentedTable(markdown: string) {
  const match = markdown.match(/<!-- auth-rate-limits:start -->\n([\s\S]*?)\n<!-- auth-rate-limits:end -->/);
  assert.ok(match, 'rate-limit parity markers must be present');
  return match[1];
}

test('runtime policy is the normative source for ADR and operations limits', async () => {
  const [adr, operations] = await Promise.all([
    readFile(new URL('../docs/adr/0001-human-authentication.md', import.meta.url), 'utf8'),
    readFile(new URL('../docs/auth-observability.md', import.meta.url), 'utf8')
  ]);
  assert.equal(documentedTable(adr), AUTH_RATE_LIMIT_POLICY_TABLE);
  assert.equal(documentedTable(operations), AUTH_RATE_LIMIT_POLICY_TABLE);

  assert.deepEqual(
    Object.fromEntries(Object.entries(AUTH_RATE_LIMIT_POLICIES).map(([action, policy]) =>
      [action, { limit: policy.limit, windowMs: policy.windowMs }]
    )),
    {
      login_ip: { limit: 5, windowMs: 600_000 },
      callback_failure_ip: { limit: 10, windowMs: 900_000 },
      session_creation_account: { limit: 10, windowMs: 900_000 },
      recovery_ip: { limit: 3, windowMs: 1_800_000 },
      reauthentication_account: { limit: 5, windowMs: 600_000 },
      invitation_acceptance_ip: { limit: 10, windowMs: 3_600_000 },
      invitation_acceptance_digest: { limit: 5, windowMs: 3_600_000 },
      human_validation_account: { limit: 20, windowMs: 60_000 },
      authentication_failure_ip: { limit: 60, windowMs: 60_000 }
    },
    'security boundaries require an explicit policy and documentation change'
  );
});
