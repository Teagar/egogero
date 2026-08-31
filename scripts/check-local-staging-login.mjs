import { createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { readFile } from 'node:fs/promises';
import path from 'node:path';
import process from 'node:process';

import { chromium } from '@playwright/test';

try {
  resetSyntheticRateLimits();
  try {
    const realm = JSON.parse(await readFile('.local-staging/realm.json', 'utf8'));
    const expectedUsers = [
      { username: 'provedor', role: 'provedor', heading: 'Condomínios' },
      { username: 'sindico', role: 'sindico', heading: 'Pessoas' },
      { username: 'morador', role: 'morador', heading: 'Meus convidados' },
      { username: 'portaria', role: 'portaria', heading: 'Validar visitante' }
    ];

    const browser = await chromium.launch();
    try {
      for (const expected of expectedUsers) {
        const password = realm.users?.find((user) => user.username === expected.username)
          ?.credentials?.find((credential) => credential.type === 'password')?.value;
        if (!password) throw new Error(`Generated local ${expected.username} credential is unavailable`);
        const context = await browser.newContext({ ignoreHTTPSErrors: true });
        try {
          const page = await context.newPage();
          await page.goto('https://office.localhost:8443/auth/login');
          await page.locator('#username').fill(expected.username);
          await page.locator('#password').fill(password);
          await page.locator('#kc-login').click();
          await page.waitForURL('https://office.localhost:8443/');
          const response = await context.request.get('https://office.localhost:8443/auth/session');
          if (response.status() !== 200) throw new Error(`Application did not create a session for ${expected.username}`);
          const session = await response.json();
          const active = session.memberships?.find((membership) => membership.id === session.activeMembershipId);
          if (active?.role !== expected.role) throw new Error(`Application did not activate ${expected.role} for ${expected.username}`);
          await page.getByRole('heading', { level: 1, name: expected.heading }).waitFor();
          process.stdout.write(`PASS ${expected.username} OIDC session and ${expected.role} screen\n`);
        } finally {
          await context.close();
        }
      }
    } finally {
      await browser.close();
    }
  } finally {
    resetSyntheticRateLimits();
  }
} catch (error) {
  process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
  process.exitCode = 1;
}

function resetSyntheticRateLimits() {
  const root = process.cwd();
  const projectName = `office-local-staging-${createHash('sha256').update(root).digest('hex').slice(0, 10)}`;
  const result = spawnSync('docker', [
    'compose', '--project-name', projectName, '-f', path.join(root, 'docker-compose.staging.yml'),
    'exec', '-T', 'db', 'psql', '-U', 'office', '-d', 'office', '-c',
    'TRUNCATE "AuthenticationRateLimit", "AuthenticationRateLimitReservation";'
  ], { cwd: root, stdio: 'ignore' });
  if (result.error) throw result.error;
  if (result.status !== 0) throw new Error('Could not reset synthetic authentication rate limits');
}
