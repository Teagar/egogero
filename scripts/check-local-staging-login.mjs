import { readFile } from 'node:fs/promises';
import process from 'node:process';

import { chromium } from '@playwright/test';

try {
  const realm = JSON.parse(await readFile('.local-staging/realm.json', 'utf8'));
  const password = realm.users?.find((user) => user.username === 'operator')
    ?.credentials?.find((credential) => credential.type === 'password')?.value;
  if (!password) throw new Error('Generated local operator credential is unavailable');

  const browser = await chromium.launch();
  try {
    const context = await browser.newContext({ ignoreHTTPSErrors: true });
    const page = await context.newPage();
    await page.goto('https://office.localhost:8443/auth/login');
    await page.locator('#username').fill('operator');
    await page.locator('#password').fill(password);
    await page.locator('#kc-login').click();
    await page.waitForURL('https://office.localhost:8443/');
    const response = await context.request.get('https://office.localhost:8443/auth/session');
    if (response.status() !== 200) throw new Error('Application did not create an authenticated browser session');
    process.stdout.write('PASS browser OIDC callback and application session\n');
  } finally {
    await browser.close();
  }
} catch (error) {
  process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
  process.exitCode = 1;
}
