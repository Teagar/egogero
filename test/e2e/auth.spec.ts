import { readFile, readdir } from 'node:fs/promises';
import path from 'node:path';

import { expect, test, type APIRequestContext, type BrowserContext, type Page } from '@playwright/test';
import { Client } from 'pg';

const APP_ORIGIN = 'https://127.0.0.1:3443';
const OIDC_ORIGIN = 'https://127.0.0.1:3444';
const DATABASE_URL = process.env.DATABASE_URL
  ?? 'postgresql://office:office@127.0.0.1:5432/office_pc31_e2e?schema=public';
const INVITATION_TOKEN = (await readFile(path.resolve('.e2e-tmp/invitation-token'), 'utf8')).trim();
const SECRET_PATTERN = /(?:__Host-eg_(?:session|oidc_handoff)=|x-csrf-token|code_verifier|pc31_invitation_token|egdev_[A-Za-z0-9_-]+)/i;

type ProviderControl = {
  attack?: 'none' | 'state' | 'nonce' | 'pkce' | 'issuer';
  subject?: string;
  email?: string;
  amr?: string[];
  acr?: string;
};

async function control(request: APIRequestContext, body: ProviderControl = {}) {
  const response = await request.post(`${OIDC_ORIGIN}/__control`, { data: body });
  expect(response.status()).toBe(204);
}

async function login(page: Page) {
  await page.goto('/auth/login');
  await expect(page).toHaveURL(/\/app$|\/$/);
  await expect(page.locator('.shell-main h1')).toBeVisible();
}

async function csrf(context: BrowserContext) {
  const response = await context.request.get(`${APP_ORIGIN}/auth/session`);
  expect(response.status()).toBe(200);
  return (await response.json() as { csrfToken: string }).csrfToken;
}

async function resetRateLimits() {
  const database = new Client({ connectionString: DATABASE_URL });
  await database.connect();
  try {
    await database.query('DELETE FROM "AuthenticationRateLimit"');
  } finally {
    await database.end();
  }
}

test.describe.configure({ mode: 'serial' });

test('real HTTPS login rotates fixation input, bootstraps CSRF only in memory, and enforces browser boundaries', async ({ page, context, request }) => {
  await control(request);
  const fixed = 'A'.repeat(43);
  await context.addCookies([{ name: '__Host-eg_session', value: fixed, url: APP_ORIGIN, secure: true, httpOnly: true, sameSite: 'Lax' }]);
  await context.setExtraHTTPHeaders({ 'X-Forwarded-For': '203.0.113.9', 'X-Forwarded-Proto': 'http' });
  const callbackUrls: string[] = [];
  page.on('request', (seen) => { if (new URL(seen.url()).pathname === '/auth/callback') callbackUrls.push(seen.url()); });
  await login(page);

  const sessionCookie = (await context.cookies()).find((cookie) => cookie.name === '__Host-eg_session');
  expect(sessionCookie).toMatchObject({ secure: true, httpOnly: true, sameSite: 'Lax', path: '/' });
  expect(sessionCookie?.value).not.toBe(fixed);
  expect(await page.evaluate(() => ({ local: Object.values(localStorage), session: Object.values(sessionStorage) })))
    .toEqual({ local: [], session: [] });
  expect(callbackUrls).toHaveLength(1);

  const replay = await context.newPage();
  await replay.goto(callbackUrls[0]!);
  await expect(replay).toHaveURL('/auth/error');
  await expect(replay.getByText('A autenticação está indisponível no momento.')).toBeVisible();
  await replay.close();

  const token = await csrf(context);
  const missingCsrf = await context.request.post(`${APP_ORIGIN}/auth/tenant`, {
    headers: { Origin: APP_ORIGIN, 'Content-Type': 'application/json' },
    data: { membershipId: '31000000-0000-4000-8000-000000000006' }
  });
  expect(missingCsrf.status()).toBe(403);
  const wrongOrigin = await context.request.post(`${APP_ORIGIN}/auth/tenant`, {
    headers: { Origin: 'https://attacker.invalid', 'Content-Type': 'application/json', 'X-CSRF-Token': token },
    data: { membershipId: '31000000-0000-4000-8000-000000000006' }
  });
  expect(wrongOrigin.status()).toBe(403);
  const wrongType = await context.request.post(`${APP_ORIGIN}/auth/tenant`, {
    headers: { Origin: APP_ORIGIN, 'Content-Type': 'text/plain', 'X-CSRF-Token': token }, data: '{}'
  });
  expect(wrongType.status()).toBe(403);
  const validReferer = await context.request.post(`${APP_ORIGIN}/auth/tenant`, {
    headers: { Referer: `${APP_ORIGIN}/app`, 'Content-Type': 'application/json', 'X-CSRF-Token': token },
    data: { membershipId: '31000000-0000-4000-8000-000000000005' }
  });
  expect(validReferer.status()).toBe(204);
  const ambiguous = await context.request.get(`${APP_ORIGIN}/auth/session`, {
    headers: { Authorization: 'Bearer egdev_not-a-device-credential' }
  });
  expect(ambiguous.status()).toBe(400);
  expect(await ambiguous.json()).toEqual({ error: 'ambiguous_credentials' });

  const inlineRan = await page.evaluate<boolean>(`(() => {
    const script = document.createElement('script');
    script.textContent = 'window.__pc31Inline = true';
    document.body.append(script);
    return Boolean(window.__pc31Inline);
  })()`);
  expect(inlineRan).toBe(false);
  const documentResponse = await context.request.get(`${APP_ORIGIN}/app`);
  expect(documentResponse.headers()['content-security-policy']).toContain("script-src 'self'");
  expect(documentResponse.headers()['content-security-policy']).not.toContain("'unsafe-inline'");

  const database = new Client({ connectionString: DATABASE_URL });
  await database.connect();
  const stored = await database.query<{ ipPrefix: string }>('SELECT "ipPrefix" FROM "BrowserSession" WHERE "revokedAt" IS NULL');
  await database.end();
  expect(stored.rows[0]?.ipPrefix).not.toContain('203.0.113');
});

test('tenant switch performs MFA reauthentication, rotates the cookie, and keeps keyboard/mobile shell usable', async ({ page, context, request }) => {
  await control(request);
  await login(page);
  const before = (await context.cookies()).find((cookie) => cookie.name === '__Host-eg_session')?.value;
  await control(request, { amr: ['webauthn'], acr: 'strong' });
  await page.getByRole('button', { name: 'Contexto' }).first().click();
  const manager = page.locator('.context-card').filter({ hasText: 'Síndico' });
  await Promise.all([
    page.waitForResponse((response) => new URL(response.url()).pathname === '/auth/callback'),
    manager.click()
  ]);
  await expect(page.getByRole('heading', { name: 'Meus convidados' })).toBeVisible();
  await page.getByRole('button', { name: 'Contexto' }).first().click();
  await page.locator('.context-card').filter({ hasText: 'Síndico' }).click();
  await expect(page.getByRole('heading', { name: 'Pessoas' })).toBeVisible();
  const after = (await context.cookies()).find((cookie) => cookie.name === '__Host-eg_session')?.value;
  expect(after).toBeTruthy();
  expect(after).not.toBe(before);
  await expect(page.getByRole('heading', { name: 'Pessoas' })).toBeFocused();

  await page.setViewportSize({ width: 390, height: 844 });
  await expect(page.getByRole('navigation', { name: 'Navegação móvel' })).toBeVisible();
  await expect(page.locator('.sidebar')).toBeHidden();
  await page.keyboard.press('Tab');
  expect(await page.evaluate<boolean>("document.activeElement?.matches('a,button,summary,input,select') === true")).toBe(true);
});

test('current logout revokes concurrent tabs and recovery uses the exact local provider endpoint', async ({ page, context, request }) => {
  await control(request, { amr: ['webauthn'], acr: 'strong' });
  await login(page);
  const otherTab = await context.newPage();
  await otherTab.goto('/app');
  await expect(otherTab.locator('.shell-main h1')).toBeVisible();
  await page.goto('/logout');
  await page.getByRole('button', { name: 'Sair deste dispositivo' }).click();
  await expect(page).toHaveURL('/login');
  await otherTab.reload();
  await expect(otherTab.getByRole('heading', { name: 'Entrar na plataforma' })).toBeVisible();
  await otherTab.close();

  await page.goto('/recovery');
  await page.getByRole('link', { name: 'Continuar recuperação' }).click();
  await expect(page.locator('.shell-main h1')).toBeVisible();
});

for (const attack of ['state', 'nonce', 'pkce', 'issuer'] as const) {
  test(`OIDC ${attack} mismatch fails closed with a neutral browser error`, async ({ browser, request }) => {
    await resetRateLimits();
    await control(request, { attack, amr: ['webauthn'], acr: 'strong' });
    const isolated = await browser.newContext({ ignoreHTTPSErrors: true });
    const page = await isolated.newPage();
    await page.goto(`${APP_ORIGIN}/auth/login`);
    await expect(page).toHaveURL(`${APP_ORIGIN}/auth/error`);
    await expect(page.getByText('A autenticação está indisponível no momento.')).toBeVisible();
    await isolated.close();
  });
}

test('invitation fragment is scrubbed before acceptance and invitation failures remain enumeration-neutral', async ({ browser, request }) => {
  await resetRateLimits();
  await control(request, {
    subject: 'pc31-invited', email: 'invited@example.test', amr: ['webauthn'], acr: 'strong'
  });
  const invited = await browser.newContext({ ignoreHTTPSErrors: true });
  const page = await invited.newPage();
  await page.goto(`${APP_ORIGIN}/invitation#token=${INVITATION_TOKEN}`);
  await expect(page).toHaveURL(`${APP_ORIGIN}/invitation`);
  expect(await page.evaluate<string>('location.hash')).toBe('');
  await page.getByRole('button', { name: 'Continuar com identidade corporativa' }).click();
  await expect(page.getByRole('heading', { name: 'Validar visitante' })).toBeVisible();
  expect(page.url()).not.toContain(INVITATION_TOKEN);
  await invited.close();

  const invalid = await browser.newContext({ ignoreHTTPSErrors: true });
  const invalidPage = await invalid.newPage();
  await invalidPage.goto(`${APP_ORIGIN}/invitation#token=${'Z'.repeat(43)}`);
  await invalidPage.getByRole('button', { name: 'Continuar com identidade corporativa' }).click();
  await expect(invalidPage.getByRole('heading', { name: 'Acesso indisponível' })).toBeVisible();
  expect(await invalidPage.locator('body').innerText()).not.toMatch(/expired|unknown|email|token/i);
  await invalid.close();
});

test.afterAll(async () => {
  expect(process.env.PC31_E2E_BROWSER_READY).toBe('true');
  for (const root of ['test-results', 'playwright-report']) {
    const files = await filesBelow(path.resolve(root));
    for (const file of files.filter((candidate) => /\.(?:txt|json|html|log)$/i.test(candidate))) {
      expect(await readFile(file, 'utf8'), `credential-like text leaked into ${file}`).not.toMatch(SECRET_PATTERN);
    }
  }
});

async function filesBelow(root: string): Promise<string[]> {
  let entries;
  try { entries = await readdir(root, { withFileTypes: true }); } catch { return []; }
  const nested = await Promise.all(entries.map((entry) => {
    const location = path.join(root, entry.name);
    return entry.isDirectory() ? filesBelow(location) : [location];
  }));
  return nested.flat();
}
