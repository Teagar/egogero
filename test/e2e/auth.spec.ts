import { mkdir, readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';

import { expect, test, type APIRequestContext, type BrowserContext, type Page } from '@playwright/test';
import { Client } from 'pg';

import { ARTIFACT_CANARY } from './artifacts.js';

const APP_ORIGIN = 'https://127.0.0.1:3443';
const OIDC_ORIGIN = 'https://127.0.0.1:3444';
const DATABASE_URL = process.env.DATABASE_URL
  ?? 'postgresql://office:office@127.0.0.1:5432/office_pc31_e2e?schema=public';
const INVITATION_TOKEN = (await readFile(path.resolve('.e2e-tmp/invitation-token'), 'utf8')).trim();
type ProviderControl = {
  attack?: 'none' | 'state' | 'nonce' | 'pkce' | 'issuer' | 'signature' | 'audience' | 'time';
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

async function databaseRows<T>(query: string, parameters: unknown[] = []) {
  const database = new Client({ connectionString: DATABASE_URL });
  try {
    await database.connect();
    return (await database.query<T & Record<string, unknown>>(query, parameters)).rows as T[];
  } finally { await database.end().catch(() => undefined); }
}

async function securitySnapshot() {
  const [session, accounts, identities, memberships, invited] = await Promise.all([
    databaseRows<{ count: string }>('SELECT COUNT(*)::text AS count FROM "BrowserSession"'),
    databaseRows<{ id: string; status: string; sessionVersion: number }>(`SELECT id, status, "sessionVersion"
      FROM "HumanAccount" ORDER BY id`),
    databaseRows<{ id: string; accountId: string; subject: string }>(`SELECT id, "accountId", subject
      FROM "ExternalIdentity" ORDER BY id`),
    databaseRows<{ id: string; status: string; role: string }>(`SELECT id, status, role
      FROM "HumanMembership" ORDER BY id`),
    databaseRows<{ status: string; consumedAt: Date | null }>(`SELECT account.status, invitation."consumedAt"
      FROM "HumanAccount" account JOIN "HumanProvisioningInvitation" invitation ON invitation."accountId" = account.id
      WHERE account.id = '31000000-0000-4000-8000-000000000007'::uuid`)
  ]);
  return { sessions: session[0]!.count, accounts, identities, memberships, invited: invited[0] };
}

async function providerStats(request: APIRequestContext) {
  const response = await request.get(`${OIDC_ORIGIN}/__stats`);
  expect(response.status()).toBe(200);
  return response.json() as Promise<{ tokenExchanges: number; rejectedCodeReplays: number; alerts: string[] }>;
}

test.describe.configure({ mode: 'serial' });

test('Chromium trusts only the generated leaf SPKI and rejects an unrelated local certificate', async ({ page }) => {
  await page.goto(`${APP_ORIGIN}/health`);
  await expect(page.locator('body')).toContainText('ok');
  await expect(page.goto('https://127.0.0.1:3445/')).rejects.toThrow(/ERR_CERT_(?:AUTHORITY_INVALID|INVALID)/);
});

test('real HTTPS login rotates fixation input, bootstraps CSRF only in memory, and enforces browser boundaries', async ({ page, context, request }) => {
  await control(request);
  const fixed = 'A'.repeat(43);
  await context.addCookies([{ name: '__Host-eg_session', value: fixed, url: APP_ORIGIN, secure: true, httpOnly: true, sameSite: 'Lax' }]);
  await context.setExtraHTTPHeaders({ 'X-Forwarded-For': '203.0.113.9', 'X-Forwarded-Proto': 'http' });
  const callbackUrls: string[] = [];
  const exchangesBefore = (await providerStats(request)).tokenExchanges;
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
  expect((await providerStats(request)).tokenExchanges).toBe(exchangesBefore + 1);

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
  const unchanged = await databaseRows<{ activeMembershipId: string }>(`SELECT "activeMembershipId"
    FROM "BrowserSession" WHERE "revokedAt" IS NULL ORDER BY "createdAt" DESC LIMIT 1`);
  expect(unchanged[0]?.activeMembershipId).toBe('31000000-0000-4000-8000-000000000005');
  const validReferer = await context.request.post(`${APP_ORIGIN}/auth/tenant`, {
    headers: { Referer: `${APP_ORIGIN}/app`, 'Content-Type': 'application/json', 'X-CSRF-Token': token },
    data: { membershipId: '31000000-0000-4000-8000-000000000005' }
  });
  expect(validReferer.status()).toBe(204);
  const stillUnchanged = await databaseRows<{ activeMembershipId: string }>(`SELECT "activeMembershipId"
    FROM "BrowserSession" WHERE "revokedAt" IS NULL ORDER BY "createdAt" DESC LIMIT 1`);
  expect(stillUnchanged[0]?.activeMembershipId).toBe('31000000-0000-4000-8000-000000000005');
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

test('current and all-session logout revoke concurrent tabs and independent browser sessions', async ({ page, context, browser, request }) => {
  await resetRateLimits();
  await control(request, { amr: ['webauthn'], acr: 'strong' });
  await login(page);
  const otherTab = await context.newPage();
  await otherTab.goto('/app');
  await expect(otherTab.locator('.shell-main h1')).toBeVisible();
  await page.goto('/logout');
  await Promise.all([
    otherTab.reload({ waitUntil: 'domcontentloaded' }).catch(() => null),
    page.getByRole('button', { name: 'Sair deste dispositivo' }).click()
  ]);
  await expect(page).toHaveURL('/login');
  await otherTab.reload();
  await expect(otherTab.getByRole('heading', { name: 'Entrar na plataforma' })).toBeVisible();
  await otherTab.close();

  await resetRateLimits();
  await login(page);
  const independent = await browser.newContext();
  const independentPage = await independent.newPage();
  await login(independentPage);
  await page.goto('/logout');
  await page.getByRole('button', { name: 'Sair de todos os dispositivos' }).click();
  await expect(page).toHaveURL('/login');
  await independentPage.reload();
  await expect(independentPage.getByRole('heading', { name: 'Entrar na plataforma' })).toBeVisible();
  const revocation = await databaseRows<{ count: string }>(`SELECT COUNT(*)::text AS count FROM "BrowserSession"
    WHERE "accountId" = '31000000-0000-4000-8000-000000000001'::uuid AND "revokedAt" IS NULL`);
  expect(revocation[0]!.count).toBe('0');
  await independent.close();

  await resetRateLimits();
  await page.goto('/recovery');
  await page.getByRole('link', { name: 'Continuar recuperação' }).click();
  await expect(page.locator('.shell-main h1')).toBeVisible();
});

const attacks: Array<{ label: string; control: ProviderControl; reason: string; alert?: string }> = [
  { label: 'state mismatch', control: { attack: 'state' }, reason: 'invalid_state', alert: 'oidc_replay_or_state_miss' },
  { label: 'nonce mismatch', control: { attack: 'nonce' }, reason: 'oidc_validation_failed' },
  { label: 'PKCE mismatch', control: { attack: 'pkce' }, reason: 'oidc_validation_failed' },
  { label: 'issuer mix-up', control: { attack: 'issuer' }, reason: 'issuer_mixup', alert: 'oidc_issuer_mixup' },
  { label: 'forged signature', control: { attack: 'signature' }, reason: 'oidc_validation_failed' },
  { label: 'forged audience', control: { attack: 'audience' }, reason: 'oidc_validation_failed' },
  { label: 'stale token time', control: { attack: 'time' }, reason: 'oidc_validation_failed' },
  { label: 'unknown account', control: { subject: 'pc31-unknown', email: 'unknown@example.test' }, reason: 'access_not_provisioned' }
];

for (const attack of attacks) {
  test(`OIDC ${attack.label} fails closed without session or identity mutation`, async ({ browser, request }) => {
    await resetRateLimits();
    await control(request, { ...attack.control, amr: ['webauthn'], acr: 'strong' });
    const before = await securitySnapshot();
    const auditBefore = new Set((await databaseRows<{ id: string }>(
      'SELECT id FROM "AuthenticationAuditEvent"'
    )).map((row) => row.id));
    const isolated = await browser.newContext();
    const page = await isolated.newPage();
    await page.goto(`${APP_ORIGIN}/auth/login`);
    await expect(page).toHaveURL(`${APP_ORIGIN}/auth/error`);
    await expect(page.getByText('A autenticação está indisponível no momento.')).toBeVisible();
    expect((await isolated.cookies()).some((cookie) => cookie.name === '__Host-eg_session')).toBe(false);
    expect(await securitySnapshot()).toEqual(before);
    const audits = await databaseRows<{ id: string; reasonCode: string }>(
      'SELECT id, "reasonCode" FROM "AuthenticationAuditEvent"'
    );
    expect(audits.filter((row) => !auditBefore.has(row.id)).map((row) => row.reasonCode)).toContain(attack.reason);
    if (attack.alert) {
      await expect.poll(async () => (await providerStats(request)).alerts, { timeout: 2_000 }).toContain(attack.alert);
    }
    await isolated.close();
  });
}

test('invitation fragment is scrubbed before acceptance and invitation failures remain enumeration-neutral', async ({ browser, request }) => {
  await resetRateLimits();
  await control(request, {
    subject: 'pc31-invited', email: 'invited@example.test', amr: ['webauthn'], acr: 'strong'
  });
  const invited = await browser.newContext();
  const page = await invited.newPage();
  await page.goto(`${APP_ORIGIN}/invitation#token=${INVITATION_TOKEN}`);
  await expect(page).toHaveURL(`${APP_ORIGIN}/invitation`);
  expect(await page.evaluate<string>('location.hash')).toBe('');
  await page.getByRole('button', { name: 'Continuar com identidade corporativa' }).click();
  await expect(page.getByRole('heading', { name: 'Validar visitante' })).toBeVisible();
  expect(page.url()).not.toContain(INVITATION_TOKEN);
  await invited.close();

  const invalid = await browser.newContext();
  const invalidPage = await invalid.newPage();
  const invalidBefore = await securitySnapshot();
  const exchangesBeforeInvalid = (await providerStats(request)).tokenExchanges;
  await invalidPage.goto(`${APP_ORIGIN}/invitation#token=${'Z'.repeat(43)}`);
  await invalidPage.getByRole('button', { name: 'Continuar com identidade corporativa' }).click();
  await expect(invalidPage).toHaveURL(`${APP_ORIGIN}/invitation`);
  await expect(invalidPage.getByText('Este convite não está disponível. Solicite um novo convite à administração.'))
    .toBeVisible();
  expect(await securitySnapshot()).toEqual(invalidBefore);
  expect((await providerStats(request)).tokenExchanges).toBe(exchangesBeforeInvalid);
  expect(await invalidPage.locator('body').innerText()).not.toMatch(/expired|unknown|email|token/i);
  await invalid.close();
});

test('post-run artifact sanitizer canary is generated for the runner gate', async () => {
  expect(process.env.PC31_E2E_BROWSER_READY).toBe('true');
  await mkdir(path.resolve('test-results'), { recursive: true });
  await writeFile(path.resolve('test-results/redaction-canary.txt'),
    `https://example.invalid/callback?code=${ARTIFACT_CANARY}&state=${ARTIFACT_CANARY}\n__Host-eg_session=${ARTIFACT_CANARY}`);
});
