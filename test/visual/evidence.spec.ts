import { mkdir } from 'node:fs/promises';
import path from 'node:path';

import { expect, test, type Page, type TestInfo } from '@playwright/test';

type Role = 'provedor' | 'sindico' | 'morador' | 'portaria';
type Surface = {
  name: string;
  path: string;
  state: 'login' | 'security' | Role | 'context';
  heading: string;
};

const surfaces: Surface[] = [
  { name: 'login-oidc', path: '/login', state: 'login', heading: 'Entrar na plataforma' },
  { name: 'security-state', path: '/auth/error', state: 'security', heading: 'Acesso indisponível' },
  { name: 'shell-context', path: '/app', state: 'context', heading: 'Trocar contexto' },
  { name: 'provider', path: '/app', state: 'provedor', heading: 'Operações da rede' },
  { name: 'manager', path: '/app', state: 'sindico', heading: 'Pessoas' },
  { name: 'resident', path: '/app', state: 'morador', heading: 'Meus convidados' },
  { name: 'gatehouse', path: '/app', state: 'portaria', heading: 'Validar visitante' }
];

const memberships = [
  { id: 'visual-provider', role: 'provedor', tenantId: null, tenantLabel: null, residentId: null, residentLabel: null },
  { id: 'visual-manager', role: 'sindico', tenantId: 'visual-tenant', tenantLabel: 'Residencial Horizonte Norte', residentId: null, residentLabel: null },
  { id: 'visual-resident', role: 'morador', tenantId: 'visual-tenant', tenantLabel: 'Residencial Horizonte Norte', residentId: 'visual-resident-record', residentLabel: 'Bloco B / Unidade 804' },
  { id: 'visual-gatehouse', role: 'portaria', tenantId: 'visual-tenant', tenantLabel: 'Residencial Horizonte Norte', residentId: null, residentLabel: null }
] as const;

const activeMembership: Record<Role | 'context', string> = {
  provedor: 'visual-provider',
  sindico: 'visual-manager',
  morador: 'visual-resident',
  portaria: 'visual-gatehouse',
  context: 'visual-provider'
};

test.describe('sanitized REV. 07 visual evidence', () => {
  for (const surface of surfaces) {
    test(`${surface.name} remains responsive and safe`, async ({ page }, testInfo) => {
      const unexpectedRequests: string[] = [];
      const requestedUrls: string[] = [];
      page.on('request', (request) => requestedUrls.push(request.url()));
      await installStaticApi(page, surface.state, unexpectedRequests);
      await page.goto(surface.path);

      if (surface.state === 'context') {
        await page.locator('button[data-destination="context"]:visible').click();
      }

      const heading = page.getByRole('heading', { name: surface.heading, exact: true });
      await expect(heading).toBeVisible();
      expect(unexpectedRequests).toEqual([]);
      await assertResponsiveLayout(page, surface.state);
      await assertSingleSignalCta(page, surface.state);
      await assertReducedMotion(page);
      await assertWcagTokenContrast(page);
      await assertSanitized(page, requestedUrls);
      await captureEvidence(page, testInfo, surface.name);
      await assertKeyboardFocus(page);
    });
  }
});

async function installStaticApi(page: Page, state: Surface['state'], unexpected: string[]) {
  await page.route('**/*', async (route) => {
    const request = route.request();
    if (request.resourceType() !== 'fetch') return route.continue();
    const pathname = new URL(request.url()).pathname;
    if (pathname === '/auth/session') {
      if (state === 'login') return json(route, { error: 'authentication_required' }, 401);
      if (state === 'security') return json(route, { error: 'unavailable' }, 503);
      const role = state === 'context' ? 'context' : state;
      return json(route, {
        account: { id: 'visual-account', displayName: 'Operação Demonstrativa' },
        memberships,
        activeMembershipId: activeMembership[role],
        activeTenantId: role === 'provedor' || role === 'context' ? null : 'visual-tenant',
        csrfToken: 'visual-static-placeholder',
        expiresAt: '2030-01-01T12:00:00.000Z',
        idleExpiresAt: '2030-01-01T11:30:00.000Z'
      });
    }
    if (pathname === '/condominios') return json(route, [
      { id: 'visual-tenant', nome: 'Residencial Horizonte Norte', responsavel: 'Administração demonstrativa', tipo: 'Residencial', timezone: 'America/Sao_Paulo' },
      { id: 'visual-tenant-2', nome: 'Parque das Águas', responsavel: 'Operação regional', tipo: 'Residencial', timezone: 'America/Recife' }
    ]);
    if (pathname === '/condominios/visual-tenant/moradores') return json(route, [
      { id: 'visual-resident-record', nome: 'Morador demonstrativo', endereco: { bloco: 'B', apartamento: '804' } },
      { id: 'visual-resident-record-2', nome: 'Residente de referência', endereco: { bloco: 'A', apartamento: '1201' } }
    ]);
    if (pathname === '/admin/human/memberships') return json(route, [
      { id: 'visual-membership-1', role: 'morador', status: 'active', residentId: 'visual-resident-record', createdAt: '2026-08-01T12:00:00.000Z' },
      { id: 'visual-membership-2', role: 'portaria', status: 'invited', residentId: null, createdAt: '2026-08-02T12:00:00.000Z' }
    ]);
    if (pathname === '/condominios/visual-tenant/moradores/visual-resident-record/convidados') return json(route, [
      { id: 'visual-guest-1', nome: 'Visitante cadastrado', email: 'visitante@example.test', telefone: null, ultimoUsoEm: '2026-08-20T15:00:00.000Z' },
      { id: 'visual-guest-2', nome: 'Prestador recorrente', email: null, telefone: null, ultimoUsoEm: null }
    ]);
    if (pathname === '/portaria/human/validacoes-recentes') return json(route, [
      { id: 'visual-audit-1', occurredAt: '2026-08-29T10:41:00.000Z', accessType: 'pedestre', result: 'permitido', invitationType: 'visitante', guestName: 'Visitante identificado' },
      { id: 'visual-audit-2', occurredAt: '2026-08-29T10:33:00.000Z', accessType: 'pedestre', result: 'negado', invitationType: null, guestName: null }
    ]);
    unexpected.push(`${request.method()} ${pathname}`);
    return json(route, { error: 'visual_route_not_defined' }, 404);
  });
}

function json(route: Parameters<Parameters<Page['route']>[1]>[0], body: unknown, status = 200) {
  return route.fulfill({ status, contentType: 'application/json', body: JSON.stringify(body) });
}

async function assertResponsiveLayout(page: Page, state: Surface['state']) {
  const layout = await page.evaluate(() => {
    const viewportWidth = document.documentElement.clientWidth;
    const offenders = [...document.body.querySelectorAll<HTMLElement>('*')].filter((element) => {
      const rect = element.getBoundingClientRect();
      if (!rect.width || !rect.height) return false;
      return rect.left < -1 || rect.right > viewportWidth + 1;
    }).map((element) => `${element.tagName.toLowerCase()}.${element.className}`);
    const smallTargets = [...document.querySelectorAll<HTMLElement>('a,button,input,select,summary')].filter((element) => {
      const rect = element.getBoundingClientRect();
      if (!rect.width || !rect.height) return false;
      return rect.width < 43.5 || rect.height < 43.5;
    }).map((element) => `${element.tagName.toLowerCase()}.${element.className}`);
    return {
      documentWidth: document.documentElement.scrollWidth,
      viewportWidth,
      offenders,
      smallTargets
    };
  });
  expect(layout.documentWidth).toBeLessThanOrEqual(layout.viewportWidth);
  expect(layout.offenders).toEqual([]);
  expect(layout.smallTargets).toEqual([]);

  if (!['login', 'security'].includes(state)) {
    const desktop = await page.locator('.sidebar [data-destination]').evaluateAll((items) => items.map((item) => item.getAttribute('data-destination')));
    const mobile = await page.locator('.mobile-nav [data-destination]').evaluateAll((items) => items.map((item) => item.getAttribute('data-destination')));
    expect(mobile).toEqual(desktop);
    await expect(page.locator('.topbar-context')).toContainText(/Residencial Horizonte Norte|Todos os condomínios/);
    await expect(page.locator('.topbar-context')).toContainText(/Provedor|Síndico|Morador|Portaria/);
  }

  if (state === 'portaria' && (page.viewportSize()?.width ?? 0) <= 640) {
    await expect(page.locator('td').first()).toHaveCSS('display', 'grid');
    const tableWidth = await page.locator('table').evaluate((element) => element.getBoundingClientRect().width);
    const captionWidth = await page.locator('caption').evaluate((element) => element.getBoundingClientRect().width);
    expect(captionWidth).toBeGreaterThanOrEqual(tableWidth - 1);
  }
}

async function assertKeyboardFocus(page: Page) {
  await page.evaluate(() => (document.activeElement as HTMLElement | null)?.blur());
  await page.keyboard.press('Tab');
  const focus = await page.evaluate(() => {
    const element = document.activeElement as HTMLElement | null;
    if (!element) return null;
    const style = getComputedStyle(element);
    const rect = element.getBoundingClientRect();
    return { tag: element.tagName, outlineStyle: style.outlineStyle, outlineWidth: style.outlineWidth, top: rect.top, bottom: rect.bottom };
  });
  expect(focus).not.toBeNull();
  expect(focus!.outlineStyle).not.toBe('none');
  expect(Number.parseFloat(focus!.outlineWidth)).toBeGreaterThanOrEqual(3);
  expect(focus!.bottom).toBeGreaterThan(0);
  expect(focus!.top).toBeLessThan(page.viewportSize()!.height);
}

async function assertSingleSignalCta(page: Page, state: Surface['state']) {
  if (state !== 'sindico' && state !== 'morador') return;
  const priorities = await page.evaluate(() => {
    const signal = getComputedStyle(document.documentElement).getPropertyValue('--signal').trim();
    const signalRgb = (() => {
      const channels = signal.match(/[a-f\d]{2}/gi)!.map((channel) => Number.parseInt(channel, 16));
      return `rgb(${channels.join(', ')})`;
    })();
    const isSignal = (element: Element) => getComputedStyle(element).backgroundColor === signalRgb;
    const priorityActions = [...document.querySelectorAll('.page-content .panel.signal .form-grid > button')]
      .filter(isSignal)
      .map((element) => element.textContent?.trim());
    const auxiliaryActions = [...document.querySelectorAll('.page-content > .split > .panel:not(.signal) .form-grid > button')]
      .map((element) => ({ signal: isSignal(element), minHeight: getComputedStyle(element).minHeight }));
    return { priorityActions, auxiliaryActions };
  });
  expect(priorities.priorityActions).toHaveLength(1);
  expect(priorities.auxiliaryActions).toEqual([{ signal: false, minHeight: '44px' }]);
  await expect(page.locator('.page-title')).toBeFocused();
  await expect(page.locator('.page-title')).toHaveCSS('outline-style', 'none');
}

async function assertReducedMotion(page: Page) {
  expect(await page.evaluate(() => matchMedia('(prefers-reduced-motion: reduce)').matches)).toBe(true);
  const duration = await page.locator('a,button').filter({ visible: true }).first().evaluate((element) => getComputedStyle(element).transitionDuration);
  expect(parseDuration(duration)).toBeLessThanOrEqual(0.001);
}

async function assertWcagTokenContrast(page: Page) {
  const ratios = await page.evaluate(() => {
    const root = getComputedStyle(document.documentElement);
    const value = (name: string) => root.getPropertyValue(name).trim();
    const luminance = (hex: string) => {
      const channels = hex.match(/[a-f\d]{2}/gi)!.map((channel) => Number.parseInt(channel, 16) / 255)
        .map((channel) => channel <= 0.04045 ? channel / 12.92 : ((channel + 0.055) / 1.055) ** 2.4);
      return 0.2126 * channels[0]! + 0.7152 * channels[1]! + 0.0722 * channels[2]!;
    };
    const ratio = (foreground: string, background: string) => {
      const values = [luminance(value(foreground)), luminance(value(background))].sort((left, right) => right - left);
      return (values[0]! + 0.05) / (values[1]! + 0.05);
    };
    return [
      ratio('--ink', '--signal'),
      ratio('--blueprint', '--paper'),
      ratio('--steel', '--paper'),
      ratio('--blueprint-on-dark', '--charcoal'),
      ratio('--success-text', '--success-tint'),
      ratio('--warning-text', '--warning-tint'),
      ratio('--danger-text', '--danger-tint')
    ];
  });
  for (const ratio of ratios) expect(ratio).toBeGreaterThanOrEqual(4.5);
}

async function assertSanitized(page: Page, requestedUrls: string[]) {
  const browserState = await page.evaluate(() => ({
    localStorage: Object.values(localStorage),
    sessionStorage: Object.values(sessionStorage),
    hash: location.hash,
    search: location.search,
    visible: document.body.innerText,
    inputs: [...document.querySelectorAll<HTMLInputElement>('input')].map((input) => input.value),
    links: [...document.querySelectorAll<HTMLAnchorElement>('a')].map((anchor) => anchor.href)
  }));
  expect(await page.context().cookies()).toEqual([]);
  expect(browserState.localStorage).toEqual([]);
  expect(browserState.sessionStorage).toEqual([]);
  expect(browserState.hash).toBe('');
  expect(browserState.search).toBe('');

  const exposed = [browserState.visible, ...browserState.inputs, ...browserState.links, ...requestedUrls].join('\n');
  expect(exposed).not.toMatch(/__Host-eg_|x-csrf-token|egdev_/i);
  expect(exposed).not.toMatch(/[?&](?:code|state|nonce|token|code_verifier)=/i);
  expect(exposed).not.toMatch(/\/auth\/callback|\/invitation#/i);
  expect(exposed).not.toMatch(/(?<![A-Za-z0-9_-])[A-Za-z0-9_-]{43}(?![A-Za-z0-9_-])/);
  expect(exposed).not.toMatch(/\b\d{6}\b/);
}

async function captureEvidence(page: Page, testInfo: TestInfo, name: string) {
  if (!['desktop', 'mobile'].includes(testInfo.project.name)) return;
  const directory = path.resolve('.visual-evidence/screenshots', testInfo.project.name);
  await mkdir(directory, { recursive: true, mode: 0o700 });
  await page.screenshot({
    path: path.join(directory, `${name}.png`),
    fullPage: true,
    animations: 'disabled'
  });
}

function parseDuration(value: string) {
  if (value.endsWith('ms')) return Number.parseFloat(value) / 1000;
  return Number.parseFloat(value);
}
