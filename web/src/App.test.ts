import { act, createElement } from 'react';
import { createRoot, type Root } from 'react-dom/client';
import { afterEach, describe, expect, it, vi } from 'vitest';

import {
  App,
  gatehouseComplete,
  gatehouseSubmit,
  isLogoutRoute,
  parseInvitationExpiration,
  reauthenticationReturnTo,
  shareVisitorCode,
  type GatehouseState
} from './App';

let root: Root | null = null;
(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;

afterEach(async () => {
  if (root) await act(async () => root?.unmount());
  root = null;
  document.body.replaceChildren();
  vi.restoreAllMocks();
});

async function renderApp(path: string) {
  window.history.replaceState(null, '', path);
  const container = document.createElement('div');
  document.body.append(container);
  root = createRoot(container);
  await act(async () => {
    root!.render(createElement(App));
    await Promise.resolve();
    await Promise.resolve();
  });
  return container;
}

const oldSession = {
  account: { id: 'account', displayName: 'Pessoa' },
  memberships: [
    { id: 'provider', role: 'provedor', tenantId: null, tenantLabel: null, residentId: null, residentLabel: null },
    { id: 'gate', role: 'portaria', tenantId: 'tenant', tenantLabel: 'Edifício', residentId: null, residentLabel: null }
  ],
  activeMembershipId: 'provider',
  activeTenantId: null,
  csrfToken: 'c'.repeat(43),
  expiresAt: '2030-01-01T00:00:00.000Z',
  idleExpiresAt: '2030-01-01T00:00:00.000Z'
};

describe('gatehouse request state', () => {
  it('clears the previous result while a new validation is in flight', () => {
    const previous: GatehouseState = {
      requestId: 4,
      busy: false,
      result: { allowed: true, guest: { name: 'Ana' } },
      message: ''
    };
    expect(gatehouseSubmit(previous, 5)).toEqual({ requestId: 5, busy: true, result: null, message: '' });
  });

  it('ignores a stale response after a newer validation starts', () => {
    const current = gatehouseSubmit({ requestId: 4, busy: false, result: null, message: '' }, 5);
    expect(gatehouseComplete(current, 4, { allowed: true })).toBe(current);
    expect(gatehouseComplete(current, 5, { allowed: false })).toMatchObject({
      requestId: 5,
      busy: false,
      result: { allowed: false }
    });
  });
});

it('recognizes both logout confirmation documents', () => {
  expect(isLogoutRoute('/logout')).toBe(true);
  expect(isLogoutRoute('/logout-all/continue')).toBe(true);
  expect(isLogoutRoute('/app')).toBe(false);
});

it('preserves the logout-all continuation destination for every reauthentication retry', () => {
  expect(reauthenticationReturnTo('/logout-all/continue')).toBe('/logout-all/continue');
  expect(reauthenticationReturnTo('/logout')).toBe('/app');
  expect(reauthenticationReturnTo('/app')).toBe('/app');
});

describe('visitor invitations', () => {
  it('accepts only a valid future expiration selected by the resident', () => {
    expect(parseInvitationExpiration('2026-08-25T10:30', new Date('2026-08-25T10:00:00').getTime()))
      .toBe(new Date('2026-08-25T10:30').toISOString());
    expect(parseInvitationExpiration('2026-08-25T09:30', new Date('2026-08-25T10:00:00').getTime())).toBeNull();
    expect(parseInvitationExpiration('')).toBeNull();
  });

  it('uses Web Share first and falls back to the clipboard visibly', async () => {
    const share = vi.fn().mockResolvedValue(undefined);
    const writeText = vi.fn().mockResolvedValue(undefined);
    await expect(shareVisitorCode('123456', { share, clipboard: { writeText } } as never)).resolves.toBe('shared');
    expect(writeText).not.toHaveBeenCalled();

    share.mockRejectedValueOnce(new Error('unavailable'));
    await expect(shareVisitorCode('654321', { share, clipboard: { writeText } } as never)).resolves.toBe('copied');
    expect(writeText).toHaveBeenCalledWith('654321');
  });
});

describe('application transitions', () => {
  it.each(['500', 'network'] as const)('never restores the old role after a successful rotation and %s bootstrap failure', async (failure) => {
    let sessionCalls = 0;
    let settleBootstrap!: () => void;
    const pendingBootstrap = new Promise<Response>((resolve, reject) => {
      settleBootstrap = () => failure === '500'
        ? resolve(new Response(JSON.stringify({ error: 'unavailable' }), { status: 500 }))
        : reject(new TypeError('network unavailable'));
    });
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (input) => {
      const url = String(input);
      if (url === '/auth/session') {
        sessionCalls += 1;
        return sessionCalls === 1
          ? new Response(JSON.stringify(oldSession), { status: 200 })
          : pendingBootstrap;
      }
      if (url === '/condominios') return new Response(JSON.stringify([]), { status: 200 });
      if (url === '/auth/tenant') return new Response(null, { status: 204 });
      throw new Error(`Unexpected request: ${url}`);
    });
    const container = await renderApp('/app');
    expect(container.textContent).toContain('Condomínios');

    const contextNavigation = [...container.querySelectorAll('button')]
      .find((button) => button.textContent?.trim() === '02Contexto')!;
    await act(async () => contextNavigation.click());
    const gateContext = [...container.querySelectorAll('button')]
      .find((button) => button.textContent?.includes('Edifício'))!;
    await act(async () => {
      gateContext.click();
      await Promise.resolve();
      await Promise.resolve();
    });
    expect(container.textContent).toContain('Verificando sessão');
    expect(container.textContent).not.toContain('Condomínios');
    expect(container.textContent).not.toContain('Pessoa');

    await act(async () => {
      settleBootstrap();
      await pendingBootstrap.catch(() => undefined);
      await Promise.resolve();
    });
    expect(container.textContent).toContain('Serviço indisponível');
    expect(container.textContent).not.toContain('Condomínios');
    expect(container.textContent).not.toContain('Pessoa');
  });

  it('renders the authenticated shell on /login and focuses headings after page changes', async () => {
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (input) => {
      if (String(input) === '/auth/session') return new Response(JSON.stringify(oldSession), { status: 200 });
      if (String(input) === '/condominios') return new Response(JSON.stringify([]), { status: 200 });
      throw new Error(`Unexpected request: ${String(input)}`);
    });
    const container = await renderApp('/login');
    expect(container.textContent).toContain('Condomínios');
    expect(container.textContent).not.toContain('Entrar na plataforma');
    expect(document.activeElement?.textContent).toBe('Condomínios');

    const contextNavigation = [...container.querySelectorAll('button')]
      .find((button) => button.textContent?.trim() === '02Contexto')!;
    await act(async () => contextNavigation.click());
    expect(document.activeElement?.textContent).toBe('Trocar contexto');
  });

  it('starts an invalid or missing invitation as unavailable without a continue action', async () => {
    const container = await renderApp('/invitation#token=invalid');
    expect(container.textContent).toContain('Este convite não está disponível');
    expect(container.textContent).not.toContain('Continuar com identidade corporativa');
    expect(container.querySelector<HTMLAnchorElement>('a[href="/login"]')).not.toBeNull();
  });
});
