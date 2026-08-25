import { afterEach, describe, expect, it, vi } from 'vitest';

import {
  acceptInvitation,
  administrativeInvitationLink,
  ApiError,
  classifyAuthError,
  getSession,
  pageForRole,
  request,
  setAuthFailureHandler,
  takeInvitationToken
} from './api';

afterEach(() => {
  setAuthFailureHandler(null);
  vi.restoreAllMocks();
});

describe('credential handling', () => {
  it('removes an invitation fragment synchronously and posts it without browser storage', async () => {
    const token = 'a'.repeat(43);
    const events: string[] = [];
    const replaceState = vi.fn(() => events.push('scrubbed'));
    const fetchMock = vi.spyOn(globalThis, 'fetch').mockImplementation(async (_url, init) => {
      events.push('posted');
      expect(init?.credentials).toBe('same-origin');
      expect(init?.redirect).toBe('manual');
      expect(init?.body).toBe(JSON.stringify({ token, returnTo: '/app' }));
      return new Response(JSON.stringify({ navigateTo: 'https://identity.example.test/start' }), { status: 200 });
    });
    const value = takeInvitationToken({ hash: `#token=${token}`, pathname: '/invitation', search: '' }, { replaceState });
    expect(value).toBe(token);
    expect(replaceState).toHaveBeenCalledWith(null, '', '/invitation');
    await acceptInvitation(value!);
    expect(events).toEqual(['scrubbed', 'posted']);
    expect(fetchMock).toHaveBeenCalledOnce();
  });

  it('keeps CSRF in module memory and adds it only to unsafe JSON requests', async () => {
    const session = { account: { id: 'a', displayName: 'A' }, memberships: [], activeMembershipId: 'm', activeTenantId: null,
      csrfToken: 'c'.repeat(43), expiresAt: '', idleExpiresAt: '' };
    const fetchMock = vi.spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(new Response(JSON.stringify(session), { status: 200 }))
      .mockResolvedValueOnce(new Response(null, { status: 204 }));
    await getSession();
    await request('/auth/logout', { method: 'POST' });
    const init = fetchMock.mock.calls[1]![1]!;
    expect(init.credentials).toBe('same-origin');
    expect(new Headers(init.headers).get('x-csrf-token')).toBe(session.csrfToken);
    expect(new Headers(init.headers).get('content-type')).toBe('application/json');
  });

  it('reports authenticated 401 and 403 responses through one auth failure channel', async () => {
    const handler = vi.fn();
    setAuthFailureHandler(handler);
    vi.spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(new Response(JSON.stringify({ error: 'reauthentication_required' }), { status: 403 }))
      .mockResolvedValueOnce(new Response(JSON.stringify({ error: 'authentication_required' }), { status: 401 }));

    await expect(request('/restricted')).rejects.toMatchObject({ status: 403, code: 'reauthentication_required' });
    await expect(request('/restricted')).rejects.toMatchObject({ status: 401, code: 'authentication_required' });
    expect(handler).toHaveBeenCalledTimes(2);
  });

  it('lets callers handle expected authorization responses without changing global auth state', async () => {
    const handler = vi.fn();
    setAuthFailureHandler(handler);
    const session = { account: { id: 'a', displayName: 'A' }, memberships: [], activeMembershipId: 'm', activeTenantId: null,
      csrfToken: 'c'.repeat(43), expiresAt: '', idleExpiresAt: '' };
    vi.spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(new Response(JSON.stringify(session), { status: 200 }))
      .mockResolvedValueOnce(new Response(JSON.stringify({ error: 'reauthentication_required' }), { status: 403 }));
    await getSession();

    await expect(request('/auth/logout-all', {
      method: 'POST',
      handleAuthFailureLocally: true
    })).rejects.toMatchObject({ status: 403, code: 'reauthentication_required' });
    expect(handler).not.toHaveBeenCalled();
  });
});

describe('explicit authentication states', () => {
  it('distinguishes expiry, reauthentication, assurance, throttling, and service failure', () => {
    expect(classifyAuthError(new ApiError(401, 'authentication_required'), false)).toBe('unauthenticated');
    expect(classifyAuthError(new ApiError(401, 'authentication_required'), true)).toBe('session-expired');
    expect(classifyAuthError(new ApiError(403, 'reauthentication_required'), true)).toBe('reauth-required');
    expect(classifyAuthError(new ApiError(403, 'insufficient_mfa'), true)).toBe('mfa-insufficient');
    expect(classifyAuthError(new ApiError(403, 'forbidden'), true)).toBe('membership-unavailable');
    expect(classifyAuthError(new ApiError(429, 'limited', 12), true)).toBe('rate-limited');
    expect(classifyAuthError(new ApiError(503), false)).toBe('bootstrap-unavailable');
  });

  it('creates an administrative invitation URL with the token only in the fragment', () => {
    const token = 'b'.repeat(43);
    const link = new URL(administrativeInvitationLink('https://office.example.test', token));
    expect(link.pathname).toBe('/invitation');
    expect(link.search).toBe('');
    expect(link.hash).toBe(`#token=${token}`);
  });
});

it('maps every role to an explicit real-data surface', () => {
  expect(['provedor', 'sindico', 'morador', 'portaria'].map((role) => pageForRole(role as never)))
    .toEqual(['condominiums', 'people', 'guests', 'validation']);
});
