export type Role = 'provedor' | 'sindico' | 'morador' | 'portaria';

export type Membership = {
  id: string;
  role: Role;
  tenantId: string | null;
  tenantLabel: string | null;
  residentId: string | null;
  residentLabel: string | null;
};

export type Session = {
  account: { id: string; displayName: string };
  memberships: Membership[];
  activeMembershipId: string;
  activeTenantId: string | null;
  csrfToken: string;
  expiresAt: string;
  idleExpiresAt: string;
};

let csrfToken: string | null = null;
let authFailureHandler: ((error: ApiError) => void) | null = null;

export type AuthStateName = 'unauthenticated' | 'session-expired' | 'bootstrap-unavailable' | 'rate-limited'
  | 'reauth-required' | 'mfa-insufficient' | 'membership-unavailable';

export class ApiError extends Error {
  constructor(readonly status: number, readonly code = 'unavailable', readonly retryAfterSeconds: number | null = null) {
    super(code);
  }
}

async function parseResponse<T>(response: Response, handleAuthFailureLocally = false): Promise<T> {
  if (!response.ok) {
    if (response.status === 401) csrfToken = null;
    let code = 'unavailable';
    try { code = String((await response.json() as { error?: unknown }).error ?? code); } catch { /* generic */ }
    const retry = Number(response.headers.get('retry-after'));
    const error = new ApiError(response.status, code, Number.isSafeInteger(retry) && retry > 0 ? retry : null);
    if (!handleAuthFailureLocally && (response.status === 401 || response.status === 403)) authFailureHandler?.(error);
    throw error;
  }
  return response.status === 204 ? undefined as T : response.json() as Promise<T>;
}

export async function getSession() {
  const response = await fetch('/auth/session', { credentials: 'same-origin', headers: { Accept: 'application/json' } });
  const session = await parseResponse<Session>(response);
  csrfToken = session.csrfToken;
  return session;
}

export async function request<T>(path: string, options: {
  method?: 'GET' | 'POST' | 'DELETE';
  body?: unknown;
  headers?: Record<string, string>;
  signal?: AbortSignal;
  handleAuthFailureLocally?: boolean;
} = {}) {
  const method = options.method ?? 'GET';
  const unsafe = method !== 'GET';
  if (unsafe && !csrfToken) throw new ApiError(401, 'authentication_required');
  const response = await fetch(path, {
    method,
    signal: options.signal,
    credentials: 'same-origin',
    headers: {
      Accept: 'application/json',
      ...(unsafe ? { 'Content-Type': 'application/json', 'X-CSRF-Token': csrfToken! } : {}),
      ...options.headers
    },
    ...(unsafe ? { body: JSON.stringify(options.body ?? {}) } : {})
  });
  return parseResponse<T>(response, options.handleAuthFailureLocally);
}

export function clearSessionMemory() {
  csrfToken = null;
}

export function setAuthFailureHandler(handler: ((error: ApiError) => void) | null) {
  authFailureHandler = handler;
}

export function classifyAuthError(error: unknown, hadSession: boolean): AuthStateName {
  if (!(error instanceof ApiError)) return 'bootstrap-unavailable';
  if (error.status === 401) return hadSession ? 'session-expired' : 'unauthenticated';
  if (error.status === 429) return 'rate-limited';
  if (error.status >= 500) return 'bootstrap-unavailable';
  if (error.status === 403 && error.code === 'reauthentication_required') return 'reauth-required';
  if (error.status === 403 && /mfa|assurance/i.test(error.code)) return 'mfa-insufficient';
  if (error.status === 403) return 'membership-unavailable';
  return 'bootstrap-unavailable';
}

export function takeInvitationToken(location: Pick<Location, 'hash' | 'pathname' | 'search'>, history: Pick<History, 'replaceState'>) {
  const fragment = new URLSearchParams(location.hash.startsWith('#') ? location.hash.slice(1) : '');
  const token = fragment.get('token');
  history.replaceState(null, '', `${location.pathname}${location.search}`);
  return token && /^[A-Za-z0-9_-]{43}$/.test(token) ? token : null;
}

export async function acceptInvitation(token: string) {
  const response = await fetch('/auth/invitations/accept', {
    method: 'POST',
    credentials: 'same-origin',
    redirect: 'manual',
    headers: { Accept: 'application/json', 'Content-Type': 'application/json' },
    body: JSON.stringify({ token, returnTo: '/app' })
  });
  return parseResponse<{ navigateTo: string }>(response);
}

export function pageForRole(role: Role) {
  return ({ provedor: 'condominiums', sindico: 'people', morador: 'guests', portaria: 'validation' } as const)[role];
}

export function administrativeInvitationLink(origin: string, token: string) {
  if (!/^[A-Za-z0-9_-]{43}$/.test(token)) throw new Error('Invalid invitation token');
  const url = new URL('/invitation', origin);
  url.hash = `token=${encodeURIComponent(token)}`;
  return url.toString();
}
