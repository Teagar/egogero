import { FormEvent, ReactNode, useEffect, useRef, useState } from 'react';

import {
  acceptInvitation,
  administrativeInvitationLink,
  ApiError,
  AuthStateName,
  classifyAuthError,
  clearSessionMemory,
  getSession,
  pageForRole,
  request,
  Session,
  setAuthFailureHandler,
  takeInvitationToken
} from './api';
import brandMark from './assets/brand-mark.svg?no-inline';

type Condominium = { id: string; nome: string; responsavel: string; tipo: string; timezone: string };
type Resident = { id: string; nome: string; endereco: Record<string, string | null> };
type Guest = { id: string; nome: string; email: string | null; telefone: string | null; ultimoUsoEm: string | null };
type HumanMembership = { id: string; role: string; status: string; residentId: string | null; createdAt: string };
type HumanAudit = { id: string; occurredAt: string; accessType: string; result: 'permitido' | 'negado'; invitationType: string | null; guestName: string | null };
type Resource<T> = { status: 'loading' } | { status: 'error'; message: string } | { status: 'success'; data: T };
type GateResult = { allowed: boolean; guest?: { name: string }; invitation?: { type: string } };
export type GatehouseState = { requestId: number; busy: boolean; result: GateResult | null; message: string };

const roleNames = { provedor: 'Provedor', sindico: 'Síndico', morador: 'Morador', portaria: 'Portaria' } as const;

export function gatehouseSubmit(state: GatehouseState, requestId: number): GatehouseState {
  return { ...state, requestId, busy: true, result: null, message: '' };
}

export function gatehouseComplete(state: GatehouseState, requestId: number, result: GateResult, message = ''): GatehouseState {
  return requestId === state.requestId ? { ...state, busy: false, result, message } : state;
}

export function isLogoutRoute(path: string) {
  return path === '/logout' || path === '/logout-all/continue';
}

export function reauthenticationReturnTo(path: string): '/app' | '/logout-all/continue' {
  return path === '/logout-all/continue' ? '/logout-all/continue' : '/app';
}

export function parseInvitationExpiration(value: string, now = Date.now()) {
  const expiresAt = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}$/.test(value) ? new Date(value) : null;
  return expiresAt && Number.isFinite(expiresAt.getTime()) && expiresAt.getTime() > now
    ? expiresAt.toISOString()
    : null;
}

export async function shareVisitorCode(token: string, target: Pick<Navigator, 'share' | 'clipboard'>) {
  const text = `Código de acesso do visitante: ${token}`;
  if (typeof target.share === 'function') {
    try {
      await target.share({ title: 'Código de acesso do visitante', text });
      return 'shared' as const;
    } catch { /* fall back to clipboard */ }
  }
  if (typeof target.clipboard?.writeText === 'function') {
    await target.clipboard.writeText(token);
    return 'copied' as const;
  }
  throw new Error('Sharing unavailable');
}

function genericMessage(error: unknown) {
  return error instanceof ApiError && error.status === 429
    ? 'Muitas tentativas. Aguarde e tente novamente.'
    : 'Não foi possível concluir. Tente novamente.';
}

function useResource<T>(key: string, loader: (signal: AbortSignal) => Promise<T>) {
  const [attempt, setAttempt] = useState(0);
  const [state, setState] = useState<Resource<T>>({ status: 'loading' });
  useEffect(() => {
    const controller = new AbortController();
    setState({ status: 'loading' });
    loader(controller.signal).then((data) => {
      if (!controller.signal.aborted) setState({ status: 'success', data });
    }).catch((error) => {
      if (!controller.signal.aborted) setState({ status: 'error', message: genericMessage(error) });
    });
    return () => controller.abort();
  }, [key, attempt]);
  return { state, retry: () => setAttempt((value) => value + 1) };
}

function Brand() { return <span className="brand"><img src={brandMark} alt="" />Teagar</span>; }
function Notice({ children, kind = 'error' }: { children: ReactNode; kind?: 'error' | 'success' }) { return <div className={`notice ${kind}`} role="alert">{children}</div>; }
function Empty({ children }: { children: ReactNode }) { return <div className="empty"><span className="registration" aria-hidden="true" />{children}</div>; }
function LoadingBlock({ label = 'Carregando dados autorizados...' }: { label?: string }) { return <div className="empty" aria-busy="true">{label}</div>; }
function ErrorBlock({ message, retry }: { message: string; retry: () => void }) { return <div className="notice error" role="alert"><p>{message}</p><button className="secondary" onClick={retry}>Tentar novamente</button></div>; }
function Field(props: React.InputHTMLAttributes<HTMLInputElement> & { label: string }) { const { label, ...input } = props; return <label>{label}<input required {...input} /></label>; }
function Metric({ value, label }: { value: number; label: string }) { return <div className="metric"><strong>{String(value).padStart(2, '0')}</strong><span>{label}</span></div>; }
function Page({ title, eyebrow, action, children }: { title: string; eyebrow: string; action?: ReactNode; children: ReactNode }) { const heading = useRef<HTMLHeadingElement>(null); useEffect(() => { heading.current?.focus({ preventScroll: true }); }, [title, eyebrow]); return <><header className="page-header blueprint"><div><p className="eyebrow">{eyebrow}</p><h1 ref={heading} tabIndex={-1}>{title}</h1></div>{action}</header><div className="page-content">{children}</div></>; }
function DataTable({ caption, headers, rows }: { caption: string; headers: string[]; rows: (string | null | undefined)[][] }) { return rows.length ? <div className="table-wrap"><table><caption>{caption}</caption><thead><tr>{headers.map((header) => <th key={header}>{header}</th>)}</tr></thead><tbody>{rows.map((row, index) => <tr key={index}>{row.map((cell, cellIndex) => <td key={cellIndex} data-label={headers[cellIndex]}>{cell || 'Não informado'}</td>)}</tr>)}</tbody></table></div> : <Empty>{caption}: nenhum registro disponível.</Empty>; }

function AuthStage({ children }: { children: ReactNode }) {
  return <main className="auth-stage blueprint" id="content"><a className="skip" href="#auth-card">Ir para o conteúdo</a><section className="auth-card" id="auth-card"><Brand />{children}</section></main>;
}

function LoginPage({ kind = 'login' }: { kind?: 'login' | 'error' | 'recovery' }) {
  const title = kind === 'error' ? 'Acesso indisponível' : kind === 'recovery' ? 'Recuperar acesso' : 'Entrar na plataforma';
  return <AuthStage><p className="eyebrow">OIDC / identidade corporativa</p><h1>{title}</h1><p className="muted">{kind === 'recovery' ? 'Recuperação e credenciais são administradas pelo provedor de identidade.' : 'Nenhuma senha é mantida por esta plataforma.'}</p>{kind === 'error' && <Notice>A autenticação está indisponível no momento.</Notice>}<a className="button primary" href={kind === 'recovery' ? '/auth/recovery' : '/auth/login'}>{kind === 'recovery' ? 'Continuar recuperação' : 'Continuar com identidade corporativa'}</a>{kind !== 'recovery' && <a href="/recovery">Não consigo acessar minha conta</a>}</AuthStage>;
}

function InvitationPage() {
  const [token] = useState(() => takeInvitationToken(window.location, window.history));
  const [state, setState] = useState<'ready' | 'working' | 'unavailable'>(() => token ? 'ready' : 'unavailable');
  async function submit() {
    if (!token) return setState('unavailable');
    setState('working');
    try {
      const { navigateTo } = await acceptInvitation(token);
      const destination = new URL(navigateTo);
      if (destination.protocol !== 'https:') throw new Error('Unsafe identity destination');
      window.location.assign(destination.href);
    } catch { setState('unavailable'); }
  }
  return <AuthStage><p className="eyebrow">Convite administrativo / 24 horas</p><h1>Ative seu vínculo.</h1><p className="muted">Este link provisiona acesso à plataforma. Ele não é o código de seis dígitos usado por visitantes.</p>{state === 'unavailable' ? <><Notice>Este convite não está disponível. Solicite um novo convite à administração.</Notice><a className="button secondary" href="/login">Ir para o acesso normal</a></> : <button className="primary" disabled={state === 'working'} onClick={submit}>{state === 'working' ? 'Conectando...' : 'Continuar com identidade corporativa'}</button>}</AuthStage>;
}

function SecuritySurface({ state, retry, retryAfter }: { state: AuthStateName; retry: () => void; retryAfter: number | null }) {
  const text: Record<AuthStateName, [string, string]> = {
    unauthenticated: ['Entrar na plataforma', 'Continue com a identidade corporativa para acessar seu contexto.'],
    'session-expired': ['Sessão encerrada', 'Entre novamente para continuar com segurança.'],
    'bootstrap-unavailable': ['Serviço indisponível', 'Não foi possível verificar sua sessão agora.'],
    'rate-limited': ['Acesso temporariamente limitado', retryAfter ? `Aguarde cerca de ${retryAfter} segundos antes de tentar novamente.` : 'Aguarde antes de tentar novamente.'],
    'reauth-required': ['Confirmação necessária', 'Confirme sua identidade novamente para continuar.'],
    'mfa-insufficient': ['Verificação adicional necessária', 'Seu método atual não atende à política deste contexto.'],
    'membership-unavailable': ['Contexto indisponível', 'Seu acesso ou contexto não está disponível no momento.']
  };
  const [title, message] = text[state];
  return <AuthStage><p className="eyebrow">Estado de segurança</p><h1>{title}</h1><p className="muted">{message}</p>{state === 'unauthenticated' || state === 'session-expired' ? <a className="button primary" href="/auth/login">Entrar novamente</a> : <button className="primary" onClick={retry}>Tentar novamente</button>}</AuthStage>;
}

function ProviderPage() {
  const resource = useResource('provider', (signal) => request<Condominium[]>('/condominios', { signal }));
  const [busy, setBusy] = useState(false); const [message, setMessage] = useState('');
  async function create(event: FormEvent<HTMLFormElement>) { event.preventDefault(); if (busy) return; setBusy(true); setMessage(''); const form = event.currentTarget; try { await request('/condominios', { method: 'POST', body: Object.fromEntries(new FormData(form)) }); form.reset(); resource.retry(); } catch (error) { setMessage(genericMessage(error)); } finally { setBusy(false); } }
  return <Page title="Condomínios" eyebrow="Rede / operação autorizada" action={resource.state.status === 'success' ? <span className="status">{resource.state.data.length} cadastrados</span> : undefined}><div className="split"><section className="panel signal"><h2>Novo condomínio</h2><form onSubmit={create} className="form-grid" aria-busy={busy}><Field name="nome" label="Nome" disabled={busy} /><Field name="responsavel" label="Responsável" disabled={busy} /><Field name="tipo" label="Tipo" disabled={busy} /><Field name="timezone" label="Fuso horário" defaultValue="America/Sao_Paulo" disabled={busy} /><button className="primary" disabled={busy}>{busy ? 'Cadastrando...' : 'Cadastrar condomínio'}</button></form>{message && <Notice>{message}</Notice>}</section><section><h2>Rede ativa</h2>{resource.state.status === 'loading' ? <LoadingBlock /> : resource.state.status === 'error' ? <ErrorBlock message={resource.state.message} retry={resource.retry} /> : resource.state.data.length ? <div className="card-list">{resource.state.data.map((item) => <article className="data-card" key={item.id}><p className="eyebrow">{item.tipo}</p><h3>{item.nome}</h3><p>{item.responsavel}</p><span className="mono muted">{item.timezone}</span></article>)}</div> : <Empty>Nenhum condomínio disponível.</Empty>}</section></div></Page>;
}

function ManagerPage({ tenantId }: { tenantId: string }) {
  const resource = useResource(tenantId, async (signal) => Promise.all([request<Resident[]>(`/condominios/${tenantId}/moradores`, { signal }), request<HumanMembership[]>('/admin/human/memberships', { signal })]));
  const [busy, setBusy] = useState<'resident' | 'invitation' | null>(null); const [message, setMessage] = useState('');
  const [adminLink, setAdminLink] = useState<string | null>(null); const [copyMessage, setCopyMessage] = useState('');
  async function addResident(event: FormEvent<HTMLFormElement>) { event.preventDefault(); if (busy) return; setBusy('resident'); setMessage(''); const form = event.currentTarget; const data = new FormData(form); try { await request('/moradores', { method: 'POST', body: { nome: data.get('nome'), condominioId: tenantId, endereco: { bloco: data.get('bloco'), apartamento: data.get('apartamento') } } }); form.reset(); resource.retry(); } catch (error) { setMessage(genericMessage(error)); } finally { setBusy(null); } }
  async function invite(event: FormEvent<HTMLFormElement>) { event.preventDefault(); if (busy) return; setBusy('invitation'); setMessage(''); setAdminLink(null); const form = event.currentTarget; const data = new FormData(form); try { const result = await request<{ token: string }>('/admin/human/invitations', { method: 'POST', body: { displayName: data.get('displayName'), email: data.get('email'), role: 'morador', condominioId: tenantId, residentId: data.get('residentId') } }); setAdminLink(administrativeInvitationLink(window.location.origin, result.token)); form.reset(); resource.retry(); } catch (error) { setMessage(genericMessage(error)); } finally { setBusy(null); } }
  async function copyLink() { if (!adminLink) return; try { await navigator.clipboard.writeText(adminLink); setCopyMessage('Link copiado.'); } catch { setCopyMessage('Não foi possível copiar. Selecione o link manualmente.'); } }
  const data = resource.state.status === 'success' ? resource.state.data : null; const residents = data?.[0] ?? []; const memberships = data?.[1] ?? [];
  return <Page title="Pessoas" eyebrow="Condomínio / vínculos humanos">{resource.state.status === 'loading' ? <LoadingBlock /> : resource.state.status === 'error' ? <ErrorBlock message={resource.state.message} retry={resource.retry} /> : <><div className="metrics"><Metric value={residents.length} label="Moradores cadastrados" /><Metric value={memberships.filter((item) => item.status === 'active').length} label="Vínculos ativos" /></div>{message && <Notice>{message}</Notice>}{adminLink && <section className="panel signal one-time" aria-live="polite"><p className="eyebrow">Link administrativo / exibido uma vez</p><h2>Convite de 24 horas</h2><p>Este link cria acesso à plataforma. Não confunda com o código de visitante da portaria.</p><input aria-label="Link administrativo" readOnly value={adminLink} onFocus={(event) => event.currentTarget.select()} /><div className="cluster"><button className="primary" onClick={copyLink}>Copiar link</button><button className="secondary" onClick={() => { setAdminLink(null); setCopyMessage(''); }}>Descartar exibição</button></div>{copyMessage && <p className="small" role="status">{copyMessage}</p>}</section>}<div className="split"><section className="panel"><h2>Novo morador</h2><form className="form-grid" onSubmit={addResident} aria-busy={busy === 'resident'}><Field name="nome" label="Nome" disabled={Boolean(busy)} /><Field name="bloco" label="Bloco" disabled={Boolean(busy)} /><Field name="apartamento" label="Apartamento" disabled={Boolean(busy)} /><button className="primary" disabled={Boolean(busy)}>{busy === 'resident' ? 'Cadastrando...' : 'Cadastrar morador'}</button></form></section><section className="panel signal"><h2>Convidar à plataforma</h2><form className="form-grid" onSubmit={invite} aria-busy={busy === 'invitation'}><Field name="displayName" label="Nome de exibição" disabled={Boolean(busy)} /><Field name="email" label="E-mail corporativo" type="email" disabled={Boolean(busy)} /><label>Morador<select name="residentId" required disabled={Boolean(busy)}><option value="">Selecione</option>{residents.map((resident) => <option key={resident.id} value={resident.id}>{resident.nome}</option>)}</select></label><button className="primary" disabled={Boolean(busy)}>{busy === 'invitation' ? 'Criando...' : 'Criar convite de 24h'}</button></form></section></div><DataTable caption="Moradores deste condomínio" headers={['Morador', 'Endereço']} rows={residents.map((resident) => [resident.nome, [resident.endereco.bloco, resident.endereco.apartamento].filter(Boolean).join(' / ') || [resident.endereco.rua, resident.endereco.numero].filter(Boolean).join(', ')])} /><DataTable caption="Vínculos humanos deste condomínio" headers={['Papel', 'Estado', 'Criado em']} rows={memberships.map((membership) => [roleNames[membership.role as keyof typeof roleNames] ?? membership.role, membership.status, new Date(membership.createdAt).toLocaleDateString('pt-BR')])} /></>}</Page>;
}

function ResidentPage({ tenantId, residentId }: { tenantId: string; residentId: string }) {
  const base = `/condominios/${tenantId}/moradores/${residentId}`; const resource = useResource(base, (signal) => request<Guest[]>(`${base}/convidados`, { signal }));
  const [busy, setBusy] = useState<'guest' | 'issue' | 'revoke' | 'share' | null>(null); const [message, setMessage] = useState(''); const [issued, setIssued] = useState<{ id: string; guest: string; token: string } | null>(null);
  async function addGuest(event: FormEvent<HTMLFormElement>) { event.preventDefault(); if (busy) return; setBusy('guest'); setMessage(''); const form = event.currentTarget; try { await request(`${base}/convidados`, { method: 'POST', body: Object.fromEntries(new FormData(form)) }); form.reset(); resource.retry(); } catch (error) { setMessage(genericMessage(error)); } finally { setBusy(null); } }
  async function issue(event: FormEvent<HTMLFormElement>) { event.preventDefault(); if (busy || resource.state.status !== 'success') return; setBusy('issue'); setMessage(''); setIssued(null); const form = event.currentTarget; const data = new FormData(form); const guestId = String(data.get('guestId')); const expiresAt = parseInvitationExpiration(String(data.get('expiresAt') ?? '')); if (!expiresAt) { setMessage('Informe uma expiração futura válida.'); setBusy(null); return; } try { const result = await request<{ id: string; token: string }>(`${base}/convidados/${guestId}/convites`, { method: 'POST', headers: { 'Idempotency-Key': crypto.randomUUID() }, body: { tipo: data.get('tipo'), expiresAt } }); setIssued({ ...result, guest: resource.state.data.find((guest) => guest.id === guestId)?.nome ?? 'Visitante' }); form.reset(); } catch (error) { setMessage(genericMessage(error)); } finally { setBusy(null); } }
  async function revoke() { if (!issued || busy) return; setBusy('revoke'); setMessage(''); try { await request(`${base}/convites/${issued.id}`, { method: 'DELETE' }); setIssued(null); setMessage('Convite cancelado.'); } catch (error) { setMessage(genericMessage(error)); } finally { setBusy(null); } }
  async function share() { if (!issued || busy) return; setBusy('share'); setMessage(''); try { const result = await shareVisitorCode(issued.token, navigator); setMessage(result === 'shared' ? 'Código compartilhado.' : 'Código copiado.'); } catch { setMessage('Não foi possível compartilhar ou copiar. Selecione o código manualmente.'); } finally { setBusy(null); } }
  if (resource.state.status === 'loading') return <Page title="Meus convidados" eyebrow="Morador / acesso de visitantes"><LoadingBlock /></Page>;
  if (resource.state.status === 'error') return <Page title="Meus convidados" eyebrow="Morador / acesso de visitantes"><ErrorBlock message={resource.state.message} retry={resource.retry} /></Page>;
  return <Page title="Meus convidados" eyebrow="Morador / acesso de visitantes">{issued && <section className="issued panel signal" aria-live="polite"><span className="status success">Código de visitante emitido</span><h2>{issued.guest}</h2><input className="visitor-code-input" aria-label="Código de visitante" readOnly value={issued.token} onFocus={(event) => event.currentTarget.select()} /><p>Exibido somente agora. Uso único na portaria; não é um link administrativo.</p><div className="cluster"><button className="primary" disabled={Boolean(busy)} onClick={share}>{busy === 'share' ? 'Compartilhando...' : 'Compartilhar código'}</button><button className="secondary" disabled={Boolean(busy)} onClick={revoke}>{busy === 'revoke' ? 'Cancelando...' : 'Cancelar acesso'}</button></div></section>}{message && <Notice kind={/cancelado|compartilhado|copiado/.test(message) ? 'success' : 'error'}>{message}</Notice>}<div className="split"><section className="panel"><h2>Novo convidado</h2><form className="form-grid" onSubmit={addGuest} aria-busy={busy === 'guest'}><Field name="nome" label="Nome" disabled={Boolean(busy)} /><Field name="email" label="E-mail (opcional)" type="email" required={false} disabled={Boolean(busy)} /><Field name="telefone" label="Telefone (opcional)" required={false} disabled={Boolean(busy)} /><button className="primary" disabled={Boolean(busy)}>{busy === 'guest' ? 'Cadastrando...' : 'Cadastrar convidado'}</button></form></section><section className="panel signal"><h2>Emitir acesso</h2><form className="form-grid" onSubmit={issue} aria-busy={busy === 'issue'}><label>Convidado<select name="guestId" required disabled={Boolean(busy)}><option value="">Selecione</option>{resource.state.data.map((guest) => <option key={guest.id} value={guest.id}>{guest.nome}</option>)}</select></label><label>Tipo<select name="tipo" disabled={Boolean(busy)}><option value="visitante">Visitante</option><option value="prestador">Prestador</option><option value="entregador">Entregador</option></select></label><Field name="expiresAt" label="Expira em" type="datetime-local" min={new Date(Date.now() - new Date().getTimezoneOffset() * 60_000).toISOString().slice(0, 16)} disabled={Boolean(busy)} /><button className="primary" disabled={Boolean(busy)}>{busy === 'issue' ? 'Gerando...' : 'Gerar código único'}</button></form></section></div><DataTable caption="Convidados cadastrados" headers={['Nome', 'Contato', 'Último acesso']} rows={resource.state.data.map((guest) => [guest.nome, guest.email ?? guest.telefone ?? 'Não informado', guest.ultimoUsoEm ? new Date(guest.ultimoUsoEm).toLocaleString('pt-BR') : 'Ainda não utilizado'])} /></Page>;
}

function GatehousePage() {
  const resource = useResource('gatehouse', (signal) => request<HumanAudit[]>('/portaria/human/validacoes-recentes', { signal }));
  const [state, setState] = useState<GatehouseState>({ requestId: 0, busy: false, result: null, message: '' }); const requestId = useRef(0);
  async function validate(event: FormEvent<HTMLFormElement>) { event.preventDefault(); if (state.busy) return; const form = event.currentTarget; const token = String(new FormData(form).get('token') ?? ''); const nextId = ++requestId.current; setState((current) => gatehouseSubmit(current, nextId)); if (!/^[0-9]{6}$/.test(token)) { setState((current) => gatehouseComplete(current, nextId, { allowed: false }, 'Informe exatamente seis dígitos.')); return; } try { const result = await request<GateResult>('/portaria/human/convites/validar', { method: 'POST', body: { token, tipoAcesso: 'pedestre' } }); setState((current) => gatehouseComplete(current, nextId, result)); form.reset(); resource.retry(); } catch (error) { setState((current) => gatehouseComplete(current, nextId, { allowed: false }, genericMessage(error))); } }
  return <Page title="Validar visitante" eyebrow="Portaria / operador humano"><div className="split"><section className="panel signal"><h2>Código de seis dígitos</h2><form className="form-grid" onSubmit={validate} aria-busy={state.busy}><Field name="token" label="Código do visitante" inputMode="numeric" pattern="[0-9]{6}" minLength={6} maxLength={6} disabled={state.busy} /><button className="primary" disabled={state.busy}>{state.busy ? 'Validando...' : 'Validar código'}</button></form><p className="small muted">Não solicite senha, token administrativo ou credencial do morador.</p></section><section aria-live="polite" aria-busy={state.busy}>{state.result && <div className={`notice ${state.result.allowed ? 'success' : 'error'}`}><strong>{state.result.allowed ? 'Acesso autorizado' : 'Não foi possível validar o acesso'}</strong><br />{state.result.allowed ? `${state.result.guest?.name} · ${state.result.invitation?.type}` : 'Confira o código ou contate a unidade responsável.'}</div>}{state.message && <Notice>{state.message}</Notice>}<p className="small muted">A resposta é neutra para código inexistente, expirado, cancelado ou já utilizado.</p></section></div>{resource.state.status === 'loading' ? <LoadingBlock label="Carregando validações recentes..." /> : resource.state.status === 'error' ? <ErrorBlock message={resource.state.message} retry={resource.retry} /> : <DataTable caption="Últimas validações deste operador" headers={['Horário', 'Referência', 'Acesso', 'Resultado']} rows={resource.state.data.map((audit) => [new Date(audit.occurredAt).toLocaleTimeString('pt-BR', { hour: '2-digit', minute: '2-digit' }), audit.guestName ?? 'Código informado', audit.accessType, audit.result === 'permitido' ? 'Autorizado' : 'Não validado'])} />}</Page>;
}

async function prepareReauthentication(returnTo: '/app' | '/logout-all/continue') {
  const result = await request<{ navigateTo: string }>('/auth/reauthenticate', { method: 'POST', body: { returnTo } });
  if (!/^\/auth\/reauthenticate\/start\/[A-Za-z0-9_-]{43}$/.test(result.navigateTo)) throw new Error('Unsafe reauthentication route');
  window.location.assign(result.navigateTo);
}

function LogoutPage({ continueAll = false }: { continueAll?: boolean }) {
  const [busy, setBusy] = useState<'current' | 'all' | null>(null); const [message, setMessage] = useState('');
  async function logout(scope: 'current' | 'all') { if (busy) return; setBusy(scope); setMessage(''); try { await request(scope === 'all' ? '/auth/logout-all' : '/auth/logout', { method: 'POST', handleAuthFailureLocally: scope === 'all' }); clearSessionMemory(); window.location.assign('/login'); } catch (error) { if (scope === 'all' && error instanceof ApiError && error.code === 'reauthentication_required') { try { await prepareReauthentication('/logout-all/continue'); return; } catch (reauthError) { setMessage(genericMessage(reauthError)); } } else setMessage(genericMessage(error)); setBusy(null); } }
  return <AuthStage><p className="eyebrow">A04 / confirmação</p><h1>{continueAll ? 'Confirmação concluída.' : 'Sair é uma decisão.'}</h1><p className="muted">{continueAll ? 'Agora você pode encerrar todas as sessões da plataforma sem repetir a autenticação.' : 'Escolha o alcance antes de encerrar o acesso.'}</p>{message && <Notice>{message}</Notice>}<div className="panel signal logout-options">{!continueAll && <><div><h2>Este dispositivo</h2><p>Encerra apenas a sessão usada neste navegador.</p></div><button className="primary" disabled={Boolean(busy)} onClick={() => logout('current')}>{busy === 'current' ? 'Saindo...' : 'Sair deste dispositivo'}</button></>}<div><h2>Todos os dispositivos</h2><p>Encerra suas sessões da plataforma. Outros sistemas do provedor podem continuar conectados.</p></div><button className="danger" disabled={Boolean(busy)} onClick={() => logout('all')}>{busy === 'all' ? 'Encerrando...' : 'Sair de todos os dispositivos'}</button><a className="button secondary" href="/app">Continuar conectado</a></div></AuthStage>;
}

function Shell({ session, refresh }: { session: Session; refresh: () => void }) {
  const active = session.memberships.find((membership) => membership.id === session.activeMembershipId) ?? session.memberships[0]!;
  const [page, setPage] = useState(pageForRole(active.role)); const [switching, setSwitching] = useState(false); const [error, setError] = useState('');
  useEffect(() => { setPage(pageForRole(active.role)); setSwitching(false); setError(''); }, [active.id, active.role]);
  const context = active.tenantLabel ?? 'Todos os condomínios';
  const nav = active.role === 'provedor' ? [['condominiums', 'Condomínios'], ['context', 'Contexto']] : active.role === 'sindico' ? [['people', 'Pessoas'], ['context', 'Contexto']] : active.role === 'morador' ? [['guests', 'Convidados'], ['context', 'Contexto']] : [['validation', 'Validar'], ['context', 'Contexto']];
  async function switchMembership(id: string) { if (switching || id === active.id) return; setSwitching(true); setError(''); try { await request('/auth/tenant', { method: 'POST', body: { membershipId: id }, handleAuthFailureLocally: true }); refresh(); } catch (failure) { if (failure instanceof ApiError && failure.code === 'reauthentication_required') { await prepareReauthentication('/app').catch((error) => { setError(genericMessage(error)); setSwitching(false); }); return; } if (failure instanceof ApiError && failure.status === 409) { refresh(); return; } setError(genericMessage(failure)); setSwitching(false); } }
  const content = page === 'condominiums' ? <ProviderPage /> : page === 'people' ? <ManagerPage tenantId={active.tenantId!} /> : page === 'guests' ? <ResidentPage tenantId={active.tenantId!} residentId={active.residentId!} /> : page === 'validation' ? <GatehousePage /> : <Page title="Trocar contexto" eyebrow="Conta / vínculos autorizados"><div className="context-grid">{session.memberships.map((membership) => <button key={membership.id} className={`context-card ${membership.id === active.id ? 'active' : ''}`} disabled={switching} onClick={() => switchMembership(membership.id)}><span className="eyebrow">{roleNames[membership.role]}</span><strong>{membership.tenantLabel ?? 'Rede global'}</strong><small>{membership.residentLabel ?? 'Contexto administrativo'}</small></button>)}</div></Page>;
  return <div className="shell"><a className="skip" href="#content">Ir para o conteúdo</a><header className="topbar"><Brand /><div><span className="context-label">Condomínio / papel</span><strong>{context} · {roleNames[active.role]}</strong></div><details className="account-details"><summary>Conta</summary><nav aria-label="Conta"><strong>{session.account.displayName}</strong><a href="/logout">Opções de saída</a></nav></details></header><aside className="sidebar"><nav aria-label="Navegação principal">{nav.map(([key, label], index) => <button key={key} aria-current={page === key ? 'page' : undefined} onClick={() => setPage(key as never)}><span>{String(index + 1).padStart(2, '0')}</span>{label}</button>)}</nav><div className="side-context"><span className="context-label">Contexto ativo</span><strong>{context}</strong><small>{roleNames[active.role]} · {session.account.displayName}</small></div></aside><main id="content" className="shell-main">{error && <Notice>{error}</Notice>}{switching ? <Page title="Trocando contexto" eyebrow="Sessão / rotação segura"><p role="status" aria-live="polite">Trocando contexto e removendo os dados anteriores.</p><LoadingBlock label="Limpando o contexto anterior..." /></Page> : <div key={active.id}>{content}</div>}</main><nav className="mobile-nav" aria-label="Navegação móvel">{nav.map(([key, label]) => <button key={key} aria-current={page === key ? 'page' : undefined} disabled={switching} onClick={() => setPage(key as never)}>{label}</button>)}</nav></div>;
}

type AppState = { name: 'checking'; hadSession: boolean; requestId: number } | { name: 'authenticated'; session: Session } | { name: AuthStateName; retryAfter: number | null; hadSession: boolean };

export function App() {
  const path = window.location.pathname; const [state, setState] = useState<AppState>({ name: 'checking', hadSession: false, requestId: 0 }); const requestId = useRef(0);
  const beginBootstrap = (hadSession: boolean) => setState({ name: 'checking', hadSession, requestId: ++requestId.current });
  useEffect(() => {
    if (state.name !== 'checking' || ['/invitation', '/recovery', '/auth/error'].includes(path)) return;
    let current = true;
    getSession().then((session) => { if (current) setState({ name: 'authenticated', session }); }).catch((error) => { if (current) setState({ name: classifyAuthError(error, state.hadSession), retryAfter: error instanceof ApiError ? error.retryAfterSeconds : null, hadSession: state.hadSession }); });
    return () => { current = false; };
  }, [path, state.name === 'checking' ? state.requestId : -1]);
  useEffect(() => {
    if (state.name !== 'authenticated') { setAuthFailureHandler(null); return; }
    setAuthFailureHandler((error) => setState({ name: classifyAuthError(error, true), retryAfter: error.retryAfterSeconds, hadSession: true }));
    return () => setAuthFailureHandler(null);
  }, [state.name]);
  if (path === '/invitation') return <InvitationPage />;
  if (path === '/recovery') return <LoginPage kind="recovery" />;
  if (path === '/auth/error') return <LoginPage kind="error" />;
  if (state.name === 'checking') return <main className="loading" aria-busy="true"><Brand /><p>Verificando sessão...</p></main>;
  if (state.name !== 'authenticated') return <SecuritySurface state={state.name} retry={() => {
    if (state.name === 'reauth-required' || state.name === 'mfa-insufficient') {
      void prepareReauthentication(reauthenticationReturnTo(path)).catch(() => setState({ name: 'bootstrap-unavailable', retryAfter: null, hadSession: state.hadSession }));
    } else beginBootstrap(state.hadSession);
  }} retryAfter={state.retryAfter} />;
  if (path === '/logout') return <LogoutPage />;
  if (path === '/logout-all/continue') return <LogoutPage continueAll />;
  return <Shell session={state.session} refresh={() => beginBootstrap(true)} />;
}
