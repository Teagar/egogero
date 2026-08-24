# ADR 0001: Human Authentication With OIDC and Opaque Application Sessions

- Status: Decided
- Date: 2026-08-24
- Decision owner: Egogero architecture
- Scope: Human authentication architecture only
- Related work: PC-20

## Scope

This ADR decides the architecture and implementation contracts for human
authentication. It does not implement authentication, add dependencies, change
the database, or expose endpoints. Runtime work must be delivered by the
follow-up cards in the rollout section after this ADR is validated.

Humans are provider operators, condominium managers, residents, and gatehouse
operators. Gatehouse devices remain non-human principals authenticated by their
existing Bearer API keys.

## Context

The service already authorizes an `AuthenticatedIdentity` with one role and a
tenant scope. It also has a common `Authenticator` interface and a device
authenticator that turns a device Bearer API key into a gatehouse identity.
Human login must fit those boundaries without making a browser hold a device
credential or making a device emulate a browser session.

The application is multi-tenant. Authentication establishes who the principal
is; local account and membership records establish which tenant and role that
principal may use. Claims from an external identity provider never directly
grant an Egogero role or condominium.

## Decision

Use a managed OpenID Connect (OIDC) provider as the source of human
authentication. Use Authorization Code Flow with PKCE. After a successful OIDC
callback, Egogero issues its own high-entropy opaque browser session in a secure
cookie. Egogero remains the authority for account status, condominium
memberships, roles, session revocation, and authorization.

The initial session store is PostgreSQL. Device Bearer API keys remain unchanged
and separate. A composite authenticator selects a browser-session authenticator
or the existing device authenticator and returns a discriminated common
identity to the existing RBAC authorization layer.

This choice deliberately avoids owning passwords, password hashes, password
reset secrets, and MFA enrollment. It also avoids putting OIDC access tokens or
ID tokens in the browser after the callback.

## Decision Matrix

Scores are 1 (poor) through 5 (best). Weighted totals make the selected option
reproducible rather than implicit.

| Criterion | Weight | Application-owned credentials | Managed OIDC | Rationale |
| --- | ---: | ---: | ---: | --- |
| Credential breach exposure | 5 | 2 | 5 | OIDC keeps passwords and recovery factors outside Egogero. |
| MFA and recovery maturity | 5 | 2 | 5 | A managed provider supplies tested MFA and recovery controls. |
| Delivery speed | 4 | 2 | 4 | OIDC needs integration but not a complete credential system. |
| Operational burden | 4 | 1 | 4 | Own credentials require continuous abuse, reset, and hash-policy operations. |
| Availability independence | 3 | 5 | 3 | Own credentials avoid an external login dependency; existing sessions still work during an OIDC outage. |
| Vendor portability | 3 | 5 | 3 | Standard OIDC is portable, but provider policy and subject migration still cost work. |
| Fine-grained local authorization | 5 | 5 | 5 | Both options can keep RBAC and tenant membership local. |
| Local development simplicity | 2 | 4 | 3 | OIDC requires a local mock, while explicit dev identity remains available. |
| Auditability | 3 | 3 | 5 | Provider events plus application session and authorization events give stronger evidence. |
| Weighted total |  | **104** | **146** | Managed OIDC is selected. |

### Rejected Alternative: Application-Owned Credentials

Benefits would be independence from an identity provider, full control of the
login UI, and simpler offline development. Costs are materially higher:
Egogero would own password hashing policy, breached-password checks, reset-token
abuse, MFA enrollment and recovery, account enumeration defenses, and security
support. Those are not differentiators for the access-control product.

### Selected Alternative Tradeoffs

OIDC adds an external trust dependency and recurring provider cost. New login
is unavailable during a provider outage, although established Egogero sessions
continue until their local expiry. Provider portability is protected by storing
the issuer and subject as an external identity rather than using email as the
account key. Local role and tenant assignment remains under Egogero control.

## Trust Boundaries and Assets

Trust boundaries:

1. The user's browser is untrusted. Script-readable data and request inputs are
   attacker-controlled.
2. The public TLS edge terminates HTTPS and forwards only normalized requests to
   Egogero. Production trusts forwarded scheme and client IP only from named
   proxy addresses.
3. The Egogero application is trusted to validate OIDC responses, issue and
   verify sessions, enforce CSRF, and map local authorization.
4. PostgreSQL is a restricted trust zone containing account, membership,
   session metadata, and audit records. It never stores raw session or CSRF
   tokens.
5. The managed OIDC provider is trusted only for human authentication facts. It
   is not trusted to assign an Egogero tenant or role.
6. Devices are untrusted network clients with a distinct credential domain.
   Their Bearer API keys never cross into the browser-session path.

Protected assets are session tokens, OIDC authorization responses, account and
membership state, recovery operations, tenant data, device API keys, audit
evidence, and signing/client secrets.

## Browser Contract

### OIDC Login

- `GET /auth/login?returnTo=<relative-path>` begins Authorization Code Flow with
  PKCE using a fresh 256-bit state, nonce, and PKCE verifier.
- `returnTo` must be an allowlisted same-origin relative path. Invalid values
  become `/`; absolute and protocol-relative URLs are rejected.
- A one-time `OidcLoginTransaction` stores hashes of state, nonce, and PKCE
  verifier plus `returnTo`, creation time, and ten-minute expiry. It is consumed
  atomically at callback and cannot be replayed.
- `GET /auth/callback` validates exact issuer, audience/client ID, signature,
  state, nonce, PKCE, authorization-code single use, and provider time claims.
  Clock skew allowance is 60 seconds.
- The callback never accepts an access token or ID token supplied by application
  JavaScript. Provider tokens are used server-side only and discarded once the
  required identity claims are read.
- Successful callback rotates any supplied application session and returns a
  `303` redirect to the stored `returnTo`. Failure consumes the login
  transaction, creates no session, emits an audit event, and redirects to a
  generic same-origin login error page.

### Session Cookie

The application creates 32 random bytes with a cryptographically secure random
generator. The base64url value is opaque and has at least 256 bits of entropy.
Only `SHA-256(token)` is stored. The cookie is:

```text
Set-Cookie: __Host-eg_session=<opaque-token>; Path=/; HttpOnly; Secure; SameSite=Lax
```

`__Host-` forbids `Domain` and requires `Path=/` and `Secure`. Production never
relaxes these attributes. Responses that set or clear authentication cookies
use `Cache-Control: no-store`. Session tokens are redacted from logs and traces.

`SameSite=Lax` permits the top-level OIDC callback while blocking most ambient
cross-site unsafe requests. It is defense in depth, not the sole CSRF control.

### CSRF

Each session receives a separate 32-byte random CSRF secret. Only its SHA-256
digest is stored. `GET /auth/session` returns the raw CSRF value in a
`Cache-Control: no-store` JSON response after authenticating the HttpOnly
session. The frontend keeps it in memory, not local storage, and sends it as
`X-CSRF-Token` on `POST`, `PUT`, `PATCH`, and `DELETE`.

For every unsafe cookie-authenticated request the application requires all of:

- an exact constant-time CSRF digest match;
- `Origin` equal to the configured public application origin, with a same-origin
  `Referer` fallback only for user agents that omit `Origin`;
- a non-simple JSON content type for JSON endpoints; and
- a route that never mutates state on `GET`, `HEAD`, or `OPTIONS`.

Missing or invalid evidence returns `403` without performing the action. OIDC
callback state/nonce validation protects the callback; it does not use the
application CSRF header. Bearer-authenticated device requests do not use cookie
CSRF because browsers do not attach their Authorization header ambiently.

### Browser API

| Endpoint | Authentication | Result |
| --- | --- | --- |
| `GET /auth/login` | none | Creates login transaction and redirects to OIDC. |
| `GET /auth/callback` | OIDC state/code | Creates local session and redirects with `303`. |
| `GET /auth/session` | session cookie | Returns `{ account, memberships, activeTenantId, csrfToken, expiresAt, idleExpiresAt }`. |
| `POST /auth/tenant` | session + CSRF | Selects one authorized membership and rotates the session. |
| `POST /auth/logout` | session + CSRF | Revokes current session and clears the cookie. Idempotent. |
| `POST /auth/logout-all` | session + CSRF + recent authentication | Increments account session version and revokes all sessions. |
| `GET /auth/recovery` | none | Redirects to the configured provider recovery flow. |
| `POST /auth/reauthenticate` | session + CSRF | Starts OIDC reauthentication with `prompt=login` and `max_age=0`. |

Errors never reveal whether an email, issuer subject, or account exists.

## Data Contracts

The names below are implementation contracts. The schema card may adapt casing
to Prisma conventions but must retain the constraints and semantics.

### `HumanAccount`

| Field | Contract |
| --- | --- |
| `id` | UUID primary key; becomes `AuthenticatedIdentity.id`. |
| `displayName` | User-facing name, updated explicitly or from approved provider claims. |
| `status` | `invited`, `active`, `suspended`, or `disabled`. Only `active` authenticates. |
| `sessionVersion` | Non-negative integer; increment revokes every existing session. |
| `createdAt`, `updatedAt` | Server timestamps. |
| `disabledAt` | Required when disabled; null otherwise. |

Email is profile and notification data, not a stable authentication key.

### `ExternalIdentity`

| Field | Contract |
| --- | --- |
| `id` | UUID primary key. |
| `accountId` | Required foreign key to `HumanAccount`. |
| `issuer` | Exact normalized HTTPS OIDC issuer. |
| `subject` | Exact OIDC `sub`; case-sensitive and never reassigned. |
| `email`, `emailVerified` | Last approved provider profile values; not authorization inputs. |
| `createdAt`, `lastLoginAt` | Server timestamps. |

`(issuer, subject)` is unique. One account may have multiple external identities
only through an audited administrative link operation requiring recent MFA.

### `HumanMembership`

| Field | Contract |
| --- | --- |
| `id` | UUID primary key. |
| `accountId` | Required foreign key to `HumanAccount`. |
| `condominioId` | Required for `sindico`, `morador`, and `portaria`; null only for `provedor`. |
| `role` | Existing role: `provedor`, `sindico`, `morador`, or `portaria`. |
| `residentId` | Required only for a `morador`; identifies the existing resident record. |
| `status` | `invited`, `active`, or `disabled`. Only `active` authorizes. |
| `createdAt`, `disabledAt` | Server timestamps. |

Unique active membership is enforced on `(accountId, condominioId, role)`.
Provider membership is unique per account and requires `condominioId = null`.
All other roles require a live condominium. Tenant selection can choose only an
active membership.

### `BrowserSession`

| Field | Contract |
| --- | --- |
| `id` | UUID primary key for administration and audit, never sent as credential. |
| `tokenDigest` | Unique 32-byte SHA-256 digest of the opaque cookie. |
| `csrfDigest` | 32-byte SHA-256 digest of the CSRF token. |
| `accountId` | Required account foreign key. |
| `accountSessionVersion` | Snapshot checked against `HumanAccount.sessionVersion`. |
| `activeMembershipId` | Required active membership for tenant-scoped users; provider membership for provider users. |
| `createdAt`, `lastSeenAt` | Server timestamps. `lastSeenAt` updates at most once per five minutes. |
| `idleExpiresAt` | Sliding expiry, never later than `absoluteExpiresAt`. |
| `absoluteExpiresAt` | Fixed at issuance. |
| `authenticatedAt` | Time of the last full OIDC authentication/MFA assertion. |
| `revokedAt`, `revokeReason` | Null while active; set atomically on revocation. |
| `ipPrefix`, `userAgentHash` | Minimized risk signals, never hard binding inputs. |

Indexes cover unique `tokenDigest`, `(accountId, revokedAt)`, and
`(idleExpiresAt, absoluteExpiresAt)`. Session and login-transaction rows are
hard-deleted 30 days after expiry or revocation; security audit events remain
under the audit retention policy.

### `OidcLoginTransaction`

Contains unique state digest, nonce digest, encrypted PKCE verifier, return path,
created time, expiry, and consumed time. Encryption uses an application key from
the secret manager. Expired or consumed rows are deleted after 24 hours.

### `AuthenticationAuditEvent`

Append-only fields are event ID, timestamp, event type, outcome, account ID when
known, external identity ID when known, session ID when known, membership and
tenant when relevant, actor identity, request correlation ID, normalized IP
prefix, user-agent hash, reason code, and structured non-secret metadata. Update
and delete permissions are denied to the application database role.

## Identity and RBAC Mapping

The common identity becomes explicitly discriminated:

```ts
type AuthenticatedIdentity =
  | {
      principalType: 'human';
      id: string; // HumanAccount.id, except resident ownership uses residentId
      accountId: string;
      role: 'provedor';
      condominioIds: null;
      authMethod: 'oidc-session' | 'development';
      sessionId: string;
    }
  | {
      principalType: 'human';
      id: string; // residentId for morador, accountId for other human roles
      accountId: string;
      role: 'sindico' | 'morador' | 'portaria';
      condominioIds: readonly [string];
      authMethod: 'oidc-session' | 'development';
      sessionId: string;
    }
  | {
      principalType: 'device';
      id: string; // Dispositivo.id
      role: 'portaria';
      condominioIds: readonly [string];
      authMethod: 'device';
    };
```

The session authenticator reloads account, membership, and tenant status on
every authenticated request. It returns null when the account, membership, or
tenant is disabled/deleted, the session is revoked/expired, or its version is
stale. The RBAC layer continues to check existing permissions and tenant scope.
For resident ownership checks, `id` maps to `HumanMembership.residentId`, not to
the external OIDC subject.

The composite authenticator uses unambiguous credential routing:

- a valid `__Host-eg_session` cookie invokes only the human session
  authenticator;
- an `Authorization: Bearer egdev_...` header invokes only the device
  authenticator;
- requests presenting both fail with `400 ambiguous_credentials` and are
  audited; and
- no human OIDC token is accepted as an API Bearer token.

## Session Lifecycle

### Issuance and Rotation

A session is issued only after a valid OIDC callback and an active local account
with at least one active membership. Unknown external identities receive a
generic access-not-provisioned result; callback does not create an account.
Provisioning is administrative and explicit.

Session creation and rotation run in one database transaction. Rotation revokes
the old session before issuing the new token. Rotation occurs after login,
tenant/role switch, privilege elevation, account recovery, identity-link change,
and reauthentication. Concurrent rotations allow only one winner.

### Expiration

- Absolute lifetime: 12 hours from issuance.
- Inactivity lifetime: 30 minutes from last qualifying request.
- `lastSeenAt` and `idleExpiresAt` are extended at most once every five minutes
  to avoid a write per request.
- Recent authentication required for logout-all, identity linking, membership
  administration, and other designated sensitive actions: OIDC authentication
  no more than 10 minutes old.
- Server time is authoritative. Expired sessions fail closed with `401`, are
  marked expired asynchronously, and cause the browser cookie to be cleared.

### Logout and Revocation

Current logout atomically sets `revokedAt`/reason before clearing the cookie.
It is successful even if the session is already absent. Logout-all increments
`HumanAccount.sessionVersion` and revokes all known sessions in the same
transaction. Incrementing the version makes a session invalid even if bulk row
updates are delayed.

Disabling an account increments its session version and disables every
membership. Disabling one membership revokes sessions using that membership.
Deleting or disabling a condominium revokes all associated human sessions.
Device revocation continues to clear the device key digest independently.

Administrative session lists expose session ID, creation/last-use times,
coarsened device description, and revocation state, never token digests.

## PostgreSQL First and Redis Migration Gate

PostgreSQL is initially the sole session source of truth. Verification performs
one indexed digest lookup joined to account, membership, and condominium state.
Metrics must separately record session-lookup latency, database time, hit/miss,
revocation latency, and write volume without principal or token labels.

Redis adoption begins only when either condition is observed in production for
seven consecutive days at expected peak load:

1. session verification p95 exceeds 20 ms for at least 15 minutes on three or
   more days after query/index tuning; or
2. session verification consumes at least 30% of database read load and the
   database exceeds 60% CPU at peak on three or more days.

Before migration, load testing must show that Redis reduces session-verification
p95 by at least 50%, preserves a revocation propagation SLO of five seconds, and
survives the tested peak at 2x headroom.

Migration uses a phased write-through design:

1. PostgreSQL remains authoritative while Redis shadow reads are compared.
2. Session create, rotate, extend, and revoke write PostgreSQL then Redis; a
   transactional outbox retries failed cache invalidations.
3. Reads use Redis only after parity is at least 99.99% for seven days. A cache
   miss reads PostgreSQL; Redis errors fall back to PostgreSQL with bounded
   concurrency.
4. PostgreSQL retains durable session metadata, account session versions, and
   audit events. Redis stores only expiring active-session projections, with TTL
   no later than absolute expiry.

Rollback disables Redis reads and returns to PostgreSQL. Because PostgreSQL
remains durable and every Redis value is reconstructible, rollback loses no
revocation or audit state.

## Recovery, MFA, and Account Lifecycle

### Credential Recovery

Recovery is owned by the OIDC provider. `/auth/recovery` redirects to the
provider's configured recovery route and accepts no account identifier. The
provider must enforce verified recovery channels, anti-enumeration responses,
rate limits, and MFA recovery policy. Egogero sends no password-reset email and
stores no reset token.

The login transaction marks recovery intent. After recovery, its callback must
include fresh authentication. Egogero increments `sessionVersion`, revokes all
local sessions, issues one new session, and records
`credential_recovery_observed`. Production provider selection also requires a
signed recovery-event webhook so recovery started directly at the provider
revokes local sessions. Webhooks are verified by signature, timestamp, replay
ID, and issuer allowlist, are processed idempotently, and fail into a monitored
retry queue. Missing the five-second revocation SLO pages the security operator.

### MFA

MFA is mandatory at the OIDC provider for every human role. `Provedor`,
`sindico`, and `portaria` accounts must enroll a phishing-resistant
WebAuthn/passkey factor. Residents may use WebAuthn/passkeys or TOTP. TOTP is the
privileged-role fallback only during a documented WebAuthn outage, and SMS is
recovery-only, never a primary factor. The selected production provider must be
capable of enforcing these role policies.

The callback requires an `amr`/`acr` value matching the configured policy for
the selected role. A session cannot switch into a role with a stronger policy
without OIDC reauthentication. Egogero never invents MFA state from a local
flag.

### Provisioning and Deactivation

An authorized provider or manager creates an account invitation and membership
for an exact tenant and role. Invitation acceptance binds the first validated
`(issuer, subject)` after verified provider email matches the invitation. The
invitation is one-time, expires after 24 hours, and is stored as a digest.
Automatic just-in-time account creation from arbitrary OIDC login is forbidden.

Role changes create/disable memberships and rotate affected sessions. Tenant
transfer is a new membership plus explicit old-membership disable, never a
tenant ID update in place. Deactivation is effective on the next request and
must meet a five-second revocation SLO when Redis is later enabled.

## Rate Limiting and Abuse Controls

Initial distributed counters live in PostgreSQL; the Redis migration may move
only counters while preserving keys and limits. Limits are evaluated on
normalized proxy-derived client IP plus action-specific dimensions:

| Action | Limit | Response |
| --- | --- | --- |
| Start login | 20 per IP per 5 minutes | `429` with bounded `Retry-After`. |
| OIDC callback failures | 30 per IP per 10 minutes | Consume transaction; `429` after limit. |
| Session creation | 10 per account per 15 minutes | Require reauthentication and alert on repeat. |
| Recovery redirect | 20 per IP per hour | Generic `429`; no account signal. |
| Invitation acceptance | 10 per IP and 5 per invitation per hour | Exponential backoff, then consume at expiry. |
| CSRF/authentication failures | 60 per IP per minute | `429`; security event on sustained abuse. |

Provider-side brute-force and recovery limits are also mandatory. Application
limits do not replace them. Counters exclude raw emails, subjects, cookies, and
API keys. A global emergency limiter protects the callback and session store.

## Audit Events

The application emits immutable success and failure events for:

- login started, callback succeeded/failed, and access not provisioned;
- session issued, rotated, expired, current logout, logout-all, and
  administrative revocation;
- CSRF failure, ambiguous credentials, invalid session, and rate limiting;
- recovery observed and reauthentication succeeded/failed;
- account invited, activated, suspended, disabled, or restored;
- external identity linked/unlinked;
- membership created, role changed, disabled, or tenant switched;
- MFA policy rejection; and
- OIDC configuration or key-set validation failure.

Events use reason codes and correlation IDs. They never include authorization
codes, provider tokens, session/CSRF values or digests, client secrets, device
API keys, or complete recovery data. Security alerts cover repeated callback
failure, cross-tenant membership denial, provider configuration drift,
revocation SLO breach, and unusual session creation.

## Secret and Key Rotation

- OIDC discovery and JWKS are fetched only from the configured exact HTTPS
  issuer. JWKS is cached according to response policy, refreshed on unknown
  `kid` with a cooldown, and fails closed if a valid signing key is unavailable.
- OIDC client secrets and login-transaction encryption keys live in the secret
  manager, never environment files committed to Git or PostgreSQL plaintext.
- Rotation keeps current and previous client/encryption keys during a 24-hour
  overlap. New writes use the current key; reads identify key version and accept
  only active versions. Rotation is rehearsed every 90 days and performed
  immediately after suspected disclosure.
- Opaque session tokens and CSRF tokens need no signing key. Their random values
  are one-way digested before storage; rotation means issuing a new session.
- Existing device API-key HMAC secret management remains a separate key domain.
  Human-key rotation cannot change device credential verification and vice
  versa.

## Threat Model

| Threat | Required mitigation and failure behavior |
| --- | --- |
| Session theft | TLS, `__Host-` HttpOnly Secure cookie, no token logging, short idle/absolute expiry, rotation, revocation. Stolen active tokens remain possible until expiry/revocation, so sensitive actions require recent auth. |
| Session fixation | Ignore unknown pre-login cookies; atomically revoke supplied valid session and issue a fresh random token after callback or privilege change. |
| CSRF | SameSite Lax plus synchronizer token, exact Origin/Referer validation, JSON content type, and no unsafe GET. Failure is `403` with no mutation. |
| XSS | HttpOnly session, CSRF token only in memory, strict CSP in frontend work, contextual output encoding, no provider token in browser. XSS can act as the user, so CSP and dependency controls remain mandatory. |
| Brute force and enumeration | Managed-provider controls, generic responses, application distributed limits, exponential backoff, and audit alerts. |
| OIDC mix-up or forged token | Exact issuer/audience, state, nonce, PKCE, signature, time, and redirect URI checks; no dynamic issuer from request input. |
| Callback replay | One-time transaction consumed atomically and authorization code handled once; duplicate callback fails generically. |
| Recovery takeover | Provider verified channels and MFA recovery, recent authentication, all-session revocation, and recovery audit/alerts. |
| Stale authorization | Reload local account, membership, tenant, and session version per request; deactivation fails closed. |
| Cross-tenant access | Provider claims never grant tenancy; composite unique membership constraints and RBAC scope checks; tenant ID is derived from active membership. |
| Revocation race | Atomic session-version increment, row revocation, transaction/outbox cache invalidation, and five-second propagation SLO. |
| Key compromise or rotation drift | Secret manager versions, overlap window, rehearsed rotation, JWKS `kid` validation, configuration alerts, and fail-closed verification. |
| Credential confusion | Discriminated principal type, strict cookie-versus-device routing, reject both credentials, never accept human OIDC Bearer tokens. |
| Database disclosure | Store only high-entropy token digests, encrypt PKCE verifier, least-privilege roles, immutable audit permissions, backups encrypted. |
| Malicious proxy headers | Trust forwarding headers only from allowlisted proxies; otherwise use direct connection data. |

## Production and Development Behavior

Production and staging require HTTPS, a configured exact OIDC issuer/client,
secret-manager keys, trusted proxy allowlists, secure cookies, distributed rate
limits, and persistent audit storage. Startup fails if any required control is
missing. There is no password fallback, default user, development header, or
cookie-security downgrade in production.

Development has two explicit modes:

1. Preferred: a local mock OIDC issuer using the same authorization-code, PKCE,
   callback, session, and CSRF path as production.
2. Test-only identity headers: enabled only by both `NODE_ENV=development` and
   an explicit flag, accepted only from loopback, and rejected if any forwarded
   client headers are present. The resulting identity has
   `authMethod='development'`, is visibly logged, and cannot run in staging or
   production.

Local HTTP cannot use the production `__Host-` cookie contract. End-to-end
authentication tests therefore run through local HTTPS. Unit tests may inject
an `Authenticator` directly and do not claim to test browser cookie security.

## End-to-End Flows

`[TB]` marks a trust-boundary crossing.

### Login

```text
Browser (untrusted)      Egogero              PostgreSQL           OIDC provider
       | GET /auth/login    |                       |                    |
       |------------------->| hash state/nonce/PKCE |                    |
       |                    |---------------------->| store, 10m expiry  |
       | 302 + state/PKCE   |                       |                    |
       |<-------------------|                       |                    |
       | [TB] authorize + PKCE ---------------------------------------->|
       |<-------------------------------- [TB] code + state ------------|
       | GET callback       |                       |                    |
       |------------------->| consume transaction  |                    |
       |                    |---------------------->| atomic one-time    |
       |                    | [TB] exchange code, validate issuer/JWKS ->|
       |                    |<---------------- verified subject/MFA ----|
       |                    | map subject to active local membership     |
       |                    |---------------------->| create session     |
       | 303 + secure opaque cookie                 |                    |
       |<-------------------|                       |                    |
```

Any state, nonce, PKCE, issuer, signature, time, account, membership, or MFA
failure creates no session and returns the same generic browser error.

### Authenticated Request

```text
Browser                 Egogero authenticator     PostgreSQL       RBAC/handler
   | cookie + CSRF [TB]          |                    |                |
   |---------------------------->| SHA-256(token)     |                |
   |                             |------------------->| session + live |
   |                             |<-------------------| account/member |
   |                             | build human identity                |
   |                             |------------------------------------>|
   |                             |                     tenant/role check|
   |<----------------------------| response or 401/403                 |
```

Unsafe requests fail before the handler when CSRF or origin validation fails.
Expired, revoked, stale-version, or disabled state returns `401`; authenticated
but unauthorized tenant/role returns `403`.

### Current and Global Revocation

```text
Human/admin            Egogero                  PostgreSQL          Redis (later)
    | logout + CSRF [TB]  |                         |                    |
    |-------------------->| revoke current OR       |                    |
    |                     | increment sessionVersion + revoke rows       |
    |                     |------------------------>| commit + outbox    |
    |                     |                         |------ invalidate -->|
    | clear cookie        |                         |                    |
    |<--------------------| audit result            |                    |
```

If later Redis invalidation is delayed, the account session-version check and
five-second revocation SLO apply. Logout remains idempotent. Device revocation
uses its existing API-key path and does not touch human sessions.

### Recovery

```text
Browser                 Egogero                OIDC provider       PostgreSQL
   | GET /auth/recovery     |                       |                  |
   |----------------------->| [TB] fixed recovery redirect            |
   |<-----------------------|                       |                  |
   | [TB] verified recovery + MFA ---------------->|                  |
   |<--------------------------- fresh auth code --|                  |
   | callback               | validate fresh auth  |                  |
   |----------------------->| increment sessionVersion + revoke all   |
   |                        |----------------------------------------->|
   | new rotated session    |                         audit recovery   |
   |<-----------------------|                                            |
```

An unprovisioned or disabled account receives the same generic failure as an
unknown account. No application reset token or password is involved.

## Rollout, Compatibility, and Rollback

All implementation cards below have PC-20 human validation as an entry
criterion. Device API keys and unauthenticated public invitation behavior remain
compatible throughout rollout.

### Phases

1. Add schema and immutable authentication audit storage behind no routes.
2. Add OIDC client, login transactions, callback, PostgreSQL session store, and
   browser-session authenticator behind `HUMAN_AUTH_ENABLED=false`.
3. Add CSRF/session/logout APIs and security/rate-limit tests; exercise local
   mock OIDC and staging provider.
4. Add provisioning, memberships, MFA policy mapping, recovery, reauthentication,
   and administrative revocation.
5. Integrate authenticated frontend and enable for internal provider users,
   then one pilot condominium, then 10%, 50%, and 100% of tenants. Each stage
   requires 24 hours without a critical auth incident, callback success at
   least 99.5%, and session verification p95 at most 20 ms.
6. Evaluate the explicit Redis gate only after production measurements meet it.

Rollback at phases 2-4 disables the feature flag and revokes test sessions.
Rollback during tenant rollout disables new human login for affected tenants
while preserving device access, then revokes human sessions created by the
faulty release. Database additions remain because they are additive; destructive
schema rollback is forbidden. OIDC provider configuration remains available for
the prior application release.

### Follow-up Cards

| Card scope | Depends on | Entry and completion contract |
| --- | --- | --- |
| A. Human auth schema and audit ledger | PC-20 | Add account, external identity, membership, login transaction, session, and immutable audit schema with all constraints and migration tests. |
| B. OIDC client and login transaction | A | Implement discovery/JWKS, Authorization Code + PKCE, state/nonce single use, callback validation, and mock-provider contract tests. |
| C. PostgreSQL browser session authenticator | A, B | Issue/rotate/verify opaque sessions, map live membership to the discriminated identity, and preserve device authenticator behavior. |
| D. CSRF, session, logout, and revocation API | C | Implement browser contract, expiry, logout-all versioning, origin checks, and race/security tests. |
| E. Provisioning, membership, MFA, and recovery | B, C, D | Implement invitation binding, lifecycle administration, provider recovery/reauthentication, MFA claim policy, and audit events. |
| F. Distributed auth rate limits and alerts | B, C, D | Implement the stated limits, proxy trust, metrics, redaction, and security alerts. |
| G. Authenticated frontend shell | C, D, E | Implement login/session/tenant/logout UI, in-memory CSRF handling, strict CSP, and no browser provider-token storage. |
| H. Staged production rollout | B through G | Configure production OIDC/secrets, run threat tests, canary by tenant, verify SLOs, and document rollback evidence. |
| I. Redis session projection | H plus migration gate | Implement shadow parity, outbox invalidation, fallback, load proof, and rollback only when measured criteria trigger it. |

Every later human-authentication or authenticated-frontend card must depend on
PC-20 and the specific prerequisite rows above. No implementation card may
change the credential model without superseding this ADR.

## Consequences

Positive consequences:

- Egogero does not store or verify human passwords.
- Human sessions can be revoked locally without waiting for OIDC token expiry.
- RBAC and tenant authority remain local and auditable.
- Browsers and devices share an authentication abstraction, not a credential.
- PostgreSQL supports a simple first release with an objective Redis escape
  hatch.

Negative consequences:

- New login depends on managed-provider availability and policy.
- Session verification initially adds an indexed PostgreSQL read.
- The application still owns browser-session security, CSRF, provisioning, and
  local revocation.
- OIDC provider migration requires mapping stable issuer/subject identities and
  coordinated reauthentication.

## Binary Architecture Review

The author review is complete. A delivery reviewer can repeat each check by
answering yes or no; any no rejects the ADR.

| Check | Answer | Evidence |
| --- | --- | --- |
| Does the ADR select one human identity architecture after a weighted comparison? | Yes | Decision and decision matrix. |
| Is scope architecture-only with no runtime implementation? | Yes | Scope and single documentation-only change. |
| Are cookie, opaque session, CSRF, PostgreSQL, and measurable Redis criteria explicit? | Yes | Browser contract, lifecycle, and Redis gate. |
| Are account, external identity, tenant membership, role, session, and audit contracts concrete? | Yes | Data contracts and RBAC mapping. |
| Are issuance, verification, rotation, expiry, logout, and all-session revocation decided? | Yes | Session lifecycle. |
| Are recovery, MFA, provisioning, deactivation, rate limiting, audit, and key rotation decided? | Yes | Dedicated sections for each control. |
| Do human sessions coexist with device Bearer API keys without credential unification? | Yes | Identity mapping and strict credential routing. |
| Are login, authenticated request, revocation, and recovery traceable end to end? | Yes | Four trust-boundary flows. |
| Does the threat model cover theft, fixation, CSRF, XSS, brute force, recovery, revocation, rotation, and tenant isolation? | Yes | Threat-model table. |
| Are production and development differences fail-closed and explicit? | Yes | Environment behavior section. |
| Are rollout, compatibility, rollback, follow-up scope, order, and dependencies executable? | Yes | Rollout phases and card map. |
| Are all required architectural choices resolved? | Yes | Every contract in this review points to a selected behavior and numeric policy. |
