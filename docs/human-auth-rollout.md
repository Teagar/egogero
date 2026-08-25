# Human authentication rollout and rollback

`HUMAN_AUTH_ENABLED=true` starts the OIDC/session infrastructure. It does not authorize a human login.
Authorization is controlled by `HumanAuthRolloutPolicy`; a missing or inconsistent applicable policy fails closed.

## Policy states

- `disabled`: deny new human authentication and deny every existing human session request.
- `internal-provider`: global-only state allowing already provisioned provider external identities. The initial OIDC
  authorization request can reach the identity provider because identity is not known yet; callback binding and
  session issue remain denied for every non-provider.
- `pilot`: allow a stable tenant cohort of exactly 10, 50, or 100 percent. The fixed algorithm is
  `sha256-tenant-v1`: SHA-256 of `sha256-tenant-v1`, a zero byte, and the tenant ID; the first unsigned 32-bit
  big-endian word modulo 100 plus one is the auditable bucket.
- `enabled`: allow the scope. Non-provider access requires both an allowing global policy and an allowing tenant
  policy. Provider membership is global and does not inherit OIDC claims.

The database starts with global `internal-provider`, which keeps every tenant closed while permitting an already
provisioned provider to administer rollout. A provider using an OIDC browser session changes policy through
`GET /admin/human-auth/rollout` and `PUT /admin/human-auth/rollout`. Mutating requests use the normal session CSRF
check. The PUT body has only `condominioId`, `state`, and `cohortPercentage`; unknown keys and non-exact cohort
values are rejected. Responses and immutable history contain no credentials or invitation/session secrets.

After a global `disabled` rollback, use the operational command because all browser sessions, including providers,
are denied: `npm run auth:rollout -- --actor <provider-account-uuid> --scope global --state internal-provider`.
The actor must be an active, externally bound provider. Tenant scopes use `tenant:<uuid>` and pilot additionally
requires `--cohort 10`, `50`, or `100`. Unknown, duplicate, or inapplicable arguments fail without changing policy.

## Rollback

Every policy change evaluates active sessions against the resulting effective global and tenant policy. It revokes
every session that is then ineligible, including `enabled` to `pilot`, pilot percentage reductions, global cohort
changes, missing tenant policy, `disabled`, and global `internal-provider`. A tenant change examines only sessions
active in that tenant; a global change examines every human session. Other eligible tenants and provider sessions
remain active. Device API keys and public visitor invitations are never examined or revoked. Repeating a policy
change is safe and only revokes sessions still active.

Policy writes take a transaction-scoped global advisory lock, then a tenant advisory lock when applicable, followed
by the policy row lock. This serializes missing-row creation and gives global/tenant rollbacks one deadlock-free
order. OIDC callback binding, invitation acceptance, handoff issue,
membership switch, session inspection, and request authentication re-evaluate policy in their database
transaction. Rollback history is protected against update, delete, and truncate by both privileges and triggers.

## In-flight requests

The linearization point is the request's transactional session authentication and rollout gate check. A business
operation whose check completed before a rollback acquired the policy lock may finish after rollback begins. The
system does not hold that Prisma transaction across a Fastify business handler. Rollback waits for earlier gate
transactions, commits the restrictive policy and revokes every resulting ineligible session before returning. Any
authentication beginning after rollback commits reads the new policy or revoked session and fails before its
business handler runs. This is the bounded residual: already authenticated work may complete; no newly
authenticated work starts after rollback commit.
