# Human authentication rollout readiness and runbook

## Decision

The integrated application revision `e087b46` is ready for local and CI verification but is **not ready for a real staging canary**.

PC-30 through PC-33 provide tenant gates, transactional human-session rollback, browser threat tests, deployment preflight, bounded telemetry, and a conservative evaluator. Those controls were validated locally against 25 migrations, 179 backend/PostgreSQL tests, 17 frontend tests, 14 Chromium HTTPS/OIDC scenarios, the four-scenario key-rotation rehearsal, and the immutable image contract.

That evidence is synthetic. It does not satisfy a staging stage, a 24-hour window, or an operator acknowledgement. Promotion remains blocked until every item under **Canary blockers** is closed with real evidence.

## Non-negotiable rules

- PostgreSQL remains authoritative.
- Device API keys and public visitor invitations remain available during human-auth promotion and rollback.
- Schema rollback is forbidden; migrations remain additive.
- Every stage gets a new, contiguous 24-hour evidence window.
- Promotion requires zero critical incidents, callback success at least 99.5%, session verification p95 at most 20 ms, and at least 100 callbacks and 100 session samples.
- Evaluator exit `1` is failure and exit `2` is inconclusive. Neither permits promotion.
- Synthetic snapshots, screenshots, partial windows, and data reconstructed from the telemetry stream are not rollout evidence.
- Redis remains disabled. Evaluation can begin only after one of the ADR production triggers is measured for seven consecutive days.

## Canary blockers

| Blocker | Required closure | Accountable owner |
| --- | --- | --- |
| Alert delivery defaults to process stdout and can acknowledge before an operator receives it | Configure a real externally monitored adapter and record an acknowledged smoke event for every bounded route | Security operations |
| Critical incident taxonomy does not include cross-tenant denial, provider configuration drift, revocation-SLO breach, or unusual session creation | Add bounded event types, emission, routes, snapshot counting, critical classification, and evaluator tests | Application security |
| Rollout administration does not require authentication within the last ten minutes | Enforce recent OIDC authentication for every global or tenant policy mutation and add route/database tests | Backend authentication |
| Direct rollout CLI trusts any holder of runtime database credentials and only attributes the change to the supplied provider UUID | Run it only through a separately authenticated, approved, least-privileged deployment identity with immutable operator binding, or change the command contract to carry verifiable operator authorization | Security and deployment platform |
| Readiness does not verify that the authoritative global policy exists and is valid | Add a cached/startup or database readiness dependency and prove missing/corrupt policy returns generic `503` | Backend authentication and SRE |
| Process instance identity is generated internally while inventory must be independent | Inject a stable UUIDv4 from the orchestrator and produce lifecycle inventory independently of snapshots | Deployment platform |
| Production has no durable snapshot sink or stage partition contract | Provide access-controlled durable JSONL collection with bounded delivery and an immutable partition per stage | Observability/SRE |
| Alert configuration was absent from the environment inventory | Render and validate the `AUTH_ALERT_*` entries now listed in `deploy/environment.manifest.yaml` | Deployment platform |
| No real staging origin, OIDC client, secret manager, proxy CIDRs, PostgreSQL security evidence, pilot tenant, or named responders | Supply and approve each dependency without committing or printing secret values | Rollout owner |
| ADR abuse limits differ from implementation, and invitation acceptance has no dedicated distributed policy | Reconcile the decision or implementation and add the invitation IP/invitation limits before external exposure | Application security |
| Recovery webhook has no monitored retry queue or five-second revocation paging | Implement and exercise retry, expiry, paging, and timing evidence | Identity and security operations |

A blocker is closed only by an immutable change reference plus the evidence named above. A risk acceptance does not turn missing 24-hour or security evidence into a pass.

## ADR control and evidence matrix

`Local` means repository tests or a disposable local environment. `Real` means evidence required from staging or production.

| ADR requirement or threat | Control | Local evidence | Real evidence and owner |
| --- | --- | --- | --- |
| OIDC code flow, state, nonce, PKCE, exact issuer/audience/signature/time | `src/oidc.ts` pins endpoints and consumes one-time transactions | `test/oidc.test.ts`, `test/oidc-db.test.ts`, browser attack matrix | Provider metadata, registered callback, JWKS and callback run; Identity owner |
| Callback replay and mix-up | Atomic state consumption and exact response issuer | Callback replay, state and issuer browser scenarios | Provider-correlated staging replay/mix-up exercise; AppSec and Identity |
| Session theft and fixation | Opaque 256-bit cookie, digest-only storage, secure `__Host-` attributes, rotation | `test/sessions*.test.ts`, fixation browser scenario | TLS-edge cookie inspection and redacted log/trace sample; AppSec |
| CSRF and XSS | Encrypted per-family CSRF, exact Origin/Referer, JSON-only mutations, strict CSP, memory-only frontend token | Session, frontend and browser boundary tests | Staging proxy-origin exercise and CSP/log monitoring; AppSec and Frontend |
| Stale authorization and revocation race | Every request reloads account/membership/tenant; policy locks and set-based revocation | Human administration and rollout concurrency tests | Deactivation and rollback timing drill; Backend and SRE |
| Cross-tenant access | Local memberships and tenant scope remain authoritative | RBAC, provisioning and rollout isolation tests | Pilot/non-pilot negative exercise and routed incident evidence; AppSec |
| Credential confusion | Browser cookie and `egdev_` Bearer routes are discriminated; both fail as ambiguous | Credential-router and browser tests | Staging browser/device coexistence exercise; Backend and QA |
| Key compromise and rotation drift | Purpose-separated keyrings, startup preflight, pairwise secret-domain checks | Deployment tests and four-scenario rotation rehearsal | Secret-manager records, provider overlap/cutover and recovery-webhook canary; Security and Identity |
| Database disclosure | Digest-only credentials, authenticated ciphertext and immutable audit | PostgreSQL schema and crypto tests | PostgreSQL TLS, least privilege, encrypted backup and restore evidence; DBA |
| Malicious proxy headers | Narrow `TRUST_PROXY`, normalized IP, HTTPS enforcement | Proxy and browser harness tests | Exact CIDRs, overwrite behavior and direct-port denial; Network/SRE |
| Recovery takeover | Fresh provider auth, session-version revocation and signed replay-safe webhook | Human-administration and recovery tests | Provider recovery policy, retry queue, acknowledgement and five-second timing; Identity/SecOps |
| MFA by role and sensitive reauthentication | Callback `amr`/`acr` policy and reauthentication intent | OIDC, administration, session and browser role-switch tests | Provider-enforced WebAuthn/TOTP policy and ten-minute sensitive-action exercise; Identity |
| Explicit provisioning and invitation binding | Digest-only one-time 24-hour invitation with exact verified email and local membership | Human-administration and browser invitation tests | Pilot invitation issue/accept/expiry evidence without PII; Product operations and Identity |
| Session expiry and lifecycle | 30-minute idle, 12-hour absolute, bounded touch, rotation and family revocation | Session unit/database tests | Staging expiry/rotation timing and multi-tab behavior; Backend and QA |
| Immutable audit and retention | Append-only authentication audit plus cleanup contracts for transient auth rows | Schema/database and retention tests | Application-role privilege inspection, retention job record and restricted export policy; DBA/Security |
| Ninety-day key rotation | Current/previous keyrings and disposable integration rehearsal | Rotation rehearsal and configuration tests | Dated secret-manager/provider rotation record at least every 90 days; Security/Identity |
| Abuse and enumeration | PostgreSQL counters, generic responses and bounded labels | Rate-limit and unknown-account/invitation tests | Reconciled ADR limits, provider limits, alert acknowledgements and load evidence; Abuse/Security |
| 24-hour promotion gate | Versioned snapshots, independent inventory, conservative histogram and evaluator | `test/auth-rollout.test.ts` | Real orchestrator inventory, durable snapshots and evaluator output per stage; SRE |
| Rollback isolation | Scoped/global policy transitions revoke only ineligible human sessions | High-cardinality and lock-order PostgreSQL tests | Staging rollback drill plus device/public-path checks; SRE and Backend |

No requirement without an owner and evidence may be marked complete.

## Responsibility matrix

| Activity | Responsible | Accountable | Consulted | Informed |
| --- | --- | --- | --- | --- |
| Immutable build and additive migration | Release engineer | Release owner | DBA | On-call |
| OIDC registration, policy and health | Identity engineer | Identity owner | Security | Release owner |
| TLS edge, proxy overwrite and private network | Network engineer | Infrastructure owner | Security | Release owner |
| Secret generation and rotation | Security engineer | Security owner | Identity, Release | On-call |
| Pilot tenant and eligible population | Product operations | Rollout owner | Tenant support | Security |
| Policy mutation and rollback | Rollout operator | Rollout/incident commander | Security, DBA | Support |
| Snapshot sink and independent inventory | Observability engineer | SRE owner | Deployment platform | Rollout owner |
| Gate evaluation | SRE operator | Rollout owner | Security, Identity, DBA | Support |
| Incident response and tenant communication | Incident and support leads | Incident commander | Security, Product | Affected tenants |
| Promotion approval | Rollout owner | Service owner | Security, SRE, Identity | Operational owners |

Named people, alternates, escalation channels, and change windows must replace these role names before staging.

## Preflight

Use a reviewed source checkout for source scripts and tests. The immutable runtime image contains compiled `dist/` files, not TypeScript `src/` files.

```sh
set -eu
umask 077

: "${IMAGE:?immutable image reference required}"
: "${ACTOR_ACCOUNT_ID:?active externally bound provider UUID required}"
: "${PILOT_TENANT_ID:?pilot condominium UUID required}"
: "${PUBLIC_APPLICATION_ORIGIN:?exact HTTPS origin required}"
: "${EVIDENCE_ROOT:?restricted evidence directory required}"

test ! -e "$EVIDENCE_ROOT" && test ! -L "$EVIDENCE_ROOT"
mkdir -m 0700 "$EVIDENCE_ROOT"
test -d "$EVIDENCE_ROOT" && test ! -L "$EVIDENCE_ROOT"
npm ci
npm run lint
npm run typecheck
npm test
npm run test:e2e
npm run test:e2e:sanitize
npm run build
docker build -t "$IMAGE" .
node scripts/verify-image-contract.mjs "$IMAGE"
```

Run migrations as a separate platform job from the immutable image. The placeholder below is not a standalone shell command: the orchestrator must inject `DATABASE_URL` from its secret reference without placing the value in arguments, logs, shell history, or evidence.

```text
platform-job run --image "$IMAGE" --secret-ref DATABASE_URL --entrypoint npm -- run db:migrate:deploy
```

Run the key rehearsal only against a migrated disposable database:

```sh
RUN_DATABASE_TESTS=true npm run auth:rotation:rehearse
```

Verify generic probes through the public edge:

```sh
curl --fail --silent --show-error "$PUBLIC_APPLICATION_ORIGIN/health"
curl --fail --silent --show-error "$PUBLIC_APPLICATION_ORIGIN/ready"
```

Expected responses are `{"status":"ok"}` and `{"status":"ready"}`. With human auth enabled, process startup and readiness require one valid global rollout policy; missing or inconsistent policy prevents startup/readiness with only generic external failure. Human-auth-disabled deployments do not query that policy. Before promotion, separately prove provider login, MFA role enforcement, recovery webhook acknowledgement, proxy overwrite, direct-port denial, device validation, and public invitation validation.

## Policy command

From the source checkout:

```sh
npm run auth:rollout -- \
  --actor "$ACTOR_ACCOUNT_ID" \
  --scope global \
  --state internal-provider
```

From the immutable image:

```sh
node dist/src/jobs/set-human-auth-rollout.js \
  --actor "$ACTOR_ACCOUNT_ID" \
  --scope global \
  --state internal-provider
```

Scopes are `global` or `tenant:<uuid>`. States are `disabled`, global-only `internal-provider`, `pilot --cohort 10|50|100`, and `enabled`. Unknown, duplicate, missing, or inapplicable arguments fail without a policy change.

Every command also requires `HUMAN_AUTH_ROLLOUT_AUTHORIZATION_TOKEN` as a masked environment secret. A separately authenticated approval job must insert one `HumanAuthDeploymentAuthorization` row using a database identity that can only insert authorizations, never mutate policy. The row binds the exact provider actor, scope, state, cohort and approval reference, expires within ten minutes, and is consumed atomically once. The application role cannot mint approvals. Never place the token in arguments, logs or evidence. Browser policy mutation requires OIDC authentication within ten minutes and sends stale sessions through the existing reauthentication flow.

## Promotion sequence

### 1. Internal provider

Assert the migration default:

```sh
node dist/src/jobs/set-human-auth-rollout.js \
  --actor "$ACTOR_ACCOUNT_ID" --scope global --state internal-provider
```

Verify provider login/session/CSRF/admin/logout, generic denial for non-provider callback binding, device access, public invitations, externally acknowledged alerts, and durable snapshots. Start a new 24-hour partition after the policy commit.

### 2. Pilot tenant

While non-provider access remains globally closed, reconcile the complete authoritative tenant-policy inventory: the pilot must be the only tenant with an allowing policy and every stale non-pilot allowing policy must be changed to `disabled`. Verify the policy extract and expected eligible/denied counts, then prepare the pilot:

```sh
node dist/src/jobs/set-human-auth-rollout.js \
  --actor "$ACTOR_ACCOUNT_ID" --scope "tenant:$PILOT_TENANT_ID" --state enabled
```

Open globally only after that reconciliation is approved:

```sh
node dist/src/jobs/set-human-auth-rollout.js \
  --actor "$ACTOR_ACCOUNT_ID" --scope global --state enabled
```

Only tenants with an allowing tenant policy become eligible. Verify pilot success, non-pilot denial, provider access, device access, public invitations, MFA and logout. Start a new partition after the final policy commit.

Prefer a pilot in bucket 1 through 10 so narrowing to 10% does not revoke its sessions:

```sh
node --input-type=module -e \
  'import { humanAuthTenantCohort } from "./dist/src/human-auth-rollout.js";
   console.log(humanAuthTenantCohort(process.argv[1]));' \
  "$PILOT_TENANT_ID"
```

### 3. Ten percent

```sh
node dist/src/jobs/set-human-auth-rollout.js \
  --actor "$ACTOR_ACCOUNT_ID" --scope global --state pilot --cohort 10
```

Install allowing tenant policies only from the authoritative eligible-tenant inventory. Start the stage window after the last policy write.

### 4. Fifty percent

Before widening global access, reconcile allowing tenant policies from the authoritative bucket-1-through-50 inventory. Verify expected eligible and denied tenant counts, then apply:

```sh
node dist/src/jobs/set-human-auth-rollout.js \
  --actor "$ACTOR_ACCOUNT_ID" --scope global --state pilot --cohort 50
```

Start a new 24-hour partition after the final tenant-policy/global-policy write.

### 5. One hundred percent

Before widening global access, reconcile allowing tenant policies for the complete authoritative target inventory and verify expected eligible and denied counts. Then apply:

```sh
node dist/src/jobs/set-human-auth-rollout.js \
  --actor "$ACTOR_ACCOUNT_ID" --scope global --state pilot --cohort 100
```

Start the stage window after the final policy write. After a passing 24-hour gate, reconcile the complete authoritative tenant-policy inventory once more: every target tenant must allow access and every excluded tenant must be disabled or absent. Verify expected eligible/denied counts, then normalize steady state:

```sh
node dist/src/jobs/set-human-auth-rollout.js \
  --actor "$ACTOR_ACCOUNT_ID" --scope global --state enabled
```

Every target tenant still requires an allowing tenant policy. Missing policies fail closed; stale allowing policies must never be carried into a global expansion.

## Gate evaluation

The platform must inject stable instance IDs, independently produce exact serving lifecycle inventory, and durably partition snapshots by stage. Inventory must never be inferred from snapshots. Snapshot inputs currently lack the inventory reader's `O_NOFOLLOW` and inode checks, so secure snapshot-file opening is itself a canary blocker.

The restricted evidence directory must be newly created with mode `0700`; collection and evaluation jobs must refuse symlinks, special files and pre-existing output paths. After secure snapshot input handling is implemented, run the evaluator through an approved platform job and create `evaluation.json` atomically with mode `0600`, never ordinary `>` onto an unchecked path:

```text
platform-job evaluate-auth-rollout \
  --exclusive-output "$EVIDENCE_ROOT/evaluation.json" \
  --inventory "$INVENTORY_FILE" \
  --snapshot "$SNAPSHOT_FILE_A" \
  --snapshot "$SNAPSHOT_FILE_B"
```

The job executes `node dist/src/auth-rollout.js`, retains its exit status, hashes every opened input and output, and verifies file identity and size before approval.

Exit `0` is pass, `1` is measured failure, and `2` is inconclusive. Promotion requires a complete 24-hour interval, zero critical incidents, callback success at least 99.5%, session p95 at most 20 ms, minimum sample volumes, complete expected instance cadence, and no observability, input, clock, sequence, overlap, or coverage gap.

## Evidence package

For each stage retain under restricted access:

- Git commit, immutable image digest, migration result, and rendered non-secret configuration inventory;
- policy result, policy version, aggregate revoked-session count, and restricted policy/history extracts;
- orchestrator lifecycle inventory, raw snapshot JSONL, evaluator JSON, and exit status;
- liveness/readiness results and sanitized browser report;
- alert-route external acknowledgements and dashboard/query references;
- key rehearsal and provider/recovery/proxy exercises;
- incidents, change ticket, approvers, start/end times, and communication record.

Do not retain database URLs, cookies, CSRF values, OIDC codes, tokens, session IDs, IP addresses, key material, or user PII in the package.

## Rollback

### Tenant scoped

```sh
node dist/src/jobs/set-human-auth-rollout.js \
  --actor "$ACTOR_ACCOUNT_ID" --scope "tenant:$TENANT_ID" --state disabled
```

This blocks new human access and transactionally revokes active human sessions in that tenant. Other tenants, providers, devices, and public invitations are unaffected.

### All non-provider humans

```sh
node dist/src/jobs/set-human-auth-rollout.js \
  --actor "$ACTOR_ACCOUNT_ID" --scope global --state internal-provider
```

This revokes non-provider human sessions while retaining eligible provider administration, devices, and public invitations.

### All humans

```sh
node dist/src/jobs/set-human-auth-rollout.js \
  --actor "$ACTOR_ACCOUNT_ID" --scope global --state disabled
```

This revokes provider and non-provider human sessions while preserving devices and public invitations. The CLI is the recovery path after provider browser sessions are denied.

Deploying with `HUMAN_AUTH_ENABLED=false` stops human services but does not itself write durable session revocations. Apply the policy rollback first when durable revocation is required, then remove every forbidden human-auth variable in the same deployment. Never reverse migration `0025` or another additive authentication migration.

## Tabletop scenarios

### OIDC outage or drift

1. Halt promotion and preserve current evidence.
2. Use tenant rollback only for a proven tenant-specific fault; otherwise use global `internal-provider`. Use `disabled` when provider integrity is uncertain.
3. Confirm device and public invitation paths.
4. Identity owner checks issuer, endpoints, callback registration, client state, signing keys, provider policy and incident status.
5. Review explicit metadata before a controlled restart.
6. Discard the interrupted interval and start a new 24-hour window.

### Callback SLO breach

1. Roll back the current stage immediately on evaluator reason `callback_success_below_99_5_percent`.
2. Preserve evaluator output and snapshots.
3. Identity checks provider health and callback configuration; DBA checks reservations, contention and indexes; Security reviews bounded failure classes.
4. Resume only after remediation and a new 24-hour window.

### Key compromise

1. Set global `disabled`.
2. Revoke compromised material and generate replacement outside source and shell history.
3. Remove a compromised PKCE/CSRF version immediately; affected sessions or transactions fail closed.
4. Rotate OIDC credentials at the provider with overlap or a maintenance window.
5. Pause recovery-webhook delivery for coordinated receiver/sender cutover and a unique canary.
6. Run the disposable rehearsal, deploy, verify readiness, restore `internal-provider`, and restart all gates.

### Proxy drift

1. Halt promotion and use global `internal-provider`; use `disabled` if origin or client-IP integrity is uncertain.
2. Remove direct public access and prove the edge overwrites `Forwarded` and `X-Forwarded-*`.
3. Update the narrow `TRUST_PROXY` allowlist and restart.
4. Prove an untrusted direct HTTP request cannot assert HTTPS.
5. Start a new evidence window.

### Cross-tenant observation

1. Declare a security incident and disable every known affected tenant.
2. Use global `disabled` when scope is unknown.
3. Preserve immutable audit, policy history and deployment evidence under restricted access.
4. Investigate membership constraints, session tenant binding, authorization paths and concurrent role switching.
5. Notify affected tenants through the incident commander.
6. Resume only after a corrective release, threat-suite pass, routed incident acknowledgement and a new 24-hour window.

## Communication protocol

Before a stage, publish scope, image digest, expected start/end, rollback command, operator, approver and incident channel. On hold, publish `promotion paused`, bounded evaluator reasons and next review time. On rollback, publish scope, policy version, aggregate revoked count, device/public-path status and incident reference. On recovery, publish remediation and the start of a completely new evidence window.

Never publish credentials, user details, tokens, session identifiers, raw IPs or tenant-sensitive audit data.

## Redis decision

Redis remains out of scope. Start an evaluation card only after production shows, for seven consecutive days at expected peak load, either:

1. session verification p95 above 20 ms for at least 15 minutes on three or more days after query/index tuning; or
2. session verification at least 30% of database read load while database CPU exceeds 60% at peak on three or more days.

Even then, migration requires at least 50% p95 improvement, five-second revocation propagation, 2x peak headroom, shadow parity, transactional invalidation, PostgreSQL fallback, and a tested rollback. No current evidence triggers this work.
