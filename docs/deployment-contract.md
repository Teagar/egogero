# Staging and production deployment contract

`deploy/environment.manifest.yaml` is the platform-agnostic variable inventory. It deliberately contains no values and does not claim integration with a secret manager. The operator must inject every secret through the selected platform and must verify that logs, rendered manifests, plans, and shell history do not expose it.

## Network assumptions

- The public application and all OIDC/recovery URLs are exact HTTPS values. `OIDC_REDIRECT_URI` is exactly `${PUBLIC_APPLICATION_ORIGIN}/auth/callback`.
- TLS terminates at a trusted reverse proxy. `TRUST_PROXY` is the narrow IP/CIDR allowlist of those proxy hops, never a wildcard. Requests outside that allowlist cannot assert `X-Forwarded-Proto`; secure gatehouse validation therefore fails with `426` over HTTP.
- The proxy must overwrite, not append from clients, `Forwarded` and `X-Forwarded-*`, pass the original HTTPS protocol, and send traffic to the container on its private network. Direct public access to the container port is forbidden.
- `DATABASE_URL` must be an absolute PostgreSQL URL. Database network encryption, server identity verification, credentials, backups, HA, and least privilege are platform responsibilities and must be confirmed before release; this repository does not provision them.

## Startup and probes

Staging and production require explicit `HUMAN_AUTH_ENABLED=true|false`. `false` is the rollback/global-disable state and requires all OIDC, session, MFA, recovery, and other human-auth variables and secrets listed under `disabled_human_auth.must_be_absent` to be absent. Nonsecret `TRUST_PROXY`, `AUTH_ALERT_ADAPTER`, and `AUTH_ALERT_TIMEOUT_MS` may remain; `AUTH_ALERT_WEBHOOK_URL` may remain only with `AUTH_ALERT_ADAPTER=https_webhook`. `LOCAL_DEVELOPMENT_AUTH` is forbidden. Configuration, invitation/idempotency/device secret fingerprints, OIDC discovery, exact metadata comparison, and initial JWKS validation all finish before listen. Device requests continue to recheck the fingerprint transactionally; startup records the successful device preflight as a cached readiness dependency.

`GET /health` is liveness and returns only `{"status":"ok"}`. `GET /ready` checks the database on every probe and requires the cached device-secret preflight. With human auth enabled it also checks the in-process result of startup metadata validation and complete OIDC/session/administration composition. It never calls the provider and failures return only `503 {"status":"unavailable"}`.

Provider metadata drift after startup does not silently change the cached readiness result and is not polled per probe. Exact issuer/endpoints/JWKS drift is detected fail-closed on the next restart/rollout; runtime JWKS key refresh remains constrained to the pinned JWKS URL. Operational monitoring must alert on provider changes and trigger a controlled restart after reviewing and updating the explicit contract.

## Deployment checklist

1. Render `deploy/environment.manifest.yaml` against the platform configuration without printing secret values.
2. Confirm exact public origin, callback registration, issuer, authorization/token/JWKS endpoints, recovery URL, webhook issuer, MFA policy, proxy CIDRs, and PostgreSQL connectivity/TLS policy with service owners.
3. Confirm all secret values are independently generated, at least 32 bytes, distinct by purpose, and absent from image layers, source, logs, manifests, and command history. Runtime comparison uses effective bytes without logging material: UTF-8 bytes for invitation/device/idempotency/OIDC-client/webhook secrets and canonical base64url-decoded bytes for PKCE/CSRF keys. Every configured domain and every keyring entry must be pairwise distinct. Text that happens to equal another value's base64url representation is not a collision unless the effective bytes are equal.
4. PKCE/CSRF decoded keys must have at least 12 distinct byte values, no single byte may occupy more than one quarter of the 32-byte key, and printable placeholder phrases are rejected. This is only a minimal degeneracy screen designed not to reject normal random 32-byte values; the deployment platform remains responsible for cryptographic generation and entropy.
5. Run `npm ci`, `npm run lint`, `npm run typecheck`, `npm test`, and `npm run build` against a fresh migrated database.
6. Build the image and run `node scripts/verify-image-contract.mjs IMAGE`. The runtime is UID/GID `node`, while every `/app` artifact is root-owned and has no write mode bit. The check also requires `web/dist` and rejects `.env` files.
7. Run `npm run db:migrate:deploy` from the immutable image as a separate pre-deploy job, then start the application only after it succeeds. Prisma and migrations are root-owned but readable/executable by `node`; application startup does not run migrations and cannot rewrite code or migration files. Run the application with a read-only root filesystem and a platform-provided ephemeral `/tmp` tmpfs if required by the runtime.
8. Deploy one instance, require readiness success, verify liveness reveals no dependency detail, then continue the rollout. Exercise login, callback, MFA-role enforcement, recovery webhook, and gatehouse HTTPS rejection. Before a human-auth canary, `AUTH_ALERT_ADAPTER=https_webhook` is mandatory and every bounded route must reach and be acknowledged by its real operator destination; the runtime default `stdout` is suitable only for local/provider-neutral plumbing, not rollout readiness.
9. For rollback, deploy the prior immutable release with its compatible secrets. To globally disable human auth, set `HUMAN_AUTH_ENABLED=false` and remove every variable listed under `disabled_human_auth.must_be_absent` in the same release; do not leave partial secrets. Only the three required non-human secret domains are compared in disabled mode. The nonsecret proxy and alert variables listed under `may_remain` may stay, with the manifest's webhook/adapter condition preserved.

## Rotation rehearsal

PKCE and CSRF keyrings accept the current version and optionally exactly the immediately previous version. New PKCE transactions and new/re-encrypted CSRF material always use current; previous exists only to finish data emitted before rollout.

1. Generate new values outside this repository and stage them only in a migrated disposable rehearsal database/environment. Run `RUN_DATABASE_TESTS=true DATABASE_URL=... npm run auth:rotation:rehearse`. The command refuses to run without the database flags and executes production parsers, an OIDC provider/store double with persisted PKCE ciphertext, and the real PostgreSQL browser-session store with persisted CSRF ciphertext. It emits no raw key values.
2. Keep overlap for at least the maximum old-data lifetime plus rollout/rollback time: PKCE 10 minutes; CSRF 12 hours. Use a longer documented operational margin if sessions can be delayed. Verify new database rows use current and old rows remain readable.
3. After the overlap and rollback window, stage current only and rerun the rehearsal before deployment. Securely destroy the retired value after all rollback releases that require it are ineligible.
4. If a key is compromised, remove it immediately. If current is compromised, generate the next version, stage that version alone, and rerun the rehearsal; existing material encrypted by the removed key fails closed and affected sessions/transactions must restart.

OIDC client-secret rehearsal models a provider that accepts old and new credentials concurrently: register new, prove both, deploy new, then revoke old. The real external provider must support that overlap; otherwise schedule a coordinated maintenance window, because this repository cannot make provider credential changes atomic. A rollback release must retain a provider-valid credential.

Recovery webhook verification accepts up to three explicit key versions. Stage old plus new, switch the sender to the new `X-Recovery-Key-Version`, verify a uniquely identified canary reaches durable acknowledgement, wait beyond the five-minute signature window and sender retry window, then remove the old version. A version is part of the signed canonical value, so it cannot be swapped in transit. Never retire a credential while an eligible rollback release or sender retry still requires it.
