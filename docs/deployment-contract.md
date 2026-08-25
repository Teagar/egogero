# Staging and production deployment contract

`deploy/environment.manifest.yaml` is the platform-agnostic variable inventory. It deliberately contains no values and does not claim integration with a secret manager. The operator must inject every secret through the selected platform and must verify that logs, rendered manifests, plans, and shell history do not expose it.

## Network assumptions

- The public application and all OIDC/recovery URLs are exact HTTPS values. `OIDC_REDIRECT_URI` is exactly `${PUBLIC_APPLICATION_ORIGIN}/auth/callback`.
- TLS terminates at a trusted reverse proxy. `TRUST_PROXY` is the narrow IP/CIDR allowlist of those proxy hops, never a wildcard. Requests outside that allowlist cannot assert `X-Forwarded-Proto`; secure gatehouse validation therefore fails with `426` over HTTP.
- The proxy must overwrite, not append from clients, `Forwarded` and `X-Forwarded-*`, pass the original HTTPS protocol, and send traffic to the container on its private network. Direct public access to the container port is forbidden.
- `DATABASE_URL` must be an absolute PostgreSQL URL. Database network encryption, server identity verification, credentials, backups, HA, and least privilege are platform responsibilities and must be confirmed before release; this repository does not provision them.

## Startup and probes

Staging and production require explicit `HUMAN_AUTH_ENABLED=true|false`. `false` is the rollback/global-disable state and requires all human-auth variables, including secrets, to be absent. `TRUST_PROXY` may remain because it is nonsecret deployment network configuration used by device validation too. `LOCAL_DEVELOPMENT_AUTH` is forbidden. Configuration, invitation/idempotency/device secret fingerprints, OIDC discovery, exact metadata comparison, and initial JWKS validation all finish before listen. Device requests continue to recheck the fingerprint transactionally; startup records the successful device preflight as a cached readiness dependency.

`GET /health` is liveness and returns only `{"status":"ok"}`. `GET /ready` checks the database on every probe and requires the cached device-secret preflight. With human auth enabled it also checks the in-process result of startup metadata validation and complete OIDC/session/administration composition. It never calls the provider and failures return only `503 {"status":"unavailable"}`.

Provider metadata drift after startup does not silently change the cached readiness result and is not polled per probe. Exact issuer/endpoints/JWKS drift is detected fail-closed on the next restart/rollout; runtime JWKS key refresh remains constrained to the pinned JWKS URL. Operational monitoring must alert on provider changes and trigger a controlled restart after reviewing and updating the explicit contract.

## Deployment checklist

1. Render `deploy/environment.manifest.yaml` against the platform configuration without printing secret values.
2. Confirm exact public origin, callback registration, issuer, authorization/token/JWKS endpoints, recovery URL, webhook issuer, MFA policy, proxy CIDRs, and PostgreSQL connectivity/TLS policy with service owners.
3. Confirm all secret values are independently generated, at least 32 bytes, distinct by purpose, and absent from image layers, source, logs, manifests, and command history. Runtime checks reject obvious placeholders, repeated-character values, application-secret reuse, duplicate keyring bytes, and PKCE/CSRF cross-domain reuse; the deployment platform remains responsible for cryptographic randomness.
4. Run `npm ci`, `npm run lint`, `npm run typecheck`, `npm test`, and `npm run build` against a fresh migrated database.
5. Build the image and run `node scripts/verify-image-contract.mjs IMAGE`. The runtime is UID/GID `node`, while every `/app` artifact is root-owned and has no write mode bit. The check also requires `web/dist` and rejects `.env` files.
6. Run `npm run db:migrate:deploy` from the immutable image as a separate pre-deploy job, then start the application only after it succeeds. Prisma and migrations are root-owned but readable/executable by `node`; application startup does not run migrations and cannot rewrite code or migration files. Run the application with a read-only root filesystem and a platform-provided ephemeral `/tmp` tmpfs if required by the runtime.
7. Deploy one instance, require readiness success, verify liveness reveals no dependency detail, then continue the rollout. Exercise login, callback, MFA-role enforcement, recovery webhook, and gatehouse HTTPS rejection.
8. For rollback, deploy the prior immutable release with its compatible secrets. To globally disable human auth, set `HUMAN_AUTH_ENABLED=false` and remove every human-auth variable in the same release; do not leave partial secrets.

## Rotation rehearsal

PKCE and CSRF keyrings accept the current version and optionally exactly the immediately previous version. New PKCE transactions and new/re-encrypted CSRF material always use current; previous exists only to finish data emitted before rollout.

1. Generate new values outside this repository and stage them only in a migrated disposable rehearsal database/environment. Run `RUN_DATABASE_TESTS=true DATABASE_URL=... npm run auth:rotation:rehearse`. The command refuses to run without the database flags and executes production parsers, an OIDC provider/store double with persisted PKCE ciphertext, and the real PostgreSQL browser-session store with persisted CSRF ciphertext. It emits no raw key values.
2. Keep overlap for at least the maximum old-data lifetime plus rollout/rollback time: PKCE 10 minutes; CSRF 12 hours. Use a longer documented operational margin if sessions can be delayed. Verify new database rows use current and old rows remain readable.
3. After the overlap and rollback window, deploy current only and rehearse `--action=retire --current=7 --versions=7`. Securely destroy the retired value after all rollback releases that require it are ineligible.
4. If a key is compromised, remove it immediately. If current is compromised, generate the next version and deploy that version alone; existing material encrypted by the removed key fails closed and affected sessions/transactions must restart. Rehearse `--action=compromised`.

OIDC client-secret rehearsal models a provider that accepts old and new credentials concurrently: register new, prove both, deploy new, then revoke old. The real external provider must support that overlap; otherwise schedule a coordinated maintenance window, because this repository cannot make provider credential changes atomic. A rollback release must retain a provider-valid credential.

Recovery webhook verification accepts one secret, so there is no receiver overlap. The rehearsal proves old-only and new-only signatures around the boundary. The external atomic step is: pause sender delivery, drain/invalidate old signed events, deploy the receiver with the new secret, update the sender, send a uniquely identified canary, then resume delivery. If sender pause and coordinated update are unavailable, rotation requires a maintenance window. Never revoke an old credential or destroy a key before deciding whether its rollback release remains eligible.
