# Staging and production deployment contract

`deploy/environment.manifest.yaml` is the platform-agnostic variable inventory. It deliberately contains no values and does not claim integration with a secret manager. The operator must inject every secret through the selected platform and must verify that logs, rendered manifests, plans, and shell history do not expose it.

## Network assumptions

- The public application and all OIDC/recovery URLs are exact HTTPS values. `OIDC_REDIRECT_URI` is exactly `${PUBLIC_APPLICATION_ORIGIN}/auth/callback`.
- TLS terminates at a trusted reverse proxy. `TRUST_PROXY` is the narrow IP/CIDR allowlist of those proxy hops, never a wildcard. Requests outside that allowlist cannot assert `X-Forwarded-Proto`; secure gatehouse validation therefore fails with `426` over HTTP.
- The proxy must overwrite, not append from clients, `Forwarded` and `X-Forwarded-*`, pass the original HTTPS protocol, and send traffic to the container on its private network. Direct public access to the container port is forbidden.
- `DATABASE_URL` must be an absolute PostgreSQL URL. Database network encryption, server identity verification, credentials, backups, HA, and least privilege are platform responsibilities and must be confirmed before release; this repository does not provision them.

## Startup and probes

Staging and production require explicit `HUMAN_AUTH_ENABLED=true|false`. `false` is the rollback/global-disable state and requires all human-auth variables, including secrets, to be absent. `LOCAL_DEVELOPMENT_AUTH` is forbidden. Configuration, database-backed idempotency verification, OIDC discovery, exact metadata comparison, and initial JWKS validation all finish before listen.

`GET /health` is liveness and returns only `{"status":"ok"}`. `GET /ready` checks the database on every probe. With human auth enabled it also checks the in-process result of startup metadata validation and complete OIDC/session/administration composition. It never calls the provider and failures return only `503 {"status":"unavailable"}`.

Provider metadata drift after startup does not silently change the cached readiness result and is not polled per probe. Exact issuer/endpoints/JWKS drift is detected fail-closed on the next restart/rollout; runtime JWKS key refresh remains constrained to the pinned JWKS URL. Operational monitoring must alert on provider changes and trigger a controlled restart after reviewing and updating the explicit contract.

## Deployment checklist

1. Render `deploy/environment.manifest.yaml` against the platform configuration without printing secret values.
2. Confirm exact public origin, callback registration, issuer, authorization/token/JWKS endpoints, recovery URL, webhook issuer, MFA policy, proxy CIDRs, and PostgreSQL connectivity/TLS policy with service owners.
3. Confirm all secret values are independently generated, at least 32 bytes, and absent from image layers, source, logs, manifests, and command history.
4. Run `npm ci`, `npm run lint`, `npm run typecheck`, `npm test`, and `npm run build` against a fresh migrated database.
5. Build the image and verify it runs as UID/GID `node`, owns the runtime files, contains `web/dist`, and has no `.env` files.
6. Run `npm run db:migrate:deploy` as a pre-deploy job. The image also runs it defensively before application startup; only one release should advance until migrations complete.
7. Deploy one instance, require readiness success, verify liveness reveals no dependency detail, then continue the rollout. Exercise login, callback, MFA-role enforcement, recovery webhook, and gatehouse HTTPS rejection.
8. For rollback, deploy the prior immutable release with its compatible secrets. To globally disable human auth, set `HUMAN_AUTH_ENABLED=false` and remove every human-auth variable in the same release; do not leave partial secrets.

## Rotation rehearsal

PKCE and CSRF keyrings accept the current version and optionally exactly the immediately previous version. New PKCE transactions and new/re-encrypted CSRF material always use current; previous exists only to finish data emitted before rollout.

1. Generate a new 32-byte key outside this repository. Increment the version, deploy `{previous,current}` with current pointing to the new version, and run `npm run auth:rotation:rehearse -- --kind=pkce --action=prepare --current=7 --versions=6,7` (repeat with `csrf`).
2. Keep overlap for at least the maximum old-data lifetime plus rollout/rollback time: PKCE 10 minutes; CSRF 12 hours. Use a longer documented operational margin if sessions can be delayed. Verify new database rows use current and old rows remain readable.
3. After the overlap and rollback window, deploy current only and rehearse `--action=retire --current=7 --versions=7`. Securely destroy the retired value after all rollback releases that require it are ineligible.
4. If a key is compromised, remove it immediately. If current is compromised, generate the next version and deploy that version alone; existing material encrypted by the removed key fails closed and affected sessions/transactions must restart. Rehearse `--action=compromised`.

OIDC client-secret rotation requires provider support for overlapping credentials or a coordinated maintenance window. Add the new provider credential, deploy it, validate login, then revoke the old credential; a rollback release must use a still-valid credential. Recovery webhook rotation similarly requires sender/receiver overlap or coordinated cutover because this application accepts one webhook secret. Never revoke an old credential before deciding whether its rollback release is still eligible.
