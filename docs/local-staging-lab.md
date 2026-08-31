# Synthetic local staging lab

This free Docker Compose environment exercises the deployment-mode application with PostgreSQL, HTTPS, Keycloak OIDC, both workers, Prometheus, and Grafana. It is a disposable local laboratory, not a hosted staging environment. Its results do not satisfy PC-35, a canary window, an external alert acknowledgement, managed-secret evidence, or production MFA and recovery evidence.

## Requirements

- Docker Engine with the Compose plugin
- Node.js 22 and npm for the helper commands
- Enough local capacity to run two PostgreSQL containers, Keycloak, the application, workers, and the observability services
- `office.localhost` and `auth.localhost` resolving to loopback; modern browsers and resolvers normally provide this for `*.localhost`

All operational credentials are generated with `node:crypto`, stored with mode `0600` under the ignored `.local-staging/` directory, and scoped to the containers that need them. The directory is excluded from Git and the Docker build context. `npm run local-staging:down` preserves credentials and Docker volumes; `npm run local-staging:reset` removes both. Credentials cannot be regenerated independently of their volumes.

## Start and verify

```sh
npm run local-staging:up
npm run local-staging:check
npm run local-staging:login-check
npm run local-staging:credentials
```

The first command generates local credentials if necessary, builds one application image for this worktree, runs the migrations once, seeds one synthetic condominium and separate provider, manager, resident, and gatehouse accounts, and starts the long-running services. Application and worker containers use the restricted `office_application` database role; the one-shot migration and seed containers use the database owner. A path-derived Compose project name isolates containers, images, networks, and volumes from other worktrees.

The lab role inherits `egogero_application` and receives an additional column-level `UPDATE` grant only on `HumanAuthRolloutPolicy.updatedAt`. PostgreSQL requires update privilege on at least one column for the application's `SELECT ... FOR SHARE` rollout gate, even though the query does not mutate the row. The role cannot use this exception to change rollout state, cohort, algorithm, or version. This local grant does not change a migration or claim that the production role wiring has been validated.

The check exports Caddy's local root certificate to `.local-staging/caddy-root.crt` and verifies:

- application liveness and database/OIDC readiness through HTTPS;
- exact Keycloak issuer metadata and the application login redirect;
- fresh healthy Prometheus/Blackbox targets and a successful PostgreSQL exporter connection;
- successful HTTPS probes for the three documented targets and running delivery/recovery worker processes;
- Grafana's provisioned Prometheus datasource and local-staging dashboard.

`local-staging:login-check` uses the installed Playwright Chromium and all four generated synthetic credentials to complete authorization code + PKCE, validate each ID token callback, and require an authenticated application session with the expected role and screen. It clears only the disposable lab's authentication rate-limit counters before and after this synthetic batch so the check is repeatable and does not consume the manual test allowance. Install the browser once with `npm run test:e2e:install` if it is unavailable.

Endpoints:

- Application: `https://office.localhost:8443`
- Keycloak administration: `https://auth.localhost:8443/admin`
- Prometheus: `http://127.0.0.1:9090`
- Grafana: `http://127.0.0.1:3002`

The generated usernames and passwords are printed only by `npm run local-staging:credentials`. Do not paste them into tickets, commits, screenshots, or staging configuration.

## Browser trust and login

Caddy issues certificates from a per-lab local CA. Import `.local-staging/caddy-root.crt` into a disposable browser profile before testing login. Do not install it as a broad organizational or production trust anchor. Remove the imported CA when the lab is discarded.

Open the application, choose login, and use one of the generated `provedor`, `sindico`, `morador`, or `portaria` credentials. Each account exposes its corresponding role screen against the same synthetic condominium. The realm emits a hard-coded `amr=["webauthn"]` claim solely to exercise the application's strict role-MFA parsing and session path without physical hardware. This is synthetic protocol plumbing, not proof that Keycloak performed phishing-resistant MFA. The realm also does not provide the real external recovery webhook or prove external session revocation.

## Observability scope

The application deliberately has no Prometheus endpoint. The lab does not invent one or translate its rollout snapshots into lossy metrics. Prometheus collects supported signals from:

- Blackbox probes of public HTTPS `/health`, `/ready`, and OIDC discovery;
- `postgres_exporter` using a generated `pg_monitor` account;
- Prometheus itself.

Grafana provisions the datasource and a small dashboard for `probe_success` and `pg_up`. Authentication rollout snapshots and alert delivery remain on the application's documented structured telemetry path and require real operator infrastructure for PC-35.

The worker check proves only that both worker processes remain running. The local delivery adapter is intentionally unavailable, so the lab does not claim successful provider delivery or functional worker-loop health. Grafana has no persistent volume, ensuring each start provisions the checked datasource and dashboard from the committed files.

## Stop and troubleshoot

```sh
npm run local-staging:down
node scripts/local-staging.mjs status
node scripts/local-staging.mjs logs app keycloak caddy
```

If `172.31.46.0/24` conflicts with a local network, run `npm run local-staging:reset`, change both the Compose subnet/Caddy address and the `TRUST_PROXY` address generated by `scripts/local-staging.mjs`, then start from scratch. Never widen `TRUST_PROXY` to a wildcard.

Changing persisted Keycloak realm settings or database credentials can make generated files and volumes disagree. Use `npm run local-staging:reset` and start again instead of editing or forcibly regenerating secret files. Service versions are constrained by tags, but upstream tags and the application base image are not digest-pinned. The lab is operationally repeatable, not bit-for-bit reproducible, and the first start requires network access to pull images that are not cached locally.
