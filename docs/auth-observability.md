# Authentication Observability and Rate Limits

PostgreSQL is authoritative for all human-authentication limits. `AuthenticationRateLimit`
uses `(action, subject)` as its primary key; one atomic upsert serializes decisions across
application processes. The cleanup operation removes rows inactive for 24 hours through
`AuthenticationRateLimit_updatedAt_idx`. IP subjects contain only IPv4 `/24` or IPv6 `/64`
prefixes. An unparseable trusted-proxy result shares the fail-closed `unknown` bucket.

| Operation | Limit | External behavior |
| --- | --- | --- |
| Login initiation | 5/IP/10 minutes | Generic `429`, bounded `Retry-After` |
| Failed OIDC callback | 10/IP/15 minutes | State is consumed, then an exact PostgreSQL exchange reservation is acquired before provider I/O |
| Session creation/rotation | 10/account/15 minutes | Denial, progressive PostgreSQL backoff, repeated-excess alert; recovery revocation happens first |
| Recovery initiation | 3/IP/30 minutes | Generic `429`, no account input or signal |
| Reauthentication initiation | 5/account/10 minutes | Generic `429` after authenticated request validation |
| CSRF/authentication failure | 60/IP/minute | Generic `429` on sustained abuse |

Callback reservations are finalized exactly once. Success releases the reservation without
consuming failure budget; failure converts it into a counted failure. This caps concurrent
provider exchanges at the remaining failure budget without eventually denying successful
callbacks. Reservations expire with the counter window and are deleted with their bucket.

`TRUST_PROXY` accepts only a comma-separated IP/CIDR allowlist. Wildcard `/0` networks and invalid configuration stop
startup. Forwarded addresses are interpreted only by Fastify after the direct peer matches
that allowlist; untrusted peers cannot select their limiter bucket.

## Metrics

The dependency-injected `AuthMetrics` interface has no external telemetry dependency. Its
default is no-op and `createAuthTestCollectors` is available for tests. Sink exceptions and
rejected promises are isolated from authentication decisions.

| Metric | Kind | Bounded labels |
| --- | --- | --- |
| `auth_oidc_callback_total` | counter | `outcome`, `reason` class |
| `auth_session_lookup_seconds` | histogram | `operation`, `outcome` |
| `auth_session_database_seconds` | histogram | `operation`, `outcome` |
| `auth_session_lookup_total` | counter | `operation`, `outcome` (`hit`/`miss`) |
| `auth_session_revocation_seconds` | histogram | `operation`, `outcome` |
| `auth_database_writes_total` | counter | `operation`, `outcome` |
| `auth_rate_limit_decisions_total` | counter | `operation`, `outcome` |

Labels must never contain an account, principal, tenant, session, IP, token, or arbitrary
reason text. `evaluateAuthAggregates` alerts when at least 100 callback observations have a
success rate below 99.5%, or at least 100 session observations have p95 above 20 ms.

## Alerts and Redaction

Alerts cover repeated limiter excess, PKCE/CSRF integrity or key failures, state misses and
replay, issuer mix-up, callback success SLO, and session latency SLO. Alert payloads pass
through recursive defensive redaction. Authorization/cookie headers and raw session, OIDC,
invitation, device, digest, ciphertext, nonce, authentication-tag, client-secret, and code
fields are replaced. Request bodies are not telemetry payloads.

An SLO alert means operators should first verify provider health or PostgreSQL query/index
health, then inspect bounded audit reason codes. Rollback disables new human login while
preserving existing sessions and the device path; schema additions remain. Redis is not part
of this implementation and must not be introduced until the ADR's measured migration gate.
