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
reason text. Export applies a metric-specific key and value allowlist and maps unexpected
values to `other`; callers cannot create new dimensions. `evaluateAuthAggregates` alerts when
at least 100 callback observations have a success rate below 99.5%, or at least 100 session
observations have conservative histogram p95 above 20 ms.

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

## Rollout Snapshot Contract

`createStructuredAuthTelemetry` emits one JSON object per interval using contract
`egogero.auth-rollout/v1`. The default sink writes JSONL to stdout. A sink adapter can send the
same object elsewhere. `createAuthSnapshotFileSink(path)` opens with `O_NOFOLLOW`, creates with
mode `0600`, repairs any existing group/other permission bits to `0600` before append, and
recovers its serialized promise chain after a failed append. Sink promises are never awaited
by authentication. Throws, rejection, timeout (default five seconds), or backpressure are
carried into a later snapshot as a degraded observability gap.
The affected interval is not silently accepted as evidence. If the only sink remains down,
there may be no durable record able to report that failure, so absence of contiguous snapshots
is itself inconclusive.

Only one sink operation and one pending snapshot are retained. Timeout requests cancellation
when the adapter supports it, but does not release the active slot until the operation really
settles. Further intervals are dropped with `sink_backpressure`; this bounds memory and stdout
`drain` listeners. A permanently stuck sole sink may be unable to publish its own gap, which is
why independent serving inventory is mandatory for rollout evaluation.

Each snapshot contains only:

| Field | Contract |
| --- | --- |
| `contract` | Exact version `egogero.auth-rollout/v1` |
| `interval.start/end` | Half-open UTC interval `[start,end)` for this process |
| `instanceId` | UUID v4 generated per process by default; non-sensitive and unrelated to hosts or users |
| `sequence` | Strictly increasing within one process instance |
| `counters[]` | Delta counters with allowlisted metric dimensions and safe integer values |
| `histograms[]` | Delta, non-cumulative bucket counts in seconds; bounds `1,2.5,5,10,20,50,100,250,500,1000ms`, plus overflow |
| `alerts` | Counts keyed only by the seven bounded `AuthAlertType` routes |
| `criticalIncidentCount` | Crypto integrity/key, replay/state-miss, and issuer mix-up total |
| `observability` | `healthy` or `degraded`, with bounded sink, routing, clock, and numeric gap code/count pairs |

Snapshots contain no raw observations or alert details. They must not contain account,
principal, condominium/tenant, session, IP/prefix, request, token, credential, or arbitrary
label values. The telemetry remains evidence only: it never grants, denies, or changes an
authentication operation.

Multiple instances are summed by bucket and counter. Concurrent intervals from different
instance IDs are expected. Intervals for one instance must be contiguous, non-overlapping, and
have increasing sequence numbers. Wall elapsed time is compared with monotonic elapsed time;
drift over five seconds is marked and the interval uses monotonic elapsed time instead. Never
average process percentiles: sum non-cumulative bucket
counts first, then choose the first upper bound whose cumulative count reaches
`ceil(total * 0.95)`. This deliberately reports the upper bound and treats overflow as
infinite.

## Canary Evaluator

Evaluation also requires an independently produced `egogero.auth-rollout-inventory/v1` JSON
file. Each `servingInstances` entry contains a UUID v4 `instanceId`, canonical UTC
`expectedStart`/`expectedEnd`, and `cadenceMs`. It must come from deployment inventory or the
orchestrator, not the telemetry sink or process lifecycle hook. Every expected interval must
be covered by that instance's snapshots, each no longer than its cadence. Planned replacement
is represented by ending the old instance and starting the new instance in inventory; a
replica that silently stops while another remains healthy is inconclusive.

Inventory is exactly one JSON record in a regular file. The evaluator checks the path, opens it
once with `O_NOFOLLOW`, verifies the opened device/inode, reads incrementally from that handle,
and verifies size and identity again after EOF. Symlinks, directories/special files, multiple
records, growth, or path replacement are rejected as inconclusive with exit `2`.

Run against one or more files, or pipe JSONL on stdin:

```sh
npm run auth:rollout:evaluate -- --inventory serving.json snapshots-a.jsonl snapshots-b.jsonl
cat snapshots.jsonl | npm run auth:rollout:evaluate -- --inventory serving.json
```

The command writes exactly one `egogero.auth-rollout-evaluation/v1` JSON object. Exit `0` is
`pass`, exit `1` is `fail`, and exit `2` is `inconclusive`. A pass requires all of:

- contiguous real wall-clock coverage of at least 24 hours (the exact boundary passes)
- zero critical authentication incidents
- callback success at least 99.5% (integer cross-multiplication; the exact boundary passes)
- session verification histogram p95 at most 20 ms (the exact bucket boundary passes)
- at least 100 callbacks and 100 session lookup samples
- no malformed records, unexpected dimensions, sequence errors, same-instance gaps/overlap, global coverage gaps, clock anomalies, numeric overflow, or observability gap markers
- complete per-instance coverage of the independent expected serving inventory at its declared cadence

An observed critical incident or measured SLO breach is `fail` even if other evidence is
incomplete. Missing volume/window, malformed data, restarts with ambiguous same-instance
overlap, and observability gaps are `inconclusive`, never pass. Synthetic snapshots are useful
only for validating the evaluator and alert plumbing; they are not staging or production
rollout evidence.

JSONL is processed as a stream. Defaults are at most 32 files, 100,000 records, 256 KiB per
line, 32 MiB per file, and 64 MiB total; inventory is capped at 256 KiB. Limit or read failures
produce machine-readable `inconclusive` output and exit `2`, rather than buffering unbounded
input or crashing with partial output.

## Dashboards and Routing

For a dashboard or warehouse, group counter deltas by `metric` and the exact bounded
`dimensions` object, then `sum(value)`. For latency, verify identical contract/bounds and
`sum(bucketCounts[index])` across every selected process and interval before computing p95.
Useful panels/queries are:

```text
callback_success = sum(auth_oidc_callback_total{outcome="success"})
callback_total   = sum(auth_oidc_callback_total{outcome in ["success","failure"]})
callback_slo     = callback_success / callback_total
session_p95      = first bound where cumulative(sum(bucketCounts)) >= ceil(sum(count) * 0.95)
critical         = sum(criticalIncidentCount)
gaps             = sum(observability.gaps.count) by code
```

Route `crypto_integrity_failure` and `crypto_key_failure` to the security/on-call channel;
route `oidc_replay_or_state_miss` and `oidc_issuer_mixup` to security and identity on-call;
route `rate_limit_repeated_excess` to abuse/on-call; and route both SLO alerts to identity and
database on-call. A routing smoke test must deliver one sanitized event for every route and
confirm acknowledgement without adding payload dimensions.

`createRoutedAuthAlertSink` validates an exact `AuthAlertType` to bounded route-name map. The
default map uses only `security`, `identity`, `abuse`, and `database`. Delivery contract
`egogero.auth-alert-delivery/v1` contains only alert type and route names; caller details are
never forwarded. The routing layer holds one active and one pending delivery, supports real
`AbortSignal` cancellation, and reports throw, reject, timeout, backpressure, and negative
acknowledgement through `recordObservabilityGap`. `createAuthAlertWebhookAdapter` accepts only
credential-free HTTPS URLs; `createAuthAlertStdoutAdapter` is the provider-neutral alternative.
Compose routing with snapshot alert counting through `combineAuthAlertSinks`. No provider is
authoritative for authentication decisions.

`startServer` always composes aggregate counting with routed delivery. Production configuration
is deliberately small and fail-closed:

| Variable | Values |
| --- | --- |
| `AUTH_ALERT_ADAPTER` | `stdout` (default) or `https_webhook` |
| `AUTH_ALERT_WEBHOOK_URL` | Required only for `https_webhook`; HTTPS without credentials, query, or fragment |
| `AUTH_ALERT_TIMEOUT_MS` | Integer `100..10000`, default `5000` |

The stdout adapter emits only `egogero.auth-alert-delivery/v1`. The webhook adapter is a generic
HTTP transport, not a claim of integration with any alert provider. Non-2xx acknowledgement,
throw, rejection, timeout, and bounded-queue drops are observability gaps and never affect an
authentication result.

Rollback the canary (disable new human login, preserve existing sessions and device access) on
any critical incident, callback success below 99.5%, session p95 above 20 ms, or repeated
excess that indicates uncontrolled abuse. Pause promotion rather than claiming success for an
observability gap, insufficient sample/window, or overlap ambiguity. Investigate provider,
key configuration, PostgreSQL health/indexes, and sink health before resuming the full 24-hour
evidence window.
