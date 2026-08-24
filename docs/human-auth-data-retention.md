# Human Authentication Data Retention

`OidcLoginTransaction` rows become eligible for hard deletion 24 hours after
consumption or expiry, whichever occurs first. `BrowserSession` rows become
eligible 30 days after revocation or effective expiry, whichever occurs first. Migration
`0017` provides bounded-cleanup indexes over those retention anchors; the auth
runtime cards must schedule deletion in limited, retryable batches.

`AuthenticationAuditEvent` is not part of either operational cleanup window.
It is an append-only security ledger retained under the organization's audit
policy. The application database role receives `SELECT` and `INSERT` but not
`UPDATE`, `DELETE`, or `TRUNCATE`; triggers also reject mutation attempts.

`egogero_application` is a `NOLOGIN` privilege role. Before human auth is
enabled, deployment must provision a distinct non-owner login as its member and
use that login for runtime database connections. Migration credentials remain
separate and need `CREATEROLE` only to bootstrap this role on a new PostgreSQL
cluster. Production must never run the application as the table owner.

Cleanup metrics and logs may contain aggregate row counts and cutoff times only.
They must not include account, identity, membership, session, tenant, IP, or
request correlation identifiers.
