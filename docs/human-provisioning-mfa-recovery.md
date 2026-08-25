# Human Provisioning, MFA, and Recovery

Human identities are created only by an explicit administrative invitation. The
application never creates an account or membership from an unrecognized OIDC
subject.

## Provisioning

- `POST /admin/human/invitations` creates an invited account and membership and
  returns a 32-byte base64url token once. PostgreSQL stores only its SHA-256
  digest. Invitations expire after 24 hours.
- A provider may provision every valid local role. A condominium manager may
  provision only non-provider roles in their live condominium. Resident scope
  continues to use the existing composite resident/condominium foreign key.
- `POST /auth/invitations/accept` requires same-origin JSON and sends only the
  token digest into the OIDC transaction. No invitation token is placed in a URL
  or retained in PostgreSQL.
- The callback requires `email_verified=true` and an exact normalized email
  match. Invitation consumption, first `(issuer, subject)` insertion, account
  activation, membership activation, audit, and handoff creation commit in one
  transaction.

## MFA Policy

`HUMAN_MFA_ROLE_POLICY` is a JSON object with all four roles. Each role has an
`amr` allowlist and an optional `acr` allowlist. Missing or unknown evidence is
denied. A representative policy is:

```json
{
  "provedor": { "amr": ["webauthn"], "acr": ["urn:phishing-resistant"] },
  "sindico": { "amr": ["webauthn"], "acr": ["urn:phishing-resistant"] },
  "morador": { "amr": ["webauthn", "otp"], "acr": [] },
  "portaria": { "amr": ["webauthn"], "acr": ["urn:phishing-resistant"] }
}
```

Validated signed ID-token evidence is copied through the one-time OIDC handoff
into the local session. It does not grant a role or tenant. Session rotation into
a different membership rechecks the target role. Trusted reauthentication may
replace the evidence while preserving the session family and CSRF value.

## Recovery

- `GET /auth/recovery` accepts no account identifier and starts a recovery-marked
  OIDC transaction at `OIDC_RECOVERY_URL`.
- A successful callback requires fresh `auth_time` and role-compatible MFA. It
  increments `sessionVersion`, revokes old sessions, and creates a new family and
  CSRF value in one transaction.
- `POST /auth/recovery/webhook` accepts only an HMAC-SHA-256 event over
  `<key-version>.<unix-seconds>.<event-id>.<issuer>.<subject>`. Configure one to
  three versioned secrets of at least 32 bytes with `RECOVERY_WEBHOOK_KEYS`, exact
  issuers with `RECOVERY_WEBHOOK_ISSUERS`, and send the version in
  `X-Recovery-Key-Version`. Timestamps have a five-minute bound. A valid event is
  synchronously and atomically persisted before `202`; database failure returns
  `503`. Invalid issuer, version, signature, timestamp, or conflicting replay
  returns a generic failure without an audit or queue mutation. An identical
  duplicate returns `200` without changing its original queue row.
- The queue stores only event and subject digests, bounded operational state,
  issuer, key version, and the already-local account UUID. It never stores the
  signature, raw provider subject, webhook body, or provider tokens.
- `npm run recovery:worker` uses PostgreSQL fenced leases, `SKIP LOCKED`, bounded
  exponential retry, five attempts, and a 15-minute event expiry. Acknowledged,
  failed, and expired states are durable. A one-shot critical alert is emitted if
  acknowledgement has not been persisted within five seconds.

The shipped adapter revokes only Egogero PostgreSQL browser sessions. This is not
an external IdP session-revocation integration. A replacement adapter must keep
the event UUID as its idempotency key, tolerate retries after timeout, honor
abort, return acknowledgement only after every in-scope session is durably
revoked, expose no identity or secret in errors/telemetry, and meet the five-second
deadline. If it cannot participate in the PostgreSQL transaction, its external
effect is at-least-once and the destination must enforce idempotency; the
application cannot manufacture exactly-once semantics across that boundary.

All lifecycle, denial, invitation, MFA, and recovery events use the immutable
authentication audit ledger. Audit metadata excludes tokens, digests,
signatures, provider tokens, complete email addresses, and cryptographic keys.
