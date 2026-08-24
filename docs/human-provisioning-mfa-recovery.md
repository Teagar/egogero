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
  `<unix-seconds>.<event-id>.<issuer>.<subject>`. Configure a secret of at least
  32 bytes and exact issuers with `RECOVERY_WEBHOOK_SECRET` and
  `RECOVERY_WEBHOOK_ISSUERS`. Timestamps have a five-minute bound. Event IDs are
  persisted for replay protection; the target is resolved only by signed exact
  issuer and subject. Responses are generic and idempotent.

All lifecycle, denial, invitation, MFA, and recovery events use the immutable
authentication audit ledger. Audit metadata excludes tokens, digests,
signatures, provider tokens, complete email addresses, and cryptographic keys.
