BEGIN;

CREATE TABLE "HumanProvisioningInvitation" (
  id UUID NOT NULL,
  "createdAt" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "expiresAt" TIMESTAMPTZ(3) NOT NULL,
  "consumedAt" TIMESTAMPTZ(3),
  "disabledAt" TIMESTAMPTZ(3),
  "tokenDigest" BYTEA NOT NULL,
  "expectedEmail" TEXT NOT NULL,
  "accountId" UUID NOT NULL,
  "membershipId" UUID NOT NULL,
  "createdByAccountId" UUID NOT NULL,
  CONSTRAINT "HumanProvisioningInvitation_pkey" PRIMARY KEY (id),
  CONSTRAINT "HumanProvisioningInvitation_digest_check" CHECK (octet_length("tokenDigest") = 32),
  CONSTRAINT "HumanProvisioningInvitation_email_check" CHECK (
    "expectedEmail" = lower(btrim("expectedEmail"))
    AND length("expectedEmail") BETWEEN 3 AND 320
    AND "expectedEmail" ~ '^[^[:space:]@]+@[^[:space:]@]+$'
  ),
  CONSTRAINT "HumanProvisioningInvitation_time_check" CHECK (
    "expiresAt" > "createdAt"
    AND "expiresAt" <= "createdAt" + interval '24 hours 1 minute'
    AND ("consumedAt" IS NULL OR "consumedAt" >= "createdAt")
    AND ("disabledAt" IS NULL OR "disabledAt" >= "createdAt")
  )
);

CREATE UNIQUE INDEX "HumanProvisioningInvitation_tokenDigest_key"
  ON "HumanProvisioningInvitation"("tokenDigest");
CREATE UNIQUE INDEX "HumanProvisioningInvitation_membershipId_key"
  ON "HumanProvisioningInvitation"("membershipId");
CREATE UNIQUE INDEX "HumanProvisioningInvitation_membershipId_accountId_key"
  ON "HumanProvisioningInvitation"("membershipId", "accountId");
CREATE INDEX "HumanProvisioningInvitation_accountId_expiresAt_idx"
  ON "HumanProvisioningInvitation"("accountId", "expiresAt");
ALTER TABLE "HumanProvisioningInvitation" ADD CONSTRAINT "HumanProvisioningInvitation_accountId_fkey"
  FOREIGN KEY ("accountId") REFERENCES "HumanAccount"(id) ON DELETE RESTRICT ON UPDATE CASCADE;
ALTER TABLE "HumanProvisioningInvitation" ADD CONSTRAINT "HumanProvisioningInvitation_membershipId_accountId_fkey"
  FOREIGN KEY ("membershipId", "accountId") REFERENCES "HumanMembership"(id, "accountId") ON DELETE RESTRICT ON UPDATE CASCADE;

ALTER TABLE "OidcLoginTransaction"
  ADD COLUMN "invitationTokenDigest" BYTEA,
  ADD CONSTRAINT "OidcLoginTransaction_invitation_digest_check"
    CHECK ("invitationTokenDigest" IS NULL OR octet_length("invitationTokenDigest") = 32),
  ADD CONSTRAINT "OidcLoginTransaction_intent_check"
    CHECK (
      NOT ("recoveryIntent" AND "invitationTokenDigest" IS NOT NULL)
      AND NOT ("recoveryIntent" AND "reauthenticationIntent")
    );

ALTER TABLE "OidcValidatedHandoff"
  ADD COLUMN "authenticationMethods" TEXT[] NOT NULL DEFAULT ARRAY[]::TEXT[],
  ADD COLUMN "assuranceContext" TEXT,
  ADD COLUMN "recoveryIntent" BOOLEAN NOT NULL DEFAULT false,
  ADD CONSTRAINT "OidcValidatedHandoff_intent_check" CHECK (
    NOT ("recoveryIntent" AND "reauthenticationIntent")
  ),
  ADD CONSTRAINT "OidcValidatedHandoff_assurance_check" CHECK (
    cardinality("authenticationMethods") BETWEEN 0 AND 16
    AND NOT ('' = ANY("authenticationMethods"))
    AND ("assuranceContext" IS NULL OR length("assuranceContext") BETWEEN 1 AND 255)
  );

ALTER TABLE "BrowserSession"
  ADD COLUMN "authenticationMethods" TEXT[] NOT NULL DEFAULT ARRAY[]::TEXT[],
  ADD COLUMN "assuranceContext" TEXT,
  ADD CONSTRAINT "BrowserSession_assurance_check" CHECK (
    cardinality("authenticationMethods") BETWEEN 0 AND 16
    AND NOT ('' = ANY("authenticationMethods"))
    AND ("assuranceContext" IS NULL OR length("assuranceContext") BETWEEN 1 AND 255)
  );

CREATE TABLE "RecoveryWebhookEvent" (
  id UUID NOT NULL,
  "createdAt" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "eventId" TEXT NOT NULL,
  "eventDigest" BYTEA NOT NULL,
  issuer TEXT NOT NULL,
  subject TEXT NOT NULL,
  "accountId" UUID,
  "processedAt" TIMESTAMPTZ(3) NOT NULL,
  CONSTRAINT "RecoveryWebhookEvent_pkey" PRIMARY KEY (id),
  CONSTRAINT "RecoveryWebhookEvent_event_id_check" CHECK (length("eventId") BETWEEN 1 AND 255),
  CONSTRAINT "RecoveryWebhookEvent_digest_check" CHECK (octet_length("eventDigest") = 32),
  CONSTRAINT "RecoveryWebhookEvent_issuer_check" CHECK (issuer ~ '^https://[^/?#[:space:]]+([^?#[:space:]]*)?$'),
  CONSTRAINT "RecoveryWebhookEvent_subject_check" CHECK (length(subject) BETWEEN 1 AND 255)
);
CREATE UNIQUE INDEX "RecoveryWebhookEvent_issuer_eventId_key" ON "RecoveryWebhookEvent"(issuer, "eventId");
CREATE UNIQUE INDEX "RecoveryWebhookEvent_eventDigest_key" ON "RecoveryWebhookEvent"("eventDigest");
CREATE INDEX "RecoveryWebhookEvent_createdAt_idx" ON "RecoveryWebhookEvent"("createdAt");

CREATE FUNCTION revoke_human_sessions_on_condominium_disable() RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
BEGIN
  IF OLD."deletedAt" IS NULL AND NEW."deletedAt" IS NOT NULL THEN
    UPDATE public."BrowserSession" session
    SET "revokedAt" = clock_timestamp(), "revokeReason" = 'condominium_disabled'
    FROM public."HumanMembership" membership
    WHERE membership.id = session."activeMembershipId"
      AND membership."accountId" = session."accountId"
      AND membership."condominioId" = NEW.id
      AND session."revokedAt" IS NULL;
  END IF;
  RETURN NEW;
END;
$$;
CREATE TRIGGER "Condominio_revoke_human_sessions_on_disable"
AFTER UPDATE OF "deletedAt" ON "Condominio"
FOR EACH ROW EXECUTE FUNCTION revoke_human_sessions_on_condominium_disable();

GRANT SELECT, INSERT, UPDATE, DELETE ON "HumanProvisioningInvitation", "RecoveryWebhookEvent"
  TO egogero_application;

COMMIT;
