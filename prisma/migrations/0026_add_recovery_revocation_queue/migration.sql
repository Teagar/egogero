BEGIN;

CREATE TYPE "RecoveryRevocationStatus" AS ENUM (
  'pending', 'processing', 'retry', 'acknowledged', 'failed', 'expired'
);

ALTER TABLE "RecoveryWebhookEvent"
  ADD COLUMN "subjectDigest" BYTEA,
  ADD COLUMN "keyVersion" INTEGER,
  ADD COLUMN status "RecoveryRevocationStatus",
  ADD COLUMN attempts INTEGER NOT NULL DEFAULT 0,
  ADD COLUMN "nextAttemptAt" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  ADD COLUMN "expiresAt" TIMESTAMPTZ(3),
  ADD COLUMN "leaseOwner" TEXT,
  ADD COLUMN "leaseToken" UUID,
  ADD COLUMN "leaseExpiresAt" TIMESTAMPTZ(3),
  ADD COLUMN "acknowledgedAt" TIMESTAMPTZ(3),
  ADD COLUMN "failedAt" TIMESTAMPTZ(3),
  ADD COLUMN "lastError" TEXT,
  ADD COLUMN "sloAlertedAt" TIMESTAMPTZ(3);

UPDATE "RecoveryWebhookEvent"
SET "subjectDigest" = "eventDigest",
    "keyVersion" = 1,
    status = 'acknowledged',
    "expiresAt" = "processedAt" + interval '15 minutes',
    "acknowledgedAt" = "processedAt";

ALTER TABLE "RecoveryWebhookEvent"
  DROP COLUMN subject,
  DROP COLUMN "processedAt",
  ALTER COLUMN "subjectDigest" SET NOT NULL,
  ALTER COLUMN "keyVersion" SET NOT NULL,
  ALTER COLUMN status SET NOT NULL,
  ALTER COLUMN status SET DEFAULT 'pending',
  ALTER COLUMN "expiresAt" SET NOT NULL,
  ADD CONSTRAINT "RecoveryWebhookEvent_accountId_fkey"
    FOREIGN KEY ("accountId") REFERENCES "HumanAccount"(id) ON DELETE RESTRICT ON UPDATE CASCADE,
  ADD CONSTRAINT "RecoveryWebhookEvent_subject_digest_check" CHECK (octet_length("subjectDigest") = 32),
  ADD CONSTRAINT "RecoveryWebhookEvent_key_version_check" CHECK ("keyVersion" > 0),
  ADD CONSTRAINT "RecoveryWebhookEvent_attempts_check" CHECK (attempts >= 0),
  ADD CONSTRAINT "RecoveryWebhookEvent_expiry_check" CHECK (
    "expiresAt" > "createdAt" AND "expiresAt" <= "createdAt" + interval '1 hour'
  ),
  ADD CONSTRAINT "RecoveryWebhookEvent_error_check" CHECK (
    "lastError" IS NULL OR "lastError" IN (
      'adapter_timeout', 'adapter_nack', 'adapter_failure', 'attempts_exhausted', 'event_expired'
    )
  ),
  ADD CONSTRAINT "RecoveryWebhookEvent_lease_check" CHECK (
    (status = 'processing' AND "leaseOwner" IS NOT NULL AND "leaseToken" IS NOT NULL AND "leaseExpiresAt" IS NOT NULL)
    OR (status <> 'processing' AND "leaseOwner" IS NULL AND "leaseToken" IS NULL AND "leaseExpiresAt" IS NULL)
  ),
  ADD CONSTRAINT "RecoveryWebhookEvent_terminal_check" CHECK (
    (status = 'acknowledged' AND "acknowledgedAt" IS NOT NULL AND "failedAt" IS NULL AND "lastError" IS NULL)
    OR (status IN ('failed', 'expired') AND "acknowledgedAt" IS NULL AND "failedAt" IS NOT NULL AND "lastError" IS NOT NULL)
    OR (status IN ('pending', 'processing', 'retry') AND "acknowledgedAt" IS NULL AND "failedAt" IS NULL)
  );

DROP INDEX "RecoveryWebhookEvent_createdAt_idx";
CREATE INDEX "RecoveryWebhookEvent_claim_idx"
  ON "RecoveryWebhookEvent" (status, "nextAttemptAt", "createdAt", id);
CREATE INDEX "RecoveryWebhookEvent_lease_idx"
  ON "RecoveryWebhookEvent" (status, "leaseExpiresAt", id);
CREATE INDEX "RecoveryWebhookEvent_slo_idx"
  ON "RecoveryWebhookEvent" (status, "createdAt", "sloAlertedAt");

COMMIT;
