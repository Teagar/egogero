BEGIN;

CREATE TYPE "DeliveryStatus" AS ENUM ('pending', 'processing', 'retry', 'delivered', 'dead_letter');

ALTER TABLE "DeliveryIntent"
  ADD COLUMN "status" "DeliveryStatus" NOT NULL DEFAULT 'pending',
  ADD COLUMN "attempts" INTEGER NOT NULL DEFAULT 0,
  ADD COLUMN "leaseOwner" TEXT,
  ADD COLUMN "leaseToken" UUID,
  ADD COLUMN "leaseExpiresAt" TIMESTAMPTZ(3),
  ADD COLUMN "nextAttemptAt" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  ADD COLUMN "lastError" TEXT;

UPDATE "DeliveryIntent" SET status = 'delivered', attempts = 1 WHERE "deliveredAt" IS NOT NULL;

ALTER TABLE "DeliveryIntent"
  ADD CONSTRAINT "DeliveryIntent_attempts_check" CHECK ("attempts" >= 0),
  ADD CONSTRAINT "DeliveryIntent_lease_check" CHECK (
    ("status" = 'processing' AND "leaseOwner" IS NOT NULL AND "leaseToken" IS NOT NULL AND "leaseExpiresAt" IS NOT NULL)
    OR
    ("status" <> 'processing' AND "leaseOwner" IS NULL AND "leaseToken" IS NULL AND "leaseExpiresAt" IS NULL)
  ),
  ADD CONSTRAINT "DeliveryIntent_terminal_check" CHECK (
    ("status" = 'delivered' AND "deliveredAt" IS NOT NULL)
    OR
    ("status" <> 'delivered' AND "deliveredAt" IS NULL)
  ),
  ADD CONSTRAINT "DeliveryIntent_error_check" CHECK (
    "lastError" IS NULL OR "lastError" IN (
      'provider_transient', 'provider_permanent', 'provider_unavailable',
      'provider_timeout', 'payload_invalid', 'payload_decryption_failed', 'attempts_exhausted'
    )
  ),
  ADD CONSTRAINT "DeliveryIntent_state_check" CHECK (
    ("status" = 'pending' AND attempts = 0 AND "lastError" IS NULL)
    OR ("status" = 'processing' AND attempts >= 0 AND "lastError" IS NULL)
    OR ("status" = 'retry' AND attempts > 0 AND "lastError" IS NOT NULL)
    OR ("status" = 'delivered' AND attempts > 0 AND "lastError" IS NULL)
    OR ("status" = 'dead_letter' AND attempts > 0 AND "lastError" IS NOT NULL)
  );

CREATE INDEX "DeliveryIntent_worker_claim_idx"
  ON "DeliveryIntent" ("nextAttemptAt", "createdAt", id)
  WHERE "status" IN ('pending', 'retry');
CREATE INDEX "DeliveryIntent_expired_lease_idx"
  ON "DeliveryIntent" ("leaseExpiresAt", id)
  WHERE "status" = 'processing';

COMMIT;
