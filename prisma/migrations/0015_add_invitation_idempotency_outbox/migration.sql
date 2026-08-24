BEGIN;

CREATE TYPE "DeliveryChannel" AS ENUM ('email', 'sms');

CREATE TABLE "IdempotencyRecord" (
    "id" UUID NOT NULL,
    "createdAt" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "confirmedAt" TIMESTAMPTZ(3),
    "expiresAt" TIMESTAMPTZ(3),
    "actorId" TEXT NOT NULL,
    "condominioId" TEXT NOT NULL,
    "method" TEXT NOT NULL,
    "route" TEXT NOT NULL,
    "keyDigest" CHAR(64) NOT NULL,
    "requestHash" CHAR(64) NOT NULL,
    "responseStatus" INTEGER,
    "responseCiphertext" BYTEA,
    "responseIv" BYTEA,
    "responseAuthTag" BYTEA,
    "keyVersion" INTEGER NOT NULL,
    CONSTRAINT "IdempotencyRecord_pkey" PRIMARY KEY ("id"),
    CONSTRAINT "IdempotencyRecord_confirmed_response_check" CHECK (
      ("confirmedAt" IS NULL AND "expiresAt" IS NULL AND "responseStatus" IS NULL
        AND "responseCiphertext" IS NULL AND "responseIv" IS NULL AND "responseAuthTag" IS NULL)
      OR
      ("confirmedAt" IS NOT NULL AND "expiresAt" IS NOT NULL AND "responseStatus" BETWEEN 200 AND 599
        AND "responseCiphertext" IS NOT NULL AND "responseIv" IS NOT NULL AND "responseAuthTag" IS NOT NULL)
    ),
    CONSTRAINT "IdempotencyRecord_digest_check" CHECK (
      "keyDigest" ~ '^[0-9a-f]{64}$' AND "requestHash" ~ '^[0-9a-f]{64}$'
    ),
    CONSTRAINT "IdempotencyRecord_crypto_check" CHECK (
      "keyVersion" = 1
      AND ("responseIv" IS NULL OR octet_length("responseIv") = 12)
      AND ("responseAuthTag" IS NULL OR octet_length("responseAuthTag") = 16)
    ),
    CONSTRAINT "IdempotencyRecord_scope_check" CHECK (
      length("actorId") BETWEEN 1 AND 128 AND method = 'POST' AND length(route) BETWEEN 1 AND 512
    )
);

CREATE TABLE "DeliveryIntent" (
    "id" UUID NOT NULL,
    "createdAt" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "deliveredAt" TIMESTAMPTZ(3),
    "conviteId" TEXT NOT NULL,
    "condominioId" TEXT NOT NULL,
    "channel" "DeliveryChannel" NOT NULL,
    "payloadCiphertext" BYTEA NOT NULL,
    "payloadIv" BYTEA NOT NULL,
    "payloadAuthTag" BYTEA NOT NULL,
    "keyVersion" INTEGER NOT NULL,
    CONSTRAINT "DeliveryIntent_pkey" PRIMARY KEY ("id"),
    CONSTRAINT "DeliveryIntent_crypto_check" CHECK (
      "keyVersion" = 1 AND octet_length("payloadIv") = 12 AND octet_length("payloadAuthTag") = 16
    )
);

CREATE FUNCTION reject_unconfirmed_idempotency_record()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  IF EXISTS (
    SELECT 1 FROM "IdempotencyRecord" WHERE id = NEW.id AND "confirmedAt" IS NULL
  ) THEN
    RAISE EXCEPTION 'idempotency record must be confirmed in its insertion transaction';
  END IF;
  RETURN NEW;
END;
$$;

CREATE CONSTRAINT TRIGGER "IdempotencyRecord_confirm_before_commit"
AFTER INSERT OR UPDATE ON "IdempotencyRecord"
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION reject_unconfirmed_idempotency_record();

CREATE UNIQUE INDEX "IdempotencyRecord_scope_key" ON "IdempotencyRecord"(
  "actorId", "condominioId", "method", "route", "keyDigest"
);
CREATE INDEX "IdempotencyRecord_expiresAt_id_idx" ON "IdempotencyRecord"("expiresAt", "id");
CREATE UNIQUE INDEX "Convite_id_condominioId_key" ON "Convite"("id", "condominioId");
CREATE UNIQUE INDEX "DeliveryIntent_conviteId_channel_key" ON "DeliveryIntent"("conviteId", "channel");
CREATE INDEX "DeliveryIntent_deliveredAt_createdAt_id_idx" ON "DeliveryIntent"("deliveredAt", "createdAt", "id");
CREATE INDEX "DeliveryIntent_condominioId_deliveredAt_createdAt_idx" ON "DeliveryIntent"("condominioId", "deliveredAt", "createdAt");

ALTER TABLE "IdempotencyRecord" ADD CONSTRAINT "IdempotencyRecord_condominioId_fkey"
  FOREIGN KEY ("condominioId") REFERENCES "Condominio"("id") ON DELETE RESTRICT ON UPDATE CASCADE;
ALTER TABLE "DeliveryIntent" ADD CONSTRAINT "DeliveryIntent_conviteId_fkey"
  FOREIGN KEY ("conviteId", "condominioId") REFERENCES "Convite"("id", "condominioId") ON DELETE RESTRICT ON UPDATE CASCADE;

COMMIT;
