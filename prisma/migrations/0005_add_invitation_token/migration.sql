BEGIN;

CREATE TYPE "TipoConvite" AS ENUM ('visitante', 'prestador', 'entregador');

-- A singleton fingerprint makes mixed token secrets across app instances fail closed.
CREATE TABLE "SecurityKey" (
  "name" TEXT NOT NULL,
  "fingerprint" CHAR(64) NOT NULL,
  CONSTRAINT "SecurityKey_pkey" PRIMARY KEY ("name"),
  CONSTRAINT "SecurityKey_fingerprint_format_check" CHECK ("fingerprint" ~ '^[0-9a-f]{64}$')
);

-- Nullable fields preserve invitations created before token generation existed.
ALTER TABLE "Convite"
ADD COLUMN "tipo" "TipoConvite",
ADD COLUMN "expiresAt" TIMESTAMP(3),
ADD COLUMN "usedAt" TIMESTAMP(3),
ADD COLUMN "tokenDigest" CHAR(64);

ALTER TABLE "Convite"
ADD CONSTRAINT "Convite_tokenDigest_format_check"
CHECK ("tokenDigest" IS NULL OR "tokenDigest" ~ '^[0-9a-f]{64}$');

ALTER TABLE "Convite"
ADD CONSTRAINT "Convite_active_token_state_check"
CHECK (
  "tokenDigest" IS NULL OR (
    "tipo" IS NOT NULL
    AND "expiresAt" IS NOT NULL
    AND "expiresAt" > "createdAt"
    AND "moradorId" IS NOT NULL
    AND "convidadoId" IS NOT NULL
    AND "usedAt" IS NULL
  )
);

-- The keyed digest arbitrates active-token races without storing the bearer token.
CREATE UNIQUE INDEX "Convite_tokenDigest_key" ON "Convite"("tokenDigest");
CREATE INDEX "Convite_condominioId_expiresAt_idx" ON "Convite"("condominioId", "expiresAt");

COMMIT;
