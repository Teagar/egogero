ALTER TABLE "AuthenticationRateLimit"
    ADD COLUMN "reservedCount" INTEGER NOT NULL DEFAULT 0,
    ADD CONSTRAINT "AuthenticationRateLimit_reserved_count_check" CHECK ("reservedCount" >= 0);

CREATE TABLE "AuthenticationRateLimitReservation" (
    "id" UUID NOT NULL,
    "action" TEXT NOT NULL,
    "subject" TEXT NOT NULL,
    "createdAt" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "expiresAt" TIMESTAMPTZ(3) NOT NULL,

    CONSTRAINT "AuthenticationRateLimitReservation_pkey" PRIMARY KEY ("id"),
    CONSTRAINT "AuthenticationRateLimitReservation_bucket_fkey"
        FOREIGN KEY ("action", "subject")
        REFERENCES "AuthenticationRateLimit"("action", "subject")
        ON DELETE CASCADE ON UPDATE CASCADE
);

CREATE INDEX "AuthenticationRateLimitReservation_expiresAt_idx"
    ON "AuthenticationRateLimitReservation"("expiresAt");

ALTER TABLE "OidcLoginTransaction"
    ADD CONSTRAINT "OidcLoginTransaction_intents_exclusive_check"
    CHECK (NOT ("recoveryIntent" AND "reauthenticationIntent"));

ALTER TABLE "OidcValidatedHandoff"
    ADD CONSTRAINT "OidcValidatedHandoff_intents_exclusive_check"
    CHECK (NOT ("recoveryIntent" AND "reauthenticationIntent"));
