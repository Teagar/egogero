CREATE TABLE "AuthenticationRateLimit" (
    "action" TEXT NOT NULL,
    "subject" TEXT NOT NULL,
    "windowStartedAt" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "count" INTEGER NOT NULL DEFAULT 0,
    "deniedCount" INTEGER NOT NULL DEFAULT 0,
    "blockedUntil" TIMESTAMPTZ(3),
    "updatedAt" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "AuthenticationRateLimit_pkey" PRIMARY KEY ("action", "subject"),
    CONSTRAINT "AuthenticationRateLimit_count_check" CHECK ("count" >= 0),
    CONSTRAINT "AuthenticationRateLimit_denied_count_check" CHECK ("deniedCount" >= 0)
);

CREATE INDEX "AuthenticationRateLimit_updatedAt_idx"
    ON "AuthenticationRateLimit"("updatedAt");
