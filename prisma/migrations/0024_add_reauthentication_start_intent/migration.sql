BEGIN;

CREATE TABLE "ReauthenticationStartIntent" (
  "id" UUID NOT NULL,
  "createdAt" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "expiresAt" TIMESTAMPTZ(3) NOT NULL,
  "consumedAt" TIMESTAMPTZ(3),
  "tokenDigest" BYTEA NOT NULL,
  "accountId" UUID NOT NULL,
  "familyId" UUID NOT NULL,
  "returnTo" TEXT NOT NULL,
  CONSTRAINT "ReauthenticationStartIntent_pkey" PRIMARY KEY ("id"),
  CONSTRAINT "ReauthenticationStartIntent_tokenDigest_key" UNIQUE ("tokenDigest"),
  CONSTRAINT "ReauthenticationStartIntent_lifetime_check"
    CHECK ("expiresAt" > "createdAt" AND "expiresAt" <= "createdAt" + interval '5 minutes'),
  CONSTRAINT "ReauthenticationStartIntent_consumedAt_check"
    CHECK ("consumedAt" IS NULL OR "consumedAt" >= "createdAt"),
  CONSTRAINT "ReauthenticationStartIntent_returnTo_check"
    CHECK ("returnTo" IN ('/app', '/logout-all/continue'))
);

CREATE INDEX "ReauthenticationStartIntent_cleanup_idx"
ON "ReauthenticationStartIntent"("expiresAt", "consumedAt", "id");

COMMIT;
