BEGIN;

ALTER TABLE "ExternalIdentity"
  ADD CONSTRAINT "ExternalIdentity_id_accountId_key" UNIQUE (id, "accountId");

CREATE TABLE "OidcValidatedHandoff" (
  id UUID NOT NULL,
  "createdAt" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "expiresAt" TIMESTAMPTZ(3) NOT NULL,
  "consumedAt" TIMESTAMPTZ(3),
  "handleDigest" BYTEA NOT NULL,
  "loginTransactionId" UUID NOT NULL,
  "accountId" UUID NOT NULL,
  "externalIdentityId" UUID NOT NULL,
  "authenticatedAt" TIMESTAMPTZ(3) NOT NULL,
  CONSTRAINT "OidcValidatedHandoff_pkey" PRIMARY KEY (id),
  CONSTRAINT "OidcValidatedHandoff_handle_check" CHECK (octet_length("handleDigest") = 32),
  CONSTRAINT "OidcValidatedHandoff_time_check" CHECK (
    "expiresAt" > "createdAt"
    AND ("consumedAt" IS NULL OR "consumedAt" >= "createdAt")
    AND "authenticatedAt" <= "createdAt" + interval '60 seconds'
  )
);

CREATE UNIQUE INDEX "OidcValidatedHandoff_handleDigest_key"
  ON "OidcValidatedHandoff"("handleDigest");
CREATE UNIQUE INDEX "OidcValidatedHandoff_loginTransactionId_key"
  ON "OidcValidatedHandoff"("loginTransactionId");
CREATE INDEX "OidcValidatedHandoff_expiresAt_consumedAt_idx"
  ON "OidcValidatedHandoff"("expiresAt", "consumedAt");
CREATE INDEX "OidcValidatedHandoff_accountId_createdAt_idx"
  ON "OidcValidatedHandoff"("accountId", "createdAt");

ALTER TABLE "OidcValidatedHandoff"
  ADD CONSTRAINT "OidcValidatedHandoff_loginTransactionId_fkey"
  FOREIGN KEY ("loginTransactionId") REFERENCES "OidcLoginTransaction"(id)
  ON DELETE RESTRICT ON UPDATE CASCADE;
ALTER TABLE "OidcValidatedHandoff"
  ADD CONSTRAINT "OidcValidatedHandoff_externalIdentityId_accountId_fkey"
  FOREIGN KEY ("externalIdentityId", "accountId") REFERENCES "ExternalIdentity"(id, "accountId")
  ON DELETE RESTRICT ON UPDATE CASCADE;

GRANT SELECT, INSERT, UPDATE, DELETE ON "OidcValidatedHandoff" TO egogero_application;

COMMIT;
