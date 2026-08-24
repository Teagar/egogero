BEGIN;

ALTER TABLE "OidcLoginTransaction"
  ADD COLUMN "reauthenticationIntent" BOOLEAN NOT NULL DEFAULT false,
  ADD COLUMN "reauthenticationFamilyId" UUID,
  ADD CONSTRAINT "OidcLoginTransaction_reauthentication_family_check" CHECK (
    "reauthenticationIntent" = ("reauthenticationFamilyId" IS NOT NULL)
  );

ALTER TABLE "OidcValidatedHandoff"
  ADD COLUMN "reauthenticationIntent" BOOLEAN NOT NULL DEFAULT false,
  ADD COLUMN "reauthenticationFamilyId" UUID,
  ADD CONSTRAINT "OidcValidatedHandoff_reauthentication_family_check" CHECK (
    "reauthenticationIntent" = ("reauthenticationFamilyId" IS NOT NULL)
  );

COMMIT;
