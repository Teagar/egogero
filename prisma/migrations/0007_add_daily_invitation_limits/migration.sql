ALTER TABLE "Condominio" ADD COLUMN "dailyInvitationLimit" INTEGER;
ALTER TABLE "Morador" ADD COLUMN "dailyInvitationLimit" INTEGER;

ALTER TABLE "Condominio"
  ADD CONSTRAINT "Condominio_dailyInvitationLimit_nonnegative"
  CHECK ("dailyInvitationLimit" IS NULL OR "dailyInvitationLimit" >= 0);
ALTER TABLE "Morador"
  ADD CONSTRAINT "Morador_dailyInvitationLimit_nonnegative"
  CHECK ("dailyInvitationLimit" IS NULL OR "dailyInvitationLimit" >= 0);

CREATE INDEX "Convite_condominioId_moradorId_createdAt_idx"
  ON "Convite"("condominioId", "moradorId", "createdAt");
