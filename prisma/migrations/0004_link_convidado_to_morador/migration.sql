ALTER TABLE "Convidado" ADD COLUMN "moradorId" TEXT NOT NULL;
ALTER TABLE "Convidado" ADD COLUMN "ultimoUsoEm" TIMESTAMP(3);

ALTER TABLE "Convidado"
ADD CONSTRAINT "Convidado_moradorId_fkey"
FOREIGN KEY ("moradorId") REFERENCES "Morador"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

CREATE INDEX "Convidado_moradorId_ultimoUsoEm_idx" ON "Convidado"("moradorId", "ultimoUsoEm");
