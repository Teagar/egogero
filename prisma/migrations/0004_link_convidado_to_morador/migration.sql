-- Existing guests predate a responsible resident, so their owner remains NULL.
-- New guest records are required to provide an active owner at the API boundary.
ALTER TABLE "Convidado" ADD COLUMN "moradorId" TEXT;
ALTER TABLE "Convidado" ADD COLUMN "ultimoUsoEm" TIMESTAMP(3);

ALTER TABLE "Morador"
ADD CONSTRAINT "Morador_id_condominioId_key" UNIQUE ("id", "condominioId");

ALTER TABLE "Convidado"
ADD CONSTRAINT "Convidado_id_condominioId_key" UNIQUE ("id", "condominioId");

ALTER TABLE "Convidado"
ADD CONSTRAINT "Convidado_moradorId_condominioId_fkey"
FOREIGN KEY ("moradorId", "condominioId") REFERENCES "Morador"("id", "condominioId") ON DELETE RESTRICT ON UPDATE CASCADE;

ALTER TABLE "Convite" DROP CONSTRAINT "Convite_moradorId_fkey";
ALTER TABLE "Convite" DROP CONSTRAINT "Convite_convidadoId_fkey";

ALTER TABLE "Convite"
ADD CONSTRAINT "Convite_moradorId_condominioId_fkey"
FOREIGN KEY ("moradorId", "condominioId") REFERENCES "Morador"("id", "condominioId") ON DELETE RESTRICT ON UPDATE CASCADE;

ALTER TABLE "Convite"
ADD CONSTRAINT "Convite_convidadoId_condominioId_fkey"
FOREIGN KEY ("convidadoId", "condominioId") REFERENCES "Convidado"("id", "condominioId") ON DELETE RESTRICT ON UPDATE CASCADE;

CREATE INDEX "Convidado_moradorId_ultimoUsoEm_idx" ON "Convidado"("moradorId", "ultimoUsoEm");
