BEGIN;

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

DO $$
BEGIN
  IF EXISTS (
    SELECT 1
    FROM "Convite" AS convite
    JOIN "Morador" AS morador ON morador.id = convite."moradorId"
    WHERE convite."condominioId" <> morador."condominioId"
  ) OR EXISTS (
    SELECT 1
    FROM "Convite" AS convite
    JOIN "Convidado" AS convidado ON convidado.id = convite."convidadoId"
    WHERE convite."condominioId" <> convidado."condominioId"
  ) THEN
    RAISE EXCEPTION 'Cannot enforce condominium-scoped invitation ownership: cross-tenant rows exist';
  END IF;
END $$;

ALTER TABLE "Convite" DROP CONSTRAINT "Convite_moradorId_fkey";
ALTER TABLE "Convite" DROP CONSTRAINT "Convite_convidadoId_fkey";

ALTER TABLE "Convite"
ADD CONSTRAINT "Convite_moradorId_condominioId_fkey"
FOREIGN KEY ("moradorId", "condominioId") REFERENCES "Morador"("id", "condominioId") ON DELETE RESTRICT ON UPDATE CASCADE;

ALTER TABLE "Convite"
ADD CONSTRAINT "Convite_convidadoId_condominioId_fkey"
FOREIGN KEY ("convidadoId", "condominioId") REFERENCES "Convidado"("id", "condominioId") ON DELETE RESTRICT ON UPDATE CASCADE;

CREATE INDEX "Convidado_moradorId_ultimoUsoEm_idx" ON "Convidado"("moradorId", "ultimoUsoEm");

COMMIT;
