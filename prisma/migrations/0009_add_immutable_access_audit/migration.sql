BEGIN;

CREATE TYPE "TipoAcesso" AS ENUM ('pedestre', 'veiculo');
CREATE TYPE "ResultadoAcesso" AS ENUM ('permitido', 'negado');

-- IDs are intentionally historical values rather than foreign keys: soft deletion and
-- future archival of operational rows must not erase or mutate the audit trail.
CREATE TABLE "AuditoriaAcesso" (
  "id" TEXT NOT NULL,
  "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "condominioId" TEXT NOT NULL,
  "dispositivoId" TEXT NOT NULL,
  "conviteId" TEXT,
  "moradorId" TEXT,
  "convidadoId" TEXT,
  "tipoAcesso" "TipoAcesso" NOT NULL,
  "resultado" "ResultadoAcesso" NOT NULL,
  CONSTRAINT "AuditoriaAcesso_pkey" PRIMARY KEY ("id"),
  CONSTRAINT "AuditoriaAcesso_dispositivoId_check" CHECK (length("dispositivoId") > 0)
);

CREATE INDEX "AuditoriaAcesso_condominioId_moradorId_createdAt_idx"
ON "AuditoriaAcesso"("condominioId", "moradorId", "createdAt");
CREATE INDEX "AuditoriaAcesso_condominioId_createdAt_idx"
ON "AuditoriaAcesso"("condominioId", "createdAt");

CREATE FUNCTION reject_access_audit_mutation() RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  RAISE EXCEPTION 'access audit rows are immutable' USING ERRCODE = '55000';
END;
$$;

CREATE TRIGGER "AuditoriaAcesso_reject_update_delete"
BEFORE UPDATE OR DELETE ON "AuditoriaAcesso"
FOR EACH ROW EXECUTE FUNCTION reject_access_audit_mutation();

CREATE TRIGGER "AuditoriaAcesso_reject_truncate"
BEFORE TRUNCATE ON "AuditoriaAcesso"
FOR EACH STATEMENT EXECUTE FUNCTION reject_access_audit_mutation();

COMMIT;
