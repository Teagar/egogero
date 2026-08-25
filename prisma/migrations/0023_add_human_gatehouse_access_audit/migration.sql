BEGIN;

-- This is additive: the legacy device audit remains unchanged and device-only.
-- Actor identifiers are historical values, not foreign keys, so retention or
-- account disablement cannot mutate the access trail.
CREATE TABLE "AuditoriaAcessoHumano" (
  "id" UUID NOT NULL,
  "createdAt" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "condominioId" TEXT NOT NULL,
  "accountId" UUID NOT NULL,
  "membershipId" UUID NOT NULL,
  "conviteId" TEXT,
  "moradorId" TEXT,
  "convidadoId" TEXT,
  "tipoAcesso" "TipoAcesso" NOT NULL,
  "resultado" "ResultadoAcesso" NOT NULL,
  CONSTRAINT "AuditoriaAcessoHumano_pkey" PRIMARY KEY ("id")
);

CREATE INDEX "AuditoriaAcessoHumano_operator_createdAt_idx"
ON "AuditoriaAcessoHumano"("condominioId", "accountId", "createdAt" DESC, "id" DESC);

CREATE FUNCTION reject_human_access_audit_mutation() RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  RAISE EXCEPTION 'human access audit rows are immutable' USING ERRCODE = '55000';
END;
$$;

CREATE TRIGGER "AuditoriaAcessoHumano_reject_update_delete"
BEFORE UPDATE OR DELETE ON "AuditoriaAcessoHumano"
FOR EACH ROW EXECUTE FUNCTION reject_human_access_audit_mutation();

CREATE TRIGGER "AuditoriaAcessoHumano_reject_truncate"
BEFORE TRUNCATE ON "AuditoriaAcessoHumano"
FOR EACH STATEMENT EXECUTE FUNCTION reject_human_access_audit_mutation();

REVOKE UPDATE, DELETE, TRUNCATE ON "AuditoriaAcessoHumano" FROM egogero_application, PUBLIC;

COMMIT;
