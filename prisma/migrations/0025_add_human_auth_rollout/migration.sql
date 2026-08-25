BEGIN;

CREATE TYPE "HumanAuthRolloutState" AS ENUM ('disabled', 'internal_provider', 'pilot', 'enabled');

CREATE TABLE "HumanAuthRolloutPolicy" (
  "scope" TEXT NOT NULL,
  "condominioId" TEXT,
  "state" "HumanAuthRolloutState" NOT NULL,
  "cohortPercentage" INTEGER,
  "cohortAlgorithm" TEXT,
  "version" INTEGER NOT NULL DEFAULT 1,
  "updatedAt" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "updatedByAccountId" UUID,
  CONSTRAINT "HumanAuthRolloutPolicy_pkey" PRIMARY KEY ("scope"),
  CONSTRAINT "HumanAuthRolloutPolicy_scope_check" CHECK (
    ("scope" = 'global' AND "condominioId" IS NULL)
    OR ("scope" = 'tenant:' || "condominioId" AND "condominioId" IS NOT NULL)
  ),
  CONSTRAINT "HumanAuthRolloutPolicy_state_check" CHECK (
    ("state" = 'pilot' AND "cohortPercentage" IN (10, 50, 100) AND "cohortAlgorithm" = 'sha256-tenant-v1')
    OR ("state" <> 'pilot' AND "cohortPercentage" IS NULL AND "cohortAlgorithm" IS NULL)
  ),
  CONSTRAINT "HumanAuthRolloutPolicy_tenant_state_check" CHECK (
    "condominioId" IS NULL OR "state" <> 'internal_provider'
  ),
  CONSTRAINT "HumanAuthRolloutPolicy_version_check" CHECK ("version" > 0),
  CONSTRAINT "HumanAuthRolloutPolicy_condominio_fkey" FOREIGN KEY ("condominioId")
    REFERENCES "Condominio"("id") ON DELETE RESTRICT ON UPDATE CASCADE
);

CREATE UNIQUE INDEX "HumanAuthRolloutPolicy_condominioId_key"
ON "HumanAuthRolloutPolicy"("condominioId") WHERE "condominioId" IS NOT NULL;

CREATE TABLE "HumanAuthRolloutHistory" (
  "id" UUID NOT NULL,
  "createdAt" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "scope" TEXT NOT NULL,
  "condominioId" TEXT,
  "previousState" "HumanAuthRolloutState",
  "previousCohortPercentage" INTEGER,
  "state" "HumanAuthRolloutState" NOT NULL,
  "cohortPercentage" INTEGER,
  "cohortAlgorithm" TEXT,
  "policyVersion" INTEGER NOT NULL,
  "actorAccountId" UUID NOT NULL,
  "requestCorrelationId" TEXT NOT NULL,
  "rollback" BOOLEAN NOT NULL,
  "revokedSessions" INTEGER NOT NULL DEFAULT 0,
  CONSTRAINT "HumanAuthRolloutHistory_pkey" PRIMARY KEY ("id"),
  CONSTRAINT "HumanAuthRolloutHistory_scope_check" CHECK (
    ("scope" = 'global' AND "condominioId" IS NULL)
    OR ("scope" = 'tenant:' || "condominioId" AND "condominioId" IS NOT NULL)
  ),
  CONSTRAINT "HumanAuthRolloutHistory_cohort_check" CHECK (
    ("state" = 'pilot' AND "cohortPercentage" IN (10, 50, 100) AND "cohortAlgorithm" = 'sha256-tenant-v1')
    OR ("state" <> 'pilot' AND "cohortPercentage" IS NULL AND "cohortAlgorithm" IS NULL)
  ),
  CONSTRAINT "HumanAuthRolloutHistory_values_check" CHECK (
    "policyVersion" > 0 AND "revokedSessions" >= 0
    AND length("requestCorrelationId") BETWEEN 1 AND 128
  )
);

CREATE INDEX "HumanAuthRolloutHistory_scope_createdAt_idx"
ON "HumanAuthRolloutHistory"("scope", "createdAt", "id");

-- Bootstrap permits only already provisioned provider identities; all tenant humans remain closed.
INSERT INTO "HumanAuthRolloutPolicy" ("scope", "state") VALUES ('global', 'internal_provider');

CREATE FUNCTION reject_human_auth_rollout_history_mutation() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION 'human auth rollout history is immutable' USING ERRCODE = '55000';
END;
$$;

CREATE TRIGGER "HumanAuthRolloutHistory_reject_update_delete"
BEFORE UPDATE OR DELETE ON "HumanAuthRolloutHistory"
FOR EACH ROW EXECUTE FUNCTION reject_human_auth_rollout_history_mutation();
CREATE TRIGGER "HumanAuthRolloutHistory_reject_truncate"
BEFORE TRUNCATE ON "HumanAuthRolloutHistory"
FOR EACH STATEMENT EXECUTE FUNCTION reject_human_auth_rollout_history_mutation();

GRANT SELECT, INSERT, UPDATE, DELETE ON "HumanAuthRolloutPolicy" TO egogero_application;
GRANT SELECT, INSERT ON "HumanAuthRolloutHistory" TO egogero_application;
REVOKE UPDATE, DELETE, TRUNCATE ON "HumanAuthRolloutHistory" FROM egogero_application, PUBLIC;

COMMIT;
