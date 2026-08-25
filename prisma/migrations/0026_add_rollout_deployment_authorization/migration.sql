BEGIN;

CREATE TABLE "HumanAuthDeploymentAuthorization" (
  "id" UUID NOT NULL,
  "createdAt" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "expiresAt" TIMESTAMPTZ(3) NOT NULL,
  "usedAt" TIMESTAMPTZ(3),
  "tokenDigest" BYTEA NOT NULL,
  "actorAccountId" UUID NOT NULL,
  "scope" TEXT NOT NULL,
  "state" "HumanAuthRolloutState" NOT NULL,
  "cohortPercentage" INTEGER,
  "approvalReference" TEXT NOT NULL,
  "requestCorrelationId" TEXT,
  CONSTRAINT "HumanAuthDeploymentAuthorization_pkey" PRIMARY KEY ("id"),
  CONSTRAINT "HumanAuthDeploymentAuthorization_tokenDigest_key" UNIQUE ("tokenDigest"),
  CONSTRAINT "HumanAuthDeploymentAuthorization_values_check" CHECK (
    length("tokenDigest") = 32 AND "expiresAt" > "createdAt"
    AND "expiresAt" <= "createdAt" + interval '10 minutes'
    AND length("approvalReference") BETWEEN 1 AND 128
    AND ("requestCorrelationId" IS NULL OR length("requestCorrelationId") BETWEEN 1 AND 128)
    AND (("scope" = 'global') OR "scope" ~ '^tenant:[0-9a-f-]{36}$')
    AND (("state" = 'pilot' AND "cohortPercentage" IN (10, 50, 100))
      OR ("state" <> 'pilot' AND "cohortPercentage" IS NULL))
  )
);

CREATE FUNCTION enforce_human_auth_deployment_authorization_immutability() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  IF TG_OP = 'DELETE' OR OLD."usedAt" IS NOT NULL
    OR NEW.id <> OLD.id OR NEW."createdAt" <> OLD."createdAt" OR NEW."expiresAt" <> OLD."expiresAt"
    OR NEW."tokenDigest" <> OLD."tokenDigest" OR NEW."actorAccountId" <> OLD."actorAccountId"
    OR NEW.scope <> OLD.scope OR NEW.state <> OLD.state
    OR NEW."cohortPercentage" IS DISTINCT FROM OLD."cohortPercentage"
    OR NEW."approvalReference" <> OLD."approvalReference"
    OR NEW."usedAt" IS NULL OR NEW."requestCorrelationId" IS NULL THEN
    RAISE EXCEPTION 'human auth deployment authorization is immutable' USING ERRCODE = '55000';
  END IF;
  RETURN NEW;
END;
$$;

CREATE TRIGGER "HumanAuthDeploymentAuthorization_immutable"
BEFORE UPDATE OR DELETE ON "HumanAuthDeploymentAuthorization"
FOR EACH ROW EXECUTE FUNCTION enforce_human_auth_deployment_authorization_immutability();

REVOKE ALL ON "HumanAuthDeploymentAuthorization" FROM PUBLIC;
GRANT SELECT ON "HumanAuthDeploymentAuthorization" TO egogero_application;
GRANT UPDATE ("usedAt", "requestCorrelationId") ON "HumanAuthDeploymentAuthorization" TO egogero_application;

COMMIT;
