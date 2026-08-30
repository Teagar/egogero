BEGIN;

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'egogero_rollout_owner') THEN
    CREATE ROLE egogero_rollout_owner NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'egogero_rollout_approver') THEN
    CREATE ROLE egogero_rollout_approver NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT;
  END IF;
END;
$$;

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
  "operatorIdentifier" TEXT NOT NULL,
  "approvalReference" TEXT NOT NULL,
  "requestCorrelationId" TEXT,
  CONSTRAINT "HumanAuthDeploymentAuthorization_pkey" PRIMARY KEY ("id"),
  CONSTRAINT "HumanAuthDeploymentAuthorization_tokenDigest_key" UNIQUE ("tokenDigest"),
  CONSTRAINT "HumanAuthDeploymentAuthorization_values_check" CHECK (
    octet_length("tokenDigest") = 32 AND "expiresAt" > "createdAt"
    AND "expiresAt" <= "createdAt" + interval '10 minutes'
    AND "operatorIdentifier" ~ '^[A-Za-z0-9][A-Za-z0-9._:@/-]{0,127}$'
    AND "approvalReference" ~ '^[A-Za-z0-9][A-Za-z0-9._:@/-]{0,127}$'
    AND ("requestCorrelationId" IS NULL OR length("requestCorrelationId") BETWEEN 1 AND 128)
    AND ("scope" = 'global' OR "scope" ~ '^tenant:[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$')
    AND (("state" = 'pilot' AND "cohortPercentage" IN (10, 50, 100))
      OR ("state" <> 'pilot' AND "cohortPercentage" IS NULL))
  )
);

ALTER TABLE "HumanAuthRolloutHistory"
  ADD COLUMN "deploymentAuthorizationId" UUID,
  ADD COLUMN "deploymentOperatorIdentifier" TEXT,
  ADD COLUMN "deploymentApprovalReference" TEXT,
  ADD CONSTRAINT "HumanAuthRolloutHistory_deployment_binding_check" CHECK (
    ("deploymentAuthorizationId" IS NULL AND "deploymentOperatorIdentifier" IS NULL AND "deploymentApprovalReference" IS NULL)
    OR ("deploymentAuthorizationId" IS NOT NULL
      AND "deploymentOperatorIdentifier" ~ '^[A-Za-z0-9][A-Za-z0-9._:@/-]{0,127}$'
      AND "deploymentApprovalReference" ~ '^[A-Za-z0-9][A-Za-z0-9._:@/-]{0,127}$')
  );

CREATE FUNCTION set_human_auth_rollout_policy(
  requested_scope TEXT,
  requested_state "HumanAuthRolloutState",
  requested_cohort INTEGER,
  requested_actor UUID,
  correlation_id TEXT,
  browser_session_id UUID DEFAULT NULL,
  deployment_token_digest BYTEA DEFAULT NULL
) RETURNS TABLE(result_scope TEXT, result_state "HumanAuthRolloutState", "resultCohortPercentage" INTEGER,
  result_version INTEGER, "resultRevokedSessions" INTEGER)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
  tenant_id TEXT;
  previous public."HumanAuthRolloutPolicy"%ROWTYPE;
  next_version INTEGER;
  cohort_algorithm TEXT;
  revoked_count INTEGER;
  deployment_id UUID;
  deployment_operator TEXT;
  deployment_reference TEXT;
  restrictive BOOLEAN;
BEGIN
  IF length(correlation_id) NOT BETWEEN 1 AND 128
    OR (browser_session_id IS NULL) = (deployment_token_digest IS NULL)
    OR (requested_scope <> 'global' AND requested_scope !~ '^tenant:[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$')
    OR (requested_scope <> 'global' AND requested_state = 'internal_provider')
    OR ((requested_state = 'pilot') <> (requested_cohort IN (10, 50, 100))) THEN
    RETURN;
  END IF;
  tenant_id := CASE WHEN requested_scope = 'global' THEN NULL ELSE substring(requested_scope FROM 8) END;

  PERFORM pg_advisory_xact_lock(hashtextextended('global', 170030));
  IF requested_scope <> 'global' THEN
    PERFORM pg_advisory_xact_lock(hashtextextended(requested_scope, 170030));
  END IF;

  IF browser_session_id IS NOT NULL THEN
    PERFORM 1
    FROM public."BrowserSession" session
    JOIN public."HumanAccount" account ON account.id = session."accountId"
    JOIN public."HumanMembership" membership ON membership.id = session."activeMembershipId"
      AND membership."accountId" = account.id
    WHERE session.id = browser_session_id AND account.id = requested_actor
      AND session."revokedAt" IS NULL AND session."idleExpiresAt" > clock_timestamp()
      AND session."absoluteExpiresAt" > clock_timestamp()
      AND session."authenticatedAt" >= clock_timestamp() - interval '10 minutes'
      AND session."authenticatedAt" <= clock_timestamp()
      AND session."accountSessionVersion" = account."sessionVersion"
      AND account.status = 'active' AND membership.status = 'active'
      AND membership.role = 'provedor' AND membership."condominioId" IS NULL
      AND EXISTS (SELECT 1 FROM public."ExternalIdentity" identity WHERE identity."accountId" = account.id)
    FOR SHARE OF session, account, membership;
    IF NOT FOUND THEN RETURN; END IF;
  ELSE
    UPDATE public."HumanAuthDeploymentAuthorization" AS deployment_auth
    SET "usedAt" = clock_timestamp(), "requestCorrelationId" = correlation_id
    WHERE deployment_auth."tokenDigest" = deployment_token_digest
      AND deployment_auth."usedAt" IS NULL AND deployment_auth."expiresAt" > clock_timestamp()
      AND deployment_auth."createdAt" <= clock_timestamp()
      AND deployment_auth."actorAccountId" = requested_actor AND deployment_auth.scope = requested_scope
      AND deployment_auth.state = requested_state
      AND deployment_auth."cohortPercentage" IS NOT DISTINCT FROM requested_cohort
      AND EXISTS (
        SELECT 1 FROM public."HumanAccount" account
        JOIN public."HumanMembership" membership ON membership."accountId" = account.id
          AND membership.role = 'provedor' AND membership.status = 'active'
        WHERE account.id = requested_actor AND account.status = 'active'
          AND EXISTS (SELECT 1 FROM public."ExternalIdentity" identity WHERE identity."accountId" = account.id)
      )
    RETURNING deployment_auth.id, deployment_auth."operatorIdentifier", deployment_auth."approvalReference"
      INTO deployment_id, deployment_operator, deployment_reference;
    IF deployment_id IS NULL THEN RETURN; END IF;
  END IF;

  SELECT * INTO previous FROM public."HumanAuthRolloutPolicy" policy
    WHERE policy.scope = requested_scope FOR UPDATE;
  IF tenant_id IS NOT NULL AND NOT EXISTS (
    SELECT 1 FROM public."Condominio" WHERE id = tenant_id AND "deletedAt" IS NULL FOR SHARE
  ) THEN RETURN; END IF;

  next_version := COALESCE(previous.version, 0) + 1;
  cohort_algorithm := CASE WHEN requested_state = 'pilot' THEN 'sha256-tenant-v1' ELSE NULL END;
  restrictive := previous.scope IS NULL AND requested_state <> 'enabled'
    OR requested_state = 'disabled'
    OR requested_state = 'internal_provider' AND previous.state NOT IN ('disabled', 'internal_provider')
    OR requested_state = 'pilot' AND (previous.state = 'enabled'
      OR previous.state = 'pilot' AND COALESCE(previous."cohortPercentage", 0) > COALESCE(requested_cohort, 0));

  INSERT INTO public."HumanAuthRolloutPolicy" AS policy
    (scope, "condominioId", state, "cohortPercentage", "cohortAlgorithm", version, "updatedAt", "updatedByAccountId")
  VALUES (requested_scope, tenant_id, requested_state, requested_cohort, cohort_algorithm,
    next_version, clock_timestamp(), requested_actor)
  ON CONFLICT (scope) DO UPDATE SET state = EXCLUDED.state,
    "cohortPercentage" = EXCLUDED."cohortPercentage", "cohortAlgorithm" = EXCLUDED."cohortAlgorithm",
    version = EXCLUDED.version, "updatedAt" = EXCLUDED."updatedAt",
    "updatedByAccountId" = EXCLUDED."updatedByAccountId";

  WITH effective AS MATERIALIZED (
    SELECT session.id, membership.role = 'provedor' AS provider,
      global_policy.state::text AS global_state,
      global_policy."cohortPercentage" AS global_percentage,
      global_policy."cohortAlgorithm" AS global_algorithm,
      tenant_policy.state::text AS tenant_state,
      tenant_policy."cohortPercentage" AS tenant_percentage,
      tenant_policy."cohortAlgorithm" AS tenant_algorithm,
      CASE WHEN membership."condominioId" IS NULL THEN NULL ELSE
        (get_byte(sha256(convert_to('sha256-tenant-v1', 'UTF8') || decode('00', 'hex') || convert_to(membership."condominioId", 'UTF8')), 0)::bigint * 16777216
        + get_byte(sha256(convert_to('sha256-tenant-v1', 'UTF8') || decode('00', 'hex') || convert_to(membership."condominioId", 'UTF8')), 1)::bigint * 65536
        + get_byte(sha256(convert_to('sha256-tenant-v1', 'UTF8') || decode('00', 'hex') || convert_to(membership."condominioId", 'UTF8')), 2)::bigint * 256
        + get_byte(sha256(convert_to('sha256-tenant-v1', 'UTF8') || decode('00', 'hex') || convert_to(membership."condominioId", 'UTF8')), 3)::bigint) % 100 + 1 END AS cohort
    FROM public."BrowserSession" session
    JOIN public."HumanMembership" membership ON membership.id = session."activeMembershipId"
      AND membership."accountId" = session."accountId"
    LEFT JOIN public."HumanAuthRolloutPolicy" global_policy ON global_policy.scope = 'global'
    LEFT JOIN public."HumanAuthRolloutPolicy" tenant_policy ON tenant_policy.scope = 'tenant:' || membership."condominioId"
    WHERE session."revokedAt" IS NULL AND (tenant_id IS NULL OR membership."condominioId" = tenant_id)
  ), revoked AS (
    UPDATE public."BrowserSession" session SET "revokedAt" = clock_timestamp(),
      "revokeReason" = 'human_auth_policy_change' FROM effective
    WHERE session.id = effective.id AND ((effective.provider AND effective.global_state IN ('internal_provider', 'pilot', 'enabled'))
      OR (NOT effective.provider AND (effective.global_state = 'enabled' OR (effective.global_state = 'pilot'
        AND effective.global_algorithm = 'sha256-tenant-v1' AND effective.global_percentage IN (10, 50, 100)
        AND effective.cohort <= effective.global_percentage))
      AND (effective.tenant_state = 'enabled' OR (effective.tenant_state = 'pilot'
        AND effective.tenant_algorithm = 'sha256-tenant-v1' AND effective.tenant_percentage IN (10, 50, 100)
        AND effective.cohort <= effective.tenant_percentage)))) IS NOT TRUE RETURNING 1
  ) SELECT count(*)::integer INTO revoked_count FROM revoked;

  INSERT INTO public."HumanAuthRolloutHistory" (
    id, scope, "condominioId", "previousState", "previousCohortPercentage", state,
    "cohortPercentage", "cohortAlgorithm", "policyVersion", "actorAccountId",
    "requestCorrelationId", rollback, "revokedSessions", "deploymentAuthorizationId",
    "deploymentOperatorIdentifier", "deploymentApprovalReference"
  ) VALUES (gen_random_uuid(), requested_scope, tenant_id, previous.state, previous."cohortPercentage",
    requested_state, requested_cohort, cohort_algorithm, next_version, requested_actor, correlation_id,
    restrictive OR revoked_count > 0, revoked_count, deployment_id, deployment_operator, deployment_reference);

  RETURN QUERY SELECT requested_scope, requested_state, requested_cohort, next_version, revoked_count;
END;
$$;

ALTER TABLE "HumanAuthDeploymentAuthorization" OWNER TO egogero_rollout_owner;
ALTER TABLE "HumanAuthRolloutPolicy" OWNER TO egogero_rollout_owner;
ALTER TABLE "HumanAuthRolloutHistory" OWNER TO egogero_rollout_owner;
ALTER FUNCTION set_human_auth_rollout_policy(TEXT, "HumanAuthRolloutState", INTEGER, UUID, TEXT, UUID, BYTEA)
  OWNER TO egogero_rollout_owner;

REVOKE ALL ON "HumanAuthDeploymentAuthorization", "HumanAuthRolloutPolicy", "HumanAuthRolloutHistory" FROM PUBLIC, egogero_application;
REVOKE ALL ON FUNCTION set_human_auth_rollout_policy(TEXT, "HumanAuthRolloutState", INTEGER, UUID, TEXT, UUID, BYTEA) FROM PUBLIC;
GRANT SELECT ON "HumanAuthRolloutPolicy", "HumanAuthRolloutHistory" TO egogero_application;
GRANT EXECUTE ON FUNCTION set_human_auth_rollout_policy(TEXT, "HumanAuthRolloutState", INTEGER, UUID, TEXT, UUID, BYTEA) TO egogero_application;
GRANT SELECT ON "BrowserSession", "HumanAccount", "HumanMembership", "ExternalIdentity", "Condominio" TO egogero_rollout_owner;
GRANT UPDATE ON "HumanAccount", "HumanMembership", "Condominio" TO egogero_rollout_owner;
GRANT UPDATE ("revokedAt", "revokeReason") ON "BrowserSession" TO egogero_rollout_owner;
GRANT USAGE ON SCHEMA public TO egogero_rollout_approver;
GRANT INSERT ON "HumanAuthDeploymentAuthorization" TO egogero_rollout_approver;

COMMIT;
