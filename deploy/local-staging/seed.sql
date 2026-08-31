\set ON_ERROR_STOP on

SELECT format('CREATE ROLE office_application LOGIN PASSWORD %L', :'runtime_password')
WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'office_application') \gexec
ALTER ROLE office_application PASSWORD :'runtime_password';
GRANT egogero_application TO office_application;
-- PostgreSQL requires UPDATE on at least one column for SELECT ... FOR SHARE.
-- Limit that exception to the audit timestamp, not rollout control fields.
REVOKE UPDATE ON "HumanAuthRolloutPolicy" FROM office_application;
GRANT UPDATE ("updatedAt") ON "HumanAuthRolloutPolicy" TO office_application;

SELECT format('CREATE ROLE office_monitor LOGIN PASSWORD %L', :'monitor_password')
WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'office_monitor') \gexec
ALTER ROLE office_monitor PASSWORD :'monitor_password';
GRANT pg_monitor TO office_monitor;

INSERT INTO "HumanAccount" (id, "updatedAt", "displayName", status)
VALUES ('46000000-0000-4000-8000-000000000001', clock_timestamp(), 'Local Staging Operator', 'active')
ON CONFLICT (id) DO UPDATE SET "displayName" = EXCLUDED."displayName", status = 'active', "disabledAt" = NULL;

INSERT INTO "ExternalIdentity" (id, "accountId", issuer, subject, email, "emailVerified")
VALUES (
  '46000000-0000-4000-8000-000000000002',
  '46000000-0000-4000-8000-000000000001',
  'https://auth.localhost:8443/realms/office',
  '46000000-0000-4000-8000-000000000100',
  'operator@local.invalid',
  true
)
ON CONFLICT (issuer, subject) DO UPDATE SET email = EXCLUDED.email, "emailVerified" = true;

INSERT INTO "HumanMembership" (id, "accountId", role, status)
VALUES (
  '46000000-0000-4000-8000-000000000003',
  '46000000-0000-4000-8000-000000000001',
  'provedor',
  'active'
)
ON CONFLICT (id) DO UPDATE SET status = 'active', "disabledAt" = NULL;

INSERT INTO "HumanAuthRolloutPolicy" (
  scope, "condominioId", state, "cohortPercentage", "cohortAlgorithm", version, "updatedAt", "updatedByAccountId"
)
VALUES ('global', NULL, 'internal_provider', NULL, NULL, 1, clock_timestamp(), NULL)
ON CONFLICT (scope) DO UPDATE SET
  state = 'internal_provider',
  "cohortPercentage" = NULL,
  "cohortAlgorithm" = NULL,
  version = "HumanAuthRolloutPolicy".version + 1,
  "updatedAt" = clock_timestamp(),
  "updatedByAccountId" = NULL;
