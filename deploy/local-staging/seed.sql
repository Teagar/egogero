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

INSERT INTO "Condominio" (id, nome, responsavel, tipo, timezone, "deletedAt")
VALUES (
  '46000000-0000-4000-8000-000000000050',
  'Condominio Demonstracao',
  'Equipe Local',
  'residencial',
  'America/Sao_Paulo',
  NULL
)
ON CONFLICT (id) DO UPDATE SET
  nome = EXCLUDED.nome,
  responsavel = EXCLUDED.responsavel,
  tipo = EXCLUDED.tipo,
  timezone = EXCLUDED.timezone,
  "deletedAt" = NULL;

INSERT INTO "Morador" (id, nome, "enderecoBloco", "enderecoApartamento", "condominioId", "deletedAt")
VALUES (
  '46000000-0000-4000-8000-000000000051',
  'Morador Demonstracao',
  'A',
  '101',
  '46000000-0000-4000-8000-000000000050',
  NULL
)
ON CONFLICT (id) DO UPDATE SET
  nome = EXCLUDED.nome,
  "enderecoBloco" = EXCLUDED."enderecoBloco",
  "enderecoApartamento" = EXCLUDED."enderecoApartamento",
  "condominioId" = EXCLUDED."condominioId",
  "deletedAt" = NULL;

INSERT INTO "HumanAccount" (id, "updatedAt", "displayName", status)
VALUES
  ('46000000-0000-4000-8000-000000000001', clock_timestamp(), 'Provedor Local', 'active'),
  ('46000000-0000-4000-8000-000000000011', clock_timestamp(), 'Sindico Local', 'active'),
  ('46000000-0000-4000-8000-000000000021', clock_timestamp(), 'Morador Local', 'active'),
  ('46000000-0000-4000-8000-000000000031', clock_timestamp(), 'Portaria Local', 'active')
ON CONFLICT (id) DO UPDATE SET "displayName" = EXCLUDED."displayName", status = 'active', "disabledAt" = NULL;

INSERT INTO "ExternalIdentity" (id, "accountId", issuer, subject, email, "emailVerified")
VALUES
  ('46000000-0000-4000-8000-000000000002', '46000000-0000-4000-8000-000000000001', 'https://auth.localhost:8443/realms/office', '46000000-0000-4000-8000-000000000100', 'provedor@local.invalid', true),
  ('46000000-0000-4000-8000-000000000012', '46000000-0000-4000-8000-000000000011', 'https://auth.localhost:8443/realms/office', '46000000-0000-4000-8000-000000000200', 'sindico@local.invalid', true),
  ('46000000-0000-4000-8000-000000000022', '46000000-0000-4000-8000-000000000021', 'https://auth.localhost:8443/realms/office', '46000000-0000-4000-8000-000000000300', 'morador@local.invalid', true),
  ('46000000-0000-4000-8000-000000000032', '46000000-0000-4000-8000-000000000031', 'https://auth.localhost:8443/realms/office', '46000000-0000-4000-8000-000000000400', 'portaria@local.invalid', true)
ON CONFLICT (issuer, subject) DO UPDATE SET
  "accountId" = EXCLUDED."accountId",
  email = EXCLUDED.email,
  "emailVerified" = true;

INSERT INTO "HumanMembership" (id, "accountId", "condominioId", "residentId", role, status)
VALUES
  ('46000000-0000-4000-8000-000000000003', '46000000-0000-4000-8000-000000000001', NULL, NULL, 'provedor', 'active'),
  ('46000000-0000-4000-8000-000000000013', '46000000-0000-4000-8000-000000000011', '46000000-0000-4000-8000-000000000050', NULL, 'sindico', 'active'),
  ('46000000-0000-4000-8000-000000000023', '46000000-0000-4000-8000-000000000021', '46000000-0000-4000-8000-000000000050', '46000000-0000-4000-8000-000000000051', 'morador', 'active'),
  ('46000000-0000-4000-8000-000000000033', '46000000-0000-4000-8000-000000000031', '46000000-0000-4000-8000-000000000050', NULL, 'portaria', 'active')
ON CONFLICT (id) DO UPDATE SET
  "accountId" = EXCLUDED."accountId",
  "condominioId" = EXCLUDED."condominioId",
  "residentId" = EXCLUDED."residentId",
  role = EXCLUDED.role,
  status = 'active',
  "disabledAt" = NULL;

INSERT INTO "HumanAuthRolloutPolicy" (
  scope, "condominioId", state, "cohortPercentage", "cohortAlgorithm", version, "updatedAt", "updatedByAccountId"
)
VALUES
  ('global', NULL, 'enabled', NULL, NULL, 1, clock_timestamp(), NULL),
  ('tenant:46000000-0000-4000-8000-000000000050', '46000000-0000-4000-8000-000000000050', 'enabled', NULL, NULL, 1, clock_timestamp(), NULL)
ON CONFLICT (scope) DO UPDATE SET
  state = EXCLUDED.state,
  "condominioId" = EXCLUDED."condominioId",
  "cohortPercentage" = NULL,
  "cohortAlgorithm" = NULL,
  version = "HumanAuthRolloutPolicy".version + 1,
  "updatedAt" = clock_timestamp(),
  "updatedByAccountId" = NULL;
