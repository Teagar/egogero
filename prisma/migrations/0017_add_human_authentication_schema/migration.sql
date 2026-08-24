BEGIN;

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'egogero_application') THEN
    CREATE ROLE egogero_application NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT;
  ELSIF EXISTS (
    SELECT 1 FROM pg_roles
    WHERE rolname = 'egogero_application'
      AND (rolcanlogin OR rolsuper OR rolcreatedb OR rolcreaterole)
  ) THEN
    RAISE EXCEPTION 'egogero_application has unsafe role attributes';
  END IF;
END;
$$;

CREATE TYPE "HumanAccountStatus" AS ENUM ('invited', 'active', 'suspended', 'disabled');
CREATE TYPE "HumanMembershipStatus" AS ENUM ('invited', 'active', 'disabled');
CREATE TYPE "HumanRole" AS ENUM ('provedor', 'sindico', 'morador', 'portaria');
CREATE TYPE "AuthenticationOutcome" AS ENUM ('success', 'failure', 'denied');
CREATE TYPE "AuthenticationActorType" AS ENUM ('human', 'device', 'system', 'anonymous');

CREATE TABLE "HumanAccount" (
  "id" UUID NOT NULL,
  "createdAt" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "updatedAt" TIMESTAMPTZ(3) NOT NULL,
  "displayName" TEXT NOT NULL,
  "status" "HumanAccountStatus" NOT NULL DEFAULT 'invited',
  "sessionVersion" INTEGER NOT NULL DEFAULT 0,
  "disabledAt" TIMESTAMPTZ(3),
  CONSTRAINT "HumanAccount_pkey" PRIMARY KEY ("id"),
  CONSTRAINT "HumanAccount_display_name_check" CHECK (length(btrim("displayName")) BETWEEN 1 AND 200),
  CONSTRAINT "HumanAccount_session_version_check" CHECK ("sessionVersion" >= 0),
  CONSTRAINT "HumanAccount_disabled_check" CHECK (("status" = 'disabled') = ("disabledAt" IS NOT NULL))
);

CREATE TABLE "ExternalIdentity" (
  "id" UUID NOT NULL,
  "createdAt" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "lastLoginAt" TIMESTAMPTZ(3),
  "accountId" UUID NOT NULL,
  "issuer" TEXT NOT NULL,
  "subject" TEXT NOT NULL,
  "email" TEXT,
  "emailVerified" BOOLEAN NOT NULL DEFAULT false,
  CONSTRAINT "ExternalIdentity_pkey" PRIMARY KEY ("id"),
  CONSTRAINT "ExternalIdentity_issuer_check" CHECK ("issuer" ~ '^https://[^/?#[:space:]]+([^?#[:space:]]*)?$'),
  CONSTRAINT "ExternalIdentity_subject_check" CHECK (length("subject") BETWEEN 1 AND 255),
  CONSTRAINT "ExternalIdentity_login_time_check" CHECK ("lastLoginAt" IS NULL OR "lastLoginAt" >= "createdAt")
);

CREATE TABLE "HumanMembership" (
  "id" UUID NOT NULL,
  "createdAt" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "disabledAt" TIMESTAMPTZ(3),
  "accountId" UUID NOT NULL,
  "condominioId" TEXT,
  "residentId" TEXT,
  "role" "HumanRole" NOT NULL,
  "status" "HumanMembershipStatus" NOT NULL DEFAULT 'invited',
  CONSTRAINT "HumanMembership_pkey" PRIMARY KEY ("id"),
  CONSTRAINT "HumanMembership_id_accountId_key" UNIQUE ("id", "accountId"),
  CONSTRAINT "HumanMembership_scope_check" CHECK (
    ("role" = 'provedor' AND "condominioId" IS NULL AND "residentId" IS NULL)
    OR ("role" IN ('sindico', 'portaria') AND "condominioId" IS NOT NULL AND "residentId" IS NULL)
    OR ("role" = 'morador' AND "condominioId" IS NOT NULL AND "residentId" IS NOT NULL)
  ),
  CONSTRAINT "HumanMembership_disabled_check" CHECK (("status" = 'disabled') = ("disabledAt" IS NOT NULL)),
  CONSTRAINT "HumanMembership_disabled_time_check" CHECK ("disabledAt" IS NULL OR "disabledAt" >= "createdAt")
);

CREATE TABLE "OidcLoginTransaction" (
  "id" UUID NOT NULL,
  "createdAt" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "expiresAt" TIMESTAMPTZ(3) NOT NULL,
  "consumedAt" TIMESTAMPTZ(3),
  "stateDigest" BYTEA NOT NULL,
  "nonceDigest" BYTEA NOT NULL,
  "pkceVerifierCiphertext" BYTEA NOT NULL,
  "pkceVerifierNonce" BYTEA NOT NULL,
  "pkceVerifierAuthTag" BYTEA NOT NULL,
  "pkceKeyVersion" INTEGER NOT NULL,
  "issuer" TEXT NOT NULL,
  "clientId" TEXT NOT NULL,
  "redirectUri" TEXT NOT NULL,
  "returnTo" TEXT NOT NULL,
  "recoveryIntent" BOOLEAN NOT NULL DEFAULT false,
  CONSTRAINT "OidcLoginTransaction_pkey" PRIMARY KEY ("id"),
  CONSTRAINT "OidcLoginTransaction_crypto_check" CHECK (
    octet_length("stateDigest") = 32 AND octet_length("nonceDigest") = 32
    AND octet_length("pkceVerifierCiphertext") BETWEEN 43 AND 128
    AND octet_length("pkceVerifierNonce") = 12
    AND octet_length("pkceVerifierAuthTag") = 16
    AND "pkceKeyVersion" > 0
  ),
  CONSTRAINT "OidcLoginTransaction_time_check" CHECK (
    "expiresAt" > "createdAt" AND ("consumedAt" IS NULL OR "consumedAt" >= "createdAt")
  ),
  CONSTRAINT "OidcLoginTransaction_issuer_check" CHECK ("issuer" ~ '^https://[^/?#[:space:]]+([^?#[:space:]]*)?$'),
  CONSTRAINT "OidcLoginTransaction_aad_check" CHECK (
    length("clientId") BETWEEN 1 AND 255 AND "redirectUri" ~ '^https://[^[:space:]]+$'
  ),
  CONSTRAINT "OidcLoginTransaction_return_to_check" CHECK (
    left("returnTo", 1) = '/' AND left("returnTo", 2) <> '//' AND "returnTo" !~ '[[:cntrl:]]'
  )
);

CREATE TABLE "BrowserSession" (
  "id" UUID NOT NULL,
  "familyId" UUID NOT NULL,
  "createdAt" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "lastSeenAt" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "idleExpiresAt" TIMESTAMPTZ(3) NOT NULL,
  "absoluteExpiresAt" TIMESTAMPTZ(3) NOT NULL,
  "authenticatedAt" TIMESTAMPTZ(3) NOT NULL,
  "revokedAt" TIMESTAMPTZ(3),
  "revokeReason" TEXT,
  "tokenDigest" BYTEA NOT NULL,
  "csrfDigest" BYTEA NOT NULL,
  "csrfCiphertext" BYTEA NOT NULL,
  "csrfNonce" BYTEA NOT NULL,
  "csrfAuthTag" BYTEA NOT NULL,
  "csrfKeyVersion" INTEGER NOT NULL,
  "accountId" UUID NOT NULL,
  "accountSessionVersion" INTEGER NOT NULL,
  "activeMembershipId" UUID NOT NULL,
  "ipPrefix" TEXT,
  "userAgentHash" BYTEA,
  CONSTRAINT "BrowserSession_pkey" PRIMARY KEY ("id"),
  CONSTRAINT "BrowserSession_token_check" CHECK (octet_length("tokenDigest") = 32),
  CONSTRAINT "BrowserSession_csrf_check" CHECK (
    octet_length("csrfDigest") = 32 AND octet_length("csrfCiphertext") = 32
    AND octet_length("csrfNonce") = 12 AND octet_length("csrfAuthTag") = 16
    AND "csrfKeyVersion" > 0
  ),
  CONSTRAINT "BrowserSession_version_check" CHECK ("accountSessionVersion" >= 0),
  CONSTRAINT "BrowserSession_time_check" CHECK (
    "authenticatedAt" <= "createdAt" AND "lastSeenAt" >= "createdAt"
    AND "idleExpiresAt" > "lastSeenAt" AND "absoluteExpiresAt" >= "idleExpiresAt"
  ),
  CONSTRAINT "BrowserSession_revocation_check" CHECK (("revokedAt" IS NULL) = ("revokeReason" IS NULL)),
  CONSTRAINT "BrowserSession_revocation_time_check" CHECK ("revokedAt" IS NULL OR "revokedAt" >= "createdAt"),
  CONSTRAINT "BrowserSession_ip_prefix_check" CHECK ("ipPrefix" IS NULL OR length("ipPrefix") BETWEEN 1 AND 64),
  CONSTRAINT "BrowserSession_user_agent_check" CHECK ("userAgentHash" IS NULL OR octet_length("userAgentHash") = 32)
);

-- Historical identifiers intentionally have no foreign keys so account lifecycle
-- cannot erase or mutate security evidence.
CREATE TABLE "AuthenticationAuditEvent" (
  "id" UUID NOT NULL,
  "createdAt" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "eventType" TEXT NOT NULL,
  "outcome" "AuthenticationOutcome" NOT NULL,
  "accountId" UUID,
  "externalIdentityId" UUID,
  "sessionId" UUID,
  "membershipId" UUID,
  "condominioId" TEXT,
  "actorType" "AuthenticationActorType" NOT NULL,
  "actorId" TEXT,
  "requestCorrelationId" TEXT NOT NULL,
  "ipPrefix" TEXT,
  "userAgentHash" BYTEA,
  "reasonCode" TEXT,
  "metadata" JSONB NOT NULL DEFAULT '{}',
  CONSTRAINT "AuthenticationAuditEvent_pkey" PRIMARY KEY ("id"),
  CONSTRAINT "AuthenticationAuditEvent_event_type_check" CHECK ("eventType" ~ '^[a-z][a-z0-9_]{0,99}$'),
  CONSTRAINT "AuthenticationAuditEvent_correlation_check" CHECK (length("requestCorrelationId") BETWEEN 1 AND 128),
  CONSTRAINT "AuthenticationAuditEvent_actor_check" CHECK (
    ("actorType" IN ('human', 'device') AND "actorId" IS NOT NULL)
    OR "actorType" = 'system'
    OR ("actorType" = 'anonymous' AND "actorId" IS NULL)
  ),
  CONSTRAINT "AuthenticationAuditEvent_ip_prefix_check" CHECK ("ipPrefix" IS NULL OR length("ipPrefix") BETWEEN 1 AND 64),
  CONSTRAINT "AuthenticationAuditEvent_user_agent_check" CHECK ("userAgentHash" IS NULL OR octet_length("userAgentHash") = 32),
  CONSTRAINT "AuthenticationAuditEvent_reason_check" CHECK ("reasonCode" IS NULL OR "reasonCode" ~ '^[a-z][a-z0-9_]{0,99}$'),
  CONSTRAINT "AuthenticationAuditEvent_metadata_check" CHECK (jsonb_typeof("metadata") = 'object')
);

CREATE UNIQUE INDEX "ExternalIdentity_issuer_subject_key" ON "ExternalIdentity"("issuer", "subject");
CREATE INDEX "ExternalIdentity_accountId_idx" ON "ExternalIdentity"("accountId");
CREATE INDEX "HumanMembership_accountId_status_idx" ON "HumanMembership"("accountId", "status");
CREATE INDEX "HumanMembership_condominioId_status_idx" ON "HumanMembership"("condominioId", "status");
CREATE INDEX "HumanMembership_residentId_condominioId_idx" ON "HumanMembership"("residentId", "condominioId");
CREATE UNIQUE INDEX "HumanMembership_active_provider_key" ON "HumanMembership"("accountId") WHERE "status" = 'active' AND "role" = 'provedor';
CREATE UNIQUE INDEX "HumanMembership_active_tenant_role_key" ON "HumanMembership"("accountId", "condominioId", "role") WHERE "status" = 'active' AND "role" <> 'provedor';
CREATE UNIQUE INDEX "OidcLoginTransaction_stateDigest_key" ON "OidcLoginTransaction"("stateDigest");
CREATE INDEX "OidcLoginTransaction_expiresAt_consumedAt_idx" ON "OidcLoginTransaction"("expiresAt", "consumedAt");
CREATE UNIQUE INDEX "BrowserSession_tokenDigest_key" ON "BrowserSession"("tokenDigest");
CREATE INDEX "BrowserSession_accountId_revokedAt_idx" ON "BrowserSession"("accountId", "revokedAt");
CREATE INDEX "BrowserSession_idleExpiresAt_absoluteExpiresAt_idx" ON "BrowserSession"("idleExpiresAt", "absoluteExpiresAt");
CREATE INDEX "BrowserSession_activeMembershipId_idx" ON "BrowserSession"("activeMembershipId");
CREATE INDEX "BrowserSession_familyId_idx" ON "BrowserSession"("familyId");
CREATE INDEX "BrowserSession_retention_idx"
  ON "BrowserSession"((LEAST("revokedAt", "idleExpiresAt", "absoluteExpiresAt")), id);
CREATE INDEX "OidcLoginTransaction_retention_idx"
  ON "OidcLoginTransaction"((LEAST("consumedAt", "expiresAt")), id);
CREATE INDEX "AuthenticationAuditEvent_accountId_createdAt_idx" ON "AuthenticationAuditEvent"("accountId", "createdAt");
CREATE INDEX "AuthenticationAuditEvent_condominioId_createdAt_idx" ON "AuthenticationAuditEvent"("condominioId", "createdAt");
CREATE INDEX "AuthenticationAuditEvent_eventType_createdAt_idx" ON "AuthenticationAuditEvent"("eventType", "createdAt");
CREATE INDEX "AuthenticationAuditEvent_createdAt_idx" ON "AuthenticationAuditEvent"("createdAt");

ALTER TABLE "ExternalIdentity" ADD CONSTRAINT "ExternalIdentity_accountId_fkey"
  FOREIGN KEY ("accountId") REFERENCES "HumanAccount"("id") ON DELETE RESTRICT ON UPDATE CASCADE;
ALTER TABLE "HumanMembership" ADD CONSTRAINT "HumanMembership_accountId_fkey"
  FOREIGN KEY ("accountId") REFERENCES "HumanAccount"("id") ON DELETE RESTRICT ON UPDATE CASCADE;
ALTER TABLE "HumanMembership" ADD CONSTRAINT "HumanMembership_condominioId_fkey"
  FOREIGN KEY ("condominioId") REFERENCES "Condominio"("id") ON DELETE RESTRICT ON UPDATE CASCADE;
ALTER TABLE "HumanMembership" ADD CONSTRAINT "HumanMembership_residentId_condominioId_fkey"
  FOREIGN KEY ("residentId", "condominioId") REFERENCES "Morador"("id", "condominioId") ON DELETE RESTRICT ON UPDATE CASCADE;
ALTER TABLE "BrowserSession" ADD CONSTRAINT "BrowserSession_accountId_fkey"
  FOREIGN KEY ("accountId") REFERENCES "HumanAccount"("id") ON DELETE RESTRICT ON UPDATE CASCADE;
ALTER TABLE "BrowserSession" ADD CONSTRAINT "BrowserSession_activeMembershipId_accountId_fkey"
  FOREIGN KEY ("activeMembershipId", "accountId") REFERENCES "HumanMembership"("id", "accountId") ON DELETE RESTRICT ON UPDATE CASCADE;

CREATE FUNCTION enforce_live_human_membership_scope() RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
BEGIN
  IF NEW."role" <> 'provedor' THEN
    PERFORM 1 FROM public."Condominio"
    WHERE id = NEW."condominioId" AND "deletedAt" IS NULL
    FOR SHARE;
    IF NOT FOUND THEN
      RAISE EXCEPTION 'human membership requires a live condominium' USING ERRCODE = '23514';
    END IF;
  END IF;

  IF NEW."role" = 'morador' THEN
    PERFORM 1 FROM public."Morador"
    WHERE id = NEW."residentId" AND "condominioId" = NEW."condominioId" AND "deletedAt" IS NULL
    FOR SHARE;
    IF NOT FOUND THEN
      RAISE EXCEPTION 'resident membership requires a live resident in the same condominium' USING ERRCODE = '23514';
    END IF;
  END IF;

  RETURN NEW;
END;
$$;

CREATE TRIGGER "HumanMembership_enforce_live_scope"
BEFORE INSERT OR UPDATE OF "condominioId", "residentId", "role" ON "HumanMembership"
FOR EACH ROW EXECUTE FUNCTION enforce_live_human_membership_scope();

CREATE FUNCTION enforce_active_browser_session_scope() RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
BEGIN
  PERFORM 1
  FROM public."HumanAccount" account
  JOIN public."HumanMembership" membership
    ON membership.id = NEW."activeMembershipId" AND membership."accountId" = account.id
  WHERE account.id = NEW."accountId"
    AND account.status = 'active'
    AND account."sessionVersion" = NEW."accountSessionVersion"
    AND membership.status = 'active'
  FOR SHARE OF account, membership;

  IF NOT FOUND THEN
    RAISE EXCEPTION 'browser session requires active account and membership state' USING ERRCODE = '23514';
  END IF;
  RETURN NEW;
END;
$$;

CREATE TRIGGER "BrowserSession_enforce_active_scope"
BEFORE INSERT OR UPDATE OF "accountId", "accountSessionVersion", "activeMembershipId" ON "BrowserSession"
FOR EACH ROW EXECUTE FUNCTION enforce_active_browser_session_scope();

CREATE FUNCTION reject_authentication_audit_mutation() RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  RAISE EXCEPTION 'authentication audit rows are immutable' USING ERRCODE = '55000';
END;
$$;

CREATE TRIGGER "AuthenticationAuditEvent_reject_update_delete"
BEFORE UPDATE OR DELETE ON "AuthenticationAuditEvent"
FOR EACH ROW EXECUTE FUNCTION reject_authentication_audit_mutation();
CREATE TRIGGER "AuthenticationAuditEvent_reject_truncate"
BEFORE TRUNCATE ON "AuthenticationAuditEvent"
FOR EACH STATEMENT EXECUTE FUNCTION reject_authentication_audit_mutation();

GRANT USAGE ON SCHEMA public TO egogero_application;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO egogero_application;
ALTER DEFAULT PRIVILEGES IN SCHEMA public
  GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO egogero_application;
REVOKE UPDATE, DELETE, TRUNCATE ON "AuthenticationAuditEvent" FROM egogero_application, PUBLIC;
REVOKE ALL PRIVILEGES ON "_prisma_migrations" FROM egogero_application;

COMMIT;
