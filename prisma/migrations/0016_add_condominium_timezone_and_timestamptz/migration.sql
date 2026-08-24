BEGIN;

ALTER TABLE "Condominio" ADD COLUMN "timezone" TEXT;
UPDATE "Condominio" SET "timezone" = 'America/Sao_Paulo';
ALTER TABLE "Condominio" ALTER COLUMN "timezone" SET NOT NULL;

CREATE FUNCTION validate_condominio_timezone()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_timezone_names WHERE name = NEW.timezone) THEN
    RAISE EXCEPTION 'invalid condominium timezone' USING ERRCODE = '22023';
  END IF;
  RETURN NEW;
END;
$$;

CREATE TRIGGER "Condominio_validate_timezone"
BEFORE INSERT OR UPDATE OF "timezone" ON "Condominio"
FOR EACH ROW EXECUTE FUNCTION validate_condominio_timezone();

ALTER TABLE "Condominio"
  ALTER COLUMN "createdAt" TYPE TIMESTAMPTZ(3) USING "createdAt" AT TIME ZONE 'UTC',
  ALTER COLUMN "deletedAt" TYPE TIMESTAMPTZ(3) USING "deletedAt" AT TIME ZONE 'UTC';

ALTER TABLE "Morador"
  ALTER COLUMN "createdAt" TYPE TIMESTAMPTZ(3) USING "createdAt" AT TIME ZONE 'UTC',
  ALTER COLUMN "deletedAt" TYPE TIMESTAMPTZ(3) USING "deletedAt" AT TIME ZONE 'UTC';

ALTER TABLE "Convidado"
  ALTER COLUMN "createdAt" TYPE TIMESTAMPTZ(3) USING "createdAt" AT TIME ZONE 'UTC',
  ALTER COLUMN "deletedAt" TYPE TIMESTAMPTZ(3) USING "deletedAt" AT TIME ZONE 'UTC',
  ALTER COLUMN "ultimoUsoEm" TYPE TIMESTAMPTZ(3) USING "ultimoUsoEm" AT TIME ZONE 'UTC',
  ALTER COLUMN "anonymizedAt" TYPE TIMESTAMPTZ(3) USING "anonymizedAt" AT TIME ZONE 'UTC';

ALTER TABLE "Convite"
  ALTER COLUMN "createdAt" TYPE TIMESTAMPTZ(3) USING "createdAt" AT TIME ZONE 'UTC',
  ALTER COLUMN "deletedAt" TYPE TIMESTAMPTZ(3) USING "deletedAt" AT TIME ZONE 'UTC',
  ALTER COLUMN "expiresAt" TYPE TIMESTAMPTZ(3) USING "expiresAt" AT TIME ZONE 'UTC',
  ALTER COLUMN "usedAt" TYPE TIMESTAMPTZ(3) USING "usedAt" AT TIME ZONE 'UTC',
  ALTER COLUMN "revokedAt" TYPE TIMESTAMPTZ(3) USING "revokedAt" AT TIME ZONE 'UTC';

ALTER TABLE "AuditoriaAcesso"
  ALTER COLUMN "createdAt" TYPE TIMESTAMPTZ(3) USING "createdAt" AT TIME ZONE 'UTC';

ALTER TABLE "Dispositivo"
  ALTER COLUMN "createdAt" TYPE TIMESTAMPTZ(3) USING "createdAt" AT TIME ZONE 'UTC',
  ALTER COLUMN "deletedAt" TYPE TIMESTAMPTZ(3) USING "deletedAt" AT TIME ZONE 'UTC',
  ALTER COLUMN "ultimoUsoEm" TYPE TIMESTAMPTZ(3) USING "ultimoUsoEm" AT TIME ZONE 'UTC';

ALTER TABLE "DispositivoRateLimit"
  ALTER COLUMN "blockedUntil" TYPE TIMESTAMPTZ(3) USING "blockedUntil" AT TIME ZONE 'UTC';

CREATE FUNCTION timestamps_at_utc(timestamps TIMESTAMP(3)[])
RETURNS TIMESTAMPTZ(3)[]
LANGUAGE sql
IMMUTABLE
AS $$
  SELECT COALESCE(
    array_agg(value AT TIME ZONE 'UTC' ORDER BY position),
    ARRAY[]::TIMESTAMPTZ(3)[]
  )
  FROM unnest(timestamps) WITH ORDINALITY AS item(value, position);
$$;

ALTER TABLE "DispositivoRateLimit"
  ALTER COLUMN "attempts" TYPE TIMESTAMPTZ(3)[] USING timestamps_at_utc("attempts");

DROP FUNCTION timestamps_at_utc(TIMESTAMP(3)[]);

ALTER TABLE "Notificacao"
  ALTER COLUMN "createdAt" TYPE TIMESTAMPTZ(3) USING "createdAt" AT TIME ZONE 'UTC',
  ALTER COLUMN "deletedAt" TYPE TIMESTAMPTZ(3) USING "deletedAt" AT TIME ZONE 'UTC',
  ALTER COLUMN "lidaEm" TYPE TIMESTAMPTZ(3) USING "lidaEm" AT TIME ZONE 'UTC',
  ALTER COLUMN "entrouEm" TYPE TIMESTAMPTZ(3) USING "entrouEm" AT TIME ZONE 'UTC';

COMMIT;
