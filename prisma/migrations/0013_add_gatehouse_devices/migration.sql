BEGIN;

CREATE TYPE "StatusDispositivo" AS ENUM ('ativo', 'revogado');

CREATE TABLE "Dispositivo" (
  id TEXT NOT NULL,
  "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "deletedAt" TIMESTAMP(3),
  nome TEXT NOT NULL,
  "condominioId" TEXT NOT NULL,
  "apiKeyDigest" CHAR(64),
  status "StatusDispositivo" NOT NULL DEFAULT 'ativo',
  "ultimoUsoEm" TIMESTAMP(3),
  CONSTRAINT "Dispositivo_pkey" PRIMARY KEY (id),
  CONSTRAINT "Dispositivo_nome_check" CHECK (length(nome) BETWEEN 1 AND 100),
  CONSTRAINT "Dispositivo_apiKeyDigest_check" CHECK ("apiKeyDigest" IS NULL OR "apiKeyDigest" ~ '^[0-9a-f]{64}$'),
  CONSTRAINT "Dispositivo_condominioId_fkey" FOREIGN KEY ("condominioId") REFERENCES "Condominio"(id) ON DELETE RESTRICT ON UPDATE CASCADE
);

CREATE UNIQUE INDEX "Dispositivo_apiKeyDigest_key" ON "Dispositivo"("apiKeyDigest");
CREATE INDEX "Dispositivo_condominioId_status_deletedAt_idx" ON "Dispositivo"("condominioId", status, "deletedAt");
CREATE UNIQUE INDEX "Dispositivo_id_condominioId_key" ON "Dispositivo"(id, "condominioId");

CREATE TABLE "DispositivoRateLimit" (
  "dispositivoId" TEXT NOT NULL,
  attempts TIMESTAMP(3)[] NOT NULL DEFAULT ARRAY[]::TIMESTAMP(3)[],
  "blockedUntil" TIMESTAMP(3),
  "backoffLevel" INTEGER NOT NULL DEFAULT 0,
  CONSTRAINT "DispositivoRateLimit_pkey" PRIMARY KEY ("dispositivoId"),
  CONSTRAINT "DispositivoRateLimit_attempts_check" CHECK (cardinality(attempts) <= 20),
  CONSTRAINT "DispositivoRateLimit_backoffLevel_check" CHECK ("backoffLevel" BETWEEN 0 AND 5),
  CONSTRAINT "DispositivoRateLimit_dispositivoId_fkey" FOREIGN KEY ("dispositivoId") REFERENCES "Dispositivo"(id) ON DELETE CASCADE ON UPDATE CASCADE
);

COMMIT;
