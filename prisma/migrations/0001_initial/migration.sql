CREATE TABLE "Condominio" (
  "id" TEXT NOT NULL,
  "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "deletedAt" TIMESTAMP(3),
  "nome" TEXT NOT NULL,
  CONSTRAINT "Condominio_pkey" PRIMARY KEY ("id")
);

CREATE TABLE "Morador" (
  "id" TEXT NOT NULL,
  "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "deletedAt" TIMESTAMP(3),
  "nome" TEXT NOT NULL,
  "condominioId" TEXT NOT NULL,
  CONSTRAINT "Morador_pkey" PRIMARY KEY ("id")
);

CREATE TABLE "Convidado" (
  "id" TEXT NOT NULL,
  "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "deletedAt" TIMESTAMP(3),
  "nome" TEXT NOT NULL,
  "condominioId" TEXT NOT NULL,
  CONSTRAINT "Convidado_pkey" PRIMARY KEY ("id")
);

CREATE TABLE "Convite" (
  "id" TEXT NOT NULL,
  "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "deletedAt" TIMESTAMP(3),
  "condominioId" TEXT NOT NULL,
  "moradorId" TEXT,
  "convidadoId" TEXT,
  CONSTRAINT "Convite_pkey" PRIMARY KEY ("id")
);

CREATE INDEX "Morador_condominioId_idx" ON "Morador"("condominioId");
CREATE INDEX "Convidado_condominioId_idx" ON "Convidado"("condominioId");
CREATE INDEX "Convite_condominioId_idx" ON "Convite"("condominioId");
CREATE INDEX "Convite_moradorId_idx" ON "Convite"("moradorId");
CREATE INDEX "Convite_convidadoId_idx" ON "Convite"("convidadoId");

ALTER TABLE "Morador"
ADD CONSTRAINT "Morador_condominioId_fkey"
FOREIGN KEY ("condominioId") REFERENCES "Condominio"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

ALTER TABLE "Convidado"
ADD CONSTRAINT "Convidado_condominioId_fkey"
FOREIGN KEY ("condominioId") REFERENCES "Condominio"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

ALTER TABLE "Convite"
ADD CONSTRAINT "Convite_condominioId_fkey"
FOREIGN KEY ("condominioId") REFERENCES "Condominio"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

ALTER TABLE "Convite"
ADD CONSTRAINT "Convite_moradorId_fkey"
FOREIGN KEY ("moradorId") REFERENCES "Morador"("id") ON DELETE SET NULL ON UPDATE CASCADE;

ALTER TABLE "Convite"
ADD CONSTRAINT "Convite_convidadoId_fkey"
FOREIGN KEY ("convidadoId") REFERENCES "Convidado"("id") ON DELETE SET NULL ON UPDATE CASCADE;
