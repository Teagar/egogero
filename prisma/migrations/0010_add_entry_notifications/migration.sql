BEGIN;

CREATE UNIQUE INDEX "Convite_notification_scope_key"
ON "Convite"("id", "condominioId", "moradorId", "convidadoId");

CREATE TABLE "Notificacao" (
    "id" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "deletedAt" TIMESTAMP(3),
    "lidaEm" TIMESTAMP(3),
    "tipo" TEXT NOT NULL,
    "mensagem" TEXT NOT NULL,
    "nomeConvidado" TEXT NOT NULL,
    "entrouEm" TIMESTAMP(3) NOT NULL,
    "condominioId" TEXT NOT NULL,
    "moradorId" TEXT NOT NULL,
    "convidadoId" TEXT NOT NULL,
    "conviteId" TEXT NOT NULL,
    CONSTRAINT "Notificacao_pkey" PRIMARY KEY ("id"),
    CONSTRAINT "Notificacao_condominioId_fkey" FOREIGN KEY ("condominioId") REFERENCES "Condominio"("id") ON DELETE RESTRICT ON UPDATE CASCADE,
    CONSTRAINT "Notificacao_morador_scope_fkey" FOREIGN KEY ("moradorId", "condominioId") REFERENCES "Morador"("id", "condominioId") ON DELETE RESTRICT ON UPDATE CASCADE,
    CONSTRAINT "Notificacao_convidado_scope_fkey" FOREIGN KEY ("convidadoId", "condominioId") REFERENCES "Convidado"("id", "condominioId") ON DELETE RESTRICT ON UPDATE CASCADE,
    CONSTRAINT "Notificacao_convite_scope_fkey" FOREIGN KEY ("conviteId", "condominioId", "moradorId", "convidadoId") REFERENCES "Convite"("id", "condominioId", "moradorId", "convidadoId") ON DELETE CASCADE ON UPDATE CASCADE
);
CREATE UNIQUE INDEX "Notificacao_conviteId_key" ON "Notificacao"("conviteId");
CREATE UNIQUE INDEX "Notificacao_invitation_scope_key" ON "Notificacao"("conviteId", "condominioId", "moradorId", "convidadoId");
CREATE INDEX "Notificacao_scope_idx" ON "Notificacao"("condominioId", "moradorId", "deletedAt", "createdAt");

COMMIT;
