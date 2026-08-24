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
    CONSTRAINT "Notificacao_moradorId_fkey" FOREIGN KEY ("moradorId") REFERENCES "Morador"("id") ON DELETE RESTRICT ON UPDATE CASCADE,
    CONSTRAINT "Notificacao_convidadoId_fkey" FOREIGN KEY ("convidadoId") REFERENCES "Convidado"("id") ON DELETE RESTRICT ON UPDATE CASCADE,
    CONSTRAINT "Notificacao_conviteId_fkey" FOREIGN KEY ("conviteId") REFERENCES "Convite"("id") ON DELETE CASCADE ON UPDATE CASCADE
);
CREATE UNIQUE INDEX "Notificacao_conviteId_key" ON "Notificacao"("conviteId");
CREATE INDEX "Notificacao_scope_idx" ON "Notificacao"("condominioId", "moradorId", "deletedAt", "createdAt");
