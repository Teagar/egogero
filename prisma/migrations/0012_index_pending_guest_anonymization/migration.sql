CREATE INDEX CONCURRENTLY "Convidado_pending_anonymization_idx"
ON "Convidado"(id)
WHERE "anonymizedAt" IS NULL;
