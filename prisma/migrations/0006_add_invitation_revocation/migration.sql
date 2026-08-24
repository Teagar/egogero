BEGIN;

-- A nullable timestamp preserves legacy invitations while recording an irreversible revocation.
ALTER TABLE "Convite"
ADD COLUMN "revokedAt" TIMESTAMP(3);

-- Consumption and revocation are mutually exclusive terminal transitions.
ALTER TABLE "Convite"
ADD CONSTRAINT "Convite_terminal_state_check"
CHECK ("revokedAt" IS NULL OR "usedAt" IS NULL);

COMMIT;
