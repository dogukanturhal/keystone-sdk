-- An extension and an object that depends on it.
-- Regression: extension-owned objects leaked into the snapshot, so the
-- differ tried to re-create or drop functions and types it does not own.
-- The extension is created unqualified so it lands in the throwaway
-- scratch schema and is dropped with it, keeping parallel runs isolated.
CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE api_keys (
    id      uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    digest  text NOT NULL,
    created timestamptz NOT NULL DEFAULT now()
);
