-- Enum types and array columns.
-- Regression: text[] / integer[] columns were reported as a destructive
-- type change on every diff, because the inspector and the renderer
-- disagreed on how to spell an array type.
CREATE TYPE tier AS ENUM ('free', 'paid', 'internal');

CREATE TABLE accounts (
    id       uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    plan     tier NOT NULL DEFAULT 'free',
    tags     text[] NOT NULL DEFAULT '{}',
    scores   integer[],
    metadata jsonb NOT NULL DEFAULT '{}'::jsonb
);
