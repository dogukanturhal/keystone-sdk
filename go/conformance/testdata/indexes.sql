-- Index shapes the differ has historically mis-round-tripped.
-- Regression: partial-index WHERE clauses were not canonicalised;
-- IN (list) vs = ANY (ARRAY[...]) compared unequal; sort direction,
-- NULLS ordering, INCLUDE columns and opclasses were dropped.
CREATE TABLE events (
    id         bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    tenant_id  uuid NOT NULL,
    kind       text NOT NULL,
    payload    text,
    active     boolean NOT NULL DEFAULT true,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX events_active_recent ON events (created_at DESC NULLS LAST) WHERE active;
CREATE INDEX events_kind_filtered ON events (tenant_id) WHERE kind IN ('signup', 'churn');
CREATE INDEX events_lower_kind    ON events (lower(kind));
CREATE INDEX events_covering      ON events (tenant_id, created_at) INCLUDE (kind);
CREATE INDEX events_text_ops      ON events (kind text_pattern_ops);
