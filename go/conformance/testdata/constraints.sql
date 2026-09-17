-- Composite primary key, CHECK constraints, and foreign keys with
-- differing referential actions.
-- Regression: composite PK rendered without its separating comma;
-- CHECK constraints were absent from the desired spec, so the differ
-- authored a bare DROP CONSTRAINT for every one of them.
CREATE TABLE regions (
    code text PRIMARY KEY,
    name text NOT NULL
);

CREATE TABLE quotas (
    tenant_id  uuid NOT NULL,
    region     text NOT NULL,
    max_seats  integer NOT NULL,
    used_seats integer NOT NULL DEFAULT 0,
    PRIMARY KEY (tenant_id, region),
    CONSTRAINT quotas_seats_positive CHECK (max_seats > 0),
    CONSTRAINT quotas_used_within    CHECK (used_seats >= 0 AND used_seats <= max_seats),
    CONSTRAINT quotas_region_fk      FOREIGN KEY (region)
        REFERENCES regions (code) ON DELETE RESTRICT
);
