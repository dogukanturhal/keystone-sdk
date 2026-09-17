-- Standalone sequences and defaults carrying literal type casts.
-- Regression: PostgreSQL canonicalises 'x'::text and 0 -> 0::integer in
-- pg_get_expr output, so defaults authored without the cast compared
-- unequal on every diff.
CREATE SEQUENCE invoice_number_seq AS bigint INCREMENT BY 1 START WITH 1000;

CREATE TABLE invoices (
    id       bigint PRIMARY KEY DEFAULT nextval('invoice_number_seq'),
    status   text NOT NULL DEFAULT 'draft',
    currency char(3) NOT NULL DEFAULT 'USD',
    retries  integer NOT NULL DEFAULT 0,
    ratio    numeric(5,4) NOT NULL DEFAULT 0.5,
    issued   boolean NOT NULL DEFAULT false
);
