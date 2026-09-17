-- Views and materialized views.
-- Regression: view bodies were compared against a non-pretty-printed
-- form so every diff saw a change; materialized view queries kept a
-- trailing semicolon that made the re-emitted DDL invalid.
CREATE TABLE orders (
    id       bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    customer text NOT NULL,
    amount   numeric(12,2) NOT NULL,
    placed   timestamptz NOT NULL DEFAULT now()
);

CREATE VIEW large_orders AS
    SELECT id, customer, amount FROM orders WHERE amount > 1000;

CREATE MATERIALIZED VIEW order_totals AS
    SELECT customer, sum(amount) AS total FROM orders GROUP BY customer;
