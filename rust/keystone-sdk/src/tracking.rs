// SPDX-License-Identifier: Apache-2.0

//! Bookkeeping table + read helpers.
//!
//! Ported from the Go `migration` runner's tracking primitives. The
//! tracking table is golang-migrate-compatible (version TEXT PRIMARY KEY,
//! dirty BOOLEAN, applied_at TIMESTAMPTZ) plus a `content_hash` column so
//! bundles that try to swap SQL behind an already-applied version are
//! detectable.
//!
//! These helpers all require a live database; their tests are gated behind
//! the `integration` cargo feature.

use std::time::SystemTime;

use tokio_postgres::Client;

use crate::ident::quote_identifier;

/// The golang-migrate-compatible default tracking-table name.
pub const DEFAULT_TRACKING_TABLE: &str = "schema_migrations";

/// DDL template for the tracking table. Two identifiers (schema, table)
/// are quoted and substituted into both the CREATE and the COMMENT. The
/// `{schema}.{table}` placeholders appear twice each.
///
/// Indentation is a literal TAB (`\t`) on every body line — character-for-
/// character identical to the Go source of truth's `migrationsTableDDLTemplate`
/// (a Go raw-string literal indented with tabs). Postgres ignores the
/// whitespace, but the port reproduces it exactly per the wire-compat contract.
const MIGRATIONS_TABLE_DDL_TEMPLATE: &str = "
CREATE TABLE IF NOT EXISTS {schema}.{table} (
\tversion       TEXT PRIMARY KEY,
\tcontent_hash  TEXT NOT NULL,
\tapplied_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
\tapplied_by    TEXT NOT NULL DEFAULT current_user,
\tduration_ms   BIGINT NOT NULL,
\tdirty         BOOLEAN NOT NULL DEFAULT FALSE
);

COMMENT ON TABLE {schema}.{table} IS
\t'Maintained by Keystone (keystone.hexxlock.io). Do not edit manually.';
";

/// Renders the tracking-table DDL for the given (already-quoted) schema and
/// table identifiers.
pub(crate) fn render_ddl(schema: &str, table: &str) -> String {
    let q_schema = quote_identifier(schema);
    let q_table = quote_identifier(table);
    let qualified = format!("{q_schema}.{q_table}");
    MIGRATIONS_TABLE_DDL_TEMPLATE.replace("{schema}.{table}", &qualified)
}

/// One row in the tracking table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppliedMigration {
    pub version: String,
    pub content_hash: String,
    pub applied_at: SystemTime,
    pub duration_ms: i64,
    pub dirty: bool,
}

/// Creates the tracking table if missing. Idempotent.
pub async fn ensure_bookkeeping(
    client: &Client,
    schema: &str,
    table: &str,
) -> Result<(), tokio_postgres::Error> {
    let stmt = render_ddl(schema, table);
    client.batch_execute(&stmt).await
}

/// Reports whether `version` is recorded in the tracking table, returning
/// the recorded row so the caller can compare content hashes.
pub async fn is_applied(
    client: &Client,
    schema: &str,
    table: &str,
    version: &str,
) -> Result<Option<AppliedMigration>, tokio_postgres::Error> {
    let q = format!(
        "SELECT version, content_hash, applied_at, duration_ms, dirty \
           FROM {}.{} \
          WHERE version = $1",
        quote_identifier(schema),
        quote_identifier(table),
    );
    let rows = client.query(&q, &[&version]).await?;
    Ok(rows.first().map(row_to_applied))
}

/// Returns every row from the tracking table, ordered by
/// `applied_at ASC, version ASC`.
pub async fn list_applied(
    client: &Client,
    schema: &str,
    table: &str,
) -> Result<Vec<AppliedMigration>, tokio_postgres::Error> {
    let q = format!(
        "SELECT version, content_hash, applied_at, duration_ms, dirty \
           FROM {}.{} \
          ORDER BY applied_at ASC, version ASC",
        quote_identifier(schema),
        quote_identifier(table),
    );
    let rows = client.query(&q, &[]).await?;
    Ok(rows.iter().map(row_to_applied).collect())
}

/// Upserts the `(version, content_hash)` row with `duration_ms = 0` WITHOUT
/// executing any migration SQL — the adoption-baseline primitive.
pub async fn record(
    client: &Client,
    schema: &str,
    table: &str,
    version: &str,
    content_hash: &str,
) -> Result<(), tokio_postgres::Error> {
    let insert_sql = format!(
        "INSERT INTO {}.{} (version, content_hash, duration_ms)\n\
         VALUES ($1, $2, 0)\n\
         ON CONFLICT (version) DO UPDATE SET\n    \
            content_hash = EXCLUDED.content_hash,\n    \
            duration_ms  = EXCLUDED.duration_ms,\n    \
            applied_at   = NOW()",
        quote_identifier(schema),
        quote_identifier(table),
    );
    client
        .execute(&insert_sql, &[&version, &content_hash])
        .await?;
    Ok(())
}

fn row_to_applied(row: &tokio_postgres::Row) -> AppliedMigration {
    AppliedMigration {
        version: row.get(0),
        content_hash: row.get(1),
        applied_at: row.get(2),
        duration_ms: row.get(3),
        dirty: row.get(4),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ddl_renders_quoted_and_exact() {
        let ddl = render_ddl("public", "schema_migrations");
        let expected = "
CREATE TABLE IF NOT EXISTS \"public\".\"schema_migrations\" (
\tversion       TEXT PRIMARY KEY,
\tcontent_hash  TEXT NOT NULL,
\tapplied_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
\tapplied_by    TEXT NOT NULL DEFAULT current_user,
\tduration_ms   BIGINT NOT NULL,
\tdirty         BOOLEAN NOT NULL DEFAULT FALSE
);

COMMENT ON TABLE \"public\".\"schema_migrations\" IS
\t'Maintained by Keystone (keystone.hexxlock.io). Do not edit manually.';
";
        assert_eq!(ddl, expected);
    }
}
