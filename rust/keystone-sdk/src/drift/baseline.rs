// SPDX-License-Identifier: Apache-2.0

//! Baseline bookkeeping (`<schema>.keystone_baselines`).
//!
//! Ported from the Go `drift` package's `baseline.go`. One row per
//! (schema, kind); `kind` is `structure` today (`rls`/`permissions`
//! reserved). The DriftController stores the accepted structure hash here
//! and compares re-inspected hashes against it.

use std::time::SystemTime;

use tokio_postgres::Client;

use crate::ident::{quote_identifier, validate_identifier, IdentError};

/// DDL for the `keystone_baselines` table. The single `{schema}` token is
/// substituted with the quoted schema (it appears twice). Indentation is a
/// literal TAB, matching the Go raw-string template.
const BASELINE_TABLE_DDL: &str = "
CREATE TABLE IF NOT EXISTS {schema}.keystone_baselines (
\tkind          TEXT PRIMARY KEY,
\thash          TEXT NOT NULL,
\tsource        TEXT NOT NULL,  -- e.g. \"migration:bundle/v42\" or \"drift-acceptance\"
\trecorded_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
\trecorded_by   TEXT NOT NULL DEFAULT current_user
);
COMMENT ON TABLE {schema}.keystone_baselines IS
\t'Maintained by Keystone DriftController (keystone.hexxlock.io). Do not edit manually.';
";

/// Identifies what aspect of the schema a baseline tracks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BaselineKind(pub &'static str);

/// The structure-hash baseline (the fast-path row).
pub const BASELINE_KIND_STRUCTURE: BaselineKind = BaselineKind("structure");

/// The canonical-snapshot-JSON row, read only when drift is detected.
pub const SNAPSHOT_KIND: BaselineKind = BaselineKind("snapshot-json");

/// One recorded baseline row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Baseline {
    pub kind: String,
    pub hash: String,
    pub source: String,
    pub recorded_at: SystemTime,
}

/// Renders the baseline DDL for the given schema (quoted).
fn render_ddl(schema: &str) -> String {
    BASELINE_TABLE_DDL.replace("{schema}", &quote_identifier(schema))
}

/// Creates the `keystone_baselines` table if missing. Idempotent.
pub async fn ensure_baseline_table(client: &Client, schema: &str) -> Result<(), BaselineError> {
    validate_identifier("schema", schema)?;
    client.batch_execute(&render_ddl(schema)).await?;
    Ok(())
}

/// Returns the recorded baseline for `kind`, or `None` if none exists.
pub async fn read_baseline(
    client: &Client,
    schema: &str,
    kind: BaselineKind,
) -> Result<Option<Baseline>, BaselineError> {
    validate_identifier("schema", schema)?;
    let q = format!(
        "SELECT kind, hash, source, recorded_at
           FROM {}.keystone_baselines
          WHERE kind = $1",
        quote_identifier(schema),
    );
    let rows = client.query(&q, &[&kind.0]).await?;
    Ok(rows.first().map(|row| Baseline {
        kind: row.get(0),
        hash: row.get(1),
        source: row.get(2),
        recorded_at: row.get(3),
    }))
}

/// Upserts the baseline. `source` documents *why* the baseline was set.
pub async fn write_baseline(
    client: &Client,
    schema: &str,
    kind: BaselineKind,
    hash: &str,
    source: &str,
) -> Result<(), BaselineError> {
    validate_identifier("schema", schema)?;
    let stmt = format!(
        "INSERT INTO {}.keystone_baselines (kind, hash, source)
         VALUES ($1, $2, $3)
         ON CONFLICT (kind) DO UPDATE
            SET hash = EXCLUDED.hash,
                source = EXCLUDED.source,
                recorded_at = NOW(),
                recorded_by = current_user",
        quote_identifier(schema),
    );
    client.execute(&stmt, &[&kind.0, &hash, &source]).await?;
    Ok(())
}

/// Errors raised by the baseline helpers.
#[derive(Debug, thiserror::Error)]
pub enum BaselineError {
    #[error(transparent)]
    Ident(#[from] IdentError),
    #[error(transparent)]
    Db(#[from] tokio_postgres::Error),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ddl_renders_quoted_and_exact() {
        let ddl = render_ddl("public");
        let expected = "
CREATE TABLE IF NOT EXISTS \"public\".keystone_baselines (
\tkind          TEXT PRIMARY KEY,
\thash          TEXT NOT NULL,
\tsource        TEXT NOT NULL,  -- e.g. \"migration:bundle/v42\" or \"drift-acceptance\"
\trecorded_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
\trecorded_by   TEXT NOT NULL DEFAULT current_user
);
COMMENT ON TABLE \"public\".keystone_baselines IS
\t'Maintained by Keystone DriftController (keystone.hexxlock.io). Do not edit manually.';
";
        assert_eq!(ddl, expected);
    }
}
