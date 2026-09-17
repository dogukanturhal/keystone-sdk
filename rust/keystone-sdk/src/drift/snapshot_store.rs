// SPDX-License-Identifier: Apache-2.0

//! Canonical-snapshot JSON storage.
//!
//! Ported from the Go `drift` package's `snapshot_store.go`. Extends
//! `keystone_baselines` with a `snapshot JSONB` column: the DriftController
//! writes the canonical snapshot when it accepts a baseline and reads it
//! when drift is detected to compute structured findings.
//!
//! Storage uses tokio-postgres's `Json` wrapper (JSONB). PostgreSQL
//! normalises JSONB on input regardless of the producer's exact escaping,
//! so a snapshot written here is byte-identical on disk to one written by
//! the Go SDK; the round-trip reconstructs the same [`Snapshot`]. (The
//! hash-compatible formatter in [`super::marshal_snapshot`] is only needed
//! for [`super::hash`], not for JSONB storage.)

use tokio_postgres::types::Json;
use tokio_postgres::Client;

use crate::ident::{quote_identifier, validate_identifier, IdentError};

use super::Snapshot;

/// DDL adding the `snapshot JSONB` column. The single `{schema}` token is
/// substituted with the quoted schema. Indentation is a literal TAB.
const SNAPSHOT_TABLE_DDL: &str = "
ALTER TABLE {schema}.keystone_baselines
\tADD COLUMN IF NOT EXISTS snapshot JSONB;
";

fn render_ddl(schema: &str) -> String {
    SNAPSHOT_TABLE_DDL.replace("{schema}", &quote_identifier(schema))
}

/// Idempotently adds the `snapshot JSONB` column to `keystone_baselines`.
pub async fn ensure_snapshot_column(
    client: &Client,
    schema: &str,
) -> Result<(), SnapshotStoreError> {
    validate_identifier("schema", schema)?;
    client.batch_execute(&render_ddl(schema)).await?;
    Ok(())
}

/// Returns the prior snapshot JSON for `kind = 'structure'`, or `None` if no
/// row exists or the column is NULL.
pub async fn read_snapshot(
    client: &Client,
    schema: &str,
) -> Result<Option<Snapshot>, SnapshotStoreError> {
    validate_identifier("schema", schema)?;
    let q = format!(
        "SELECT snapshot FROM {}.keystone_baselines WHERE kind = 'structure'",
        quote_identifier(schema),
    );
    let rows = client.query(&q, &[]).await?;
    let Some(row) = rows.first() else {
        return Ok(None);
    };
    let snap: Option<Json<Snapshot>> = row.get(0);
    Ok(snap.map(|j| j.0))
}

/// Stores the canonical snapshot alongside the existing hash row. Called
/// after [`super::write_baseline`] so hash and snapshot stay in sync.
pub async fn write_snapshot(
    client: &Client,
    schema: &str,
    snap: &Snapshot,
) -> Result<(), SnapshotStoreError> {
    validate_identifier("schema", schema)?;
    let stmt = format!(
        "UPDATE {}.keystone_baselines SET snapshot = $1 WHERE kind = 'structure'",
        quote_identifier(schema),
    );
    client.execute(&stmt, &[&Json(snap)]).await?;
    Ok(())
}

/// Errors raised by the snapshot-store helpers.
#[derive(Debug, thiserror::Error)]
pub enum SnapshotStoreError {
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
ALTER TABLE \"public\".keystone_baselines
\tADD COLUMN IF NOT EXISTS snapshot JSONB;
";
        assert_eq!(ddl, expected);
    }
}
