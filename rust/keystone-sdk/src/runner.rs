// SPDX-License-Identifier: Apache-2.0

//! The apply engine.
//!
//! Ported from the Go `migration` runner. [`Runner::apply`] runs every
//! file inside ONE transaction by default; if any source file contains the
//! `CONCURRENTLY` keyword it switches to a no-tx (autocommit) path that
//! dispatches one statement per round-trip — `CONCURRENTLY` refuses to run
//! inside any transaction.
//!
//! Connection model: the runner borrows a `&mut tokio_postgres::Client`
//! per apply. The TX path opens a real transaction; the NO-TX path mutates
//! session state (`SET search_path` / `SET ROLE`) directly on the
//! connection and resets it afterwards. Pooling is out of scope for this
//! wire-compat core — the SDK accepts a borrowed client and never closes
//! it (the caller owns the connection lifecycle).
//!
//! `rows_affected`: the migration file bodies run via tokio-postgres
//! `simple_query` (the simple query protocol — it permits multi-statement
//! files and `CONCURRENTLY`, unlike the extended protocol). Each statement
//! yields a `CommandComplete` row count, so [`FileResult::rows_affected`]
//! mirrors pgx exactly: the TX path sends the whole file in one round-trip
//! and reports the LAST statement's count (pgx's `Exec` returns the final
//! command tag for a multi-statement simple query); the no-tx path splits
//! the file and SUMS the per-statement counts (matching the Go no-tx loop).
//! The version-recording UPSERT keeps the extended protocol (`execute`)
//! because it binds `$1/$2/$3` parameters.

use std::sync::LazyLock;
use std::time::Instant;

use regex::Regex;
use thiserror::Error;
use tokio_postgres::Client;

use crate::ident::{quote_identifier, validate_identifier, IdentError};
use crate::source::ResolvedSource;
use crate::sqlsplit::split_sql_statements;
use crate::tracking::DEFAULT_TRACKING_TABLE;

/// Matches the `CONCURRENTLY` keyword (case-insensitive, word-bounded).
/// PostgreSQL refuses `CREATE/DROP INDEX CONCURRENTLY` and
/// `REINDEX … CONCURRENTLY` inside a transaction block (SQLSTATE 25001).
static CONCURRENTLY_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)\bCONCURRENTLY\b").expect("concurrently regex"));

/// Per-file execution outcome.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileResult {
    pub file: String,
    /// 1-based position in apply order.
    pub index: i32,
    pub duration_ms: i64,
    /// Rows affected by the file. TX path = the last statement's count;
    /// no-tx path = sum of per-statement counts (mirrors pgx — see module docs).
    pub rows_affected: i64,
}

/// Aggregate outcome of an [`Runner::apply`] call.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ApplyResult {
    pub files: Vec<FileResult>,
    pub total_duration_ms: i64,
    /// Empty on success.
    pub failed_file: String,
    pub failed_index: i32,
    pub failure_msg: String,
}

/// Errors raised by the runner.
#[derive(Debug, Error)]
pub enum RunnerError {
    #[error(transparent)]
    Ident(#[from] IdentError),
    #[error(transparent)]
    Db(#[from] tokio_postgres::Error),
}

/// Applies SQL files against a target schema.
pub struct Runner {
    schema: String,
    tracking_table: String,
    owner_role: Option<String>,
}

impl Runner {
    /// Binds a runner to a target schema + tracking table. The schema,
    /// table (defaulted when empty) and optional owner role are
    /// identifier-validated, matching the Go `NewRunner`.
    pub fn new(
        schema: &str,
        tracking_table: &str,
        owner_role: Option<&str>,
    ) -> Result<Self, IdentError> {
        validate_identifier("schema", schema)?;
        let table = if tracking_table.is_empty() {
            DEFAULT_TRACKING_TABLE
        } else {
            tracking_table
        };
        validate_identifier("trackingTable", table)?;
        if let Some(role) = owner_role {
            if !role.is_empty() {
                validate_identifier("ownerRole", role)?;
            }
        }
        Ok(Runner {
            schema: schema.to_string(),
            tracking_table: table.to_string(),
            owner_role: owner_role.filter(|r| !r.is_empty()).map(|r| r.to_string()),
        })
    }

    /// Reports whether `source` contains any `CONCURRENTLY` statement.
    pub fn needs_no_tx(&self, source: &ResolvedSource) -> bool {
        needs_no_tx(source)
    }

    /// Runs every file against the database, recording the version on
    /// success. Uses the TX path by default and the no-tx path when the
    /// source contains `CONCURRENTLY`.
    pub async fn apply(
        &self,
        client: &mut Client,
        version: &str,
        content_hash: &str,
        source: &ResolvedSource,
    ) -> Result<ApplyResult, RunnerError> {
        let mut res = ApplyResult::default();
        let start = Instant::now();

        if needs_no_tx(source) {
            return self
                .apply_no_tx(client, version, content_hash, source, res, start)
                .await;
        }

        let tx = client.transaction().await?;

        // search_path so unqualified objects land in the right schema.
        tx.batch_execute(&format!(
            "SET LOCAL search_path TO {}",
            quote_identifier(&self.schema)
        ))
        .await?;

        if let Some(role) = &self.owner_role {
            tx.batch_execute(&format!("SET LOCAL ROLE {}", quote_identifier(role)))
                .await?;
        }

        for (idx, name) in source.names().iter().enumerate() {
            let file_start = Instant::now();
            let body = &source.files()[name];
            // pgx's `Exec` on a multi-statement simple query returns the LAST
            // command tag, so take the last `CommandComplete` count.
            let rows_affected = match tx.simple_query(body).await {
                Ok(msgs) => last_command_count(&msgs),
                Err(e) => {
                    res.failed_file = name.clone();
                    res.failed_index = (idx + 1) as i32;
                    res.failure_msg = e.to_string();
                    // Drop tx to roll back, then return the error.
                    drop(tx);
                    return Err(RunnerError::Db(e));
                }
            };
            res.files.push(FileResult {
                file: name.clone(),
                index: (idx + 1) as i32,
                duration_ms: file_start.elapsed().as_millis() as i64,
                rows_affected,
            });
        }

        // Reset role before the tracking upsert so PG resolves the INSERT
        // privilege against the connection user, not <owner_role>.
        if self.owner_role.is_some() {
            tx.batch_execute("SET LOCAL ROLE NONE").await?;
        }

        let total_ms = start.elapsed().as_millis() as i64;
        let upsert = self.upsert_sql();
        tx.execute(&upsert, &[&version, &content_hash, &total_ms])
            .await?;

        tx.commit().await?;
        res.total_duration_ms = total_ms;
        Ok(res)
    }

    /// Executes the bundle without a transaction, on the borrowed client.
    /// Required for `CONCURRENTLY`; each statement carries its own implicit
    /// autocommit tx.
    #[allow(clippy::too_many_arguments)]
    async fn apply_no_tx(
        &self,
        client: &mut Client,
        version: &str,
        content_hash: &str,
        source: &ResolvedSource,
        mut res: ApplyResult,
        start: Instant,
    ) -> Result<ApplyResult, RunnerError> {
        client
            .batch_execute(&format!(
                "SET search_path TO {}",
                quote_identifier(&self.schema)
            ))
            .await?;

        if let Some(role) = &self.owner_role {
            client
                .batch_execute(&format!("SET ROLE {}", quote_identifier(role)))
                .await?;
        }

        for (idx, name) in source.names().iter().enumerate() {
            let file_start = Instant::now();
            // One statement per round-trip: the simple-query protocol wraps
            // multi-statement Exec in an implicit tx, which CONCURRENTLY
            // refuses.
            let stmts = split_sql_statements(&source.files()[name]);
            let mut rows_affected: i64 = 0;
            for stmt in &stmts {
                match client.simple_query(stmt).await {
                    Ok(msgs) => rows_affected += last_command_count(&msgs),
                    Err(e) => {
                        res.failed_file = name.clone();
                        res.failed_index = (idx + 1) as i32;
                        res.failure_msg = e.to_string();
                        // Best-effort session reset before bailing.
                        let _ = self.reset_session(client).await;
                        return Err(RunnerError::Db(e));
                    }
                }
            }
            res.files.push(FileResult {
                file: name.clone(),
                index: (idx + 1) as i32,
                duration_ms: file_start.elapsed().as_millis() as i64,
                rows_affected,
            });
        }

        // Reset role before the tracking upsert.
        if self.owner_role.is_some() {
            client.batch_execute("RESET ROLE").await?;
        }

        let total_ms = start.elapsed().as_millis() as i64;
        let upsert = self.upsert_sql();
        client
            .execute(&upsert, &[&version, &content_hash, &total_ms])
            .await?;

        // Reset search_path so the connection doesn't leak it.
        client.batch_execute("RESET search_path").await?;

        res.total_duration_ms = total_ms;
        Ok(res)
    }

    async fn reset_session(&self, client: &Client) -> Result<(), tokio_postgres::Error> {
        if self.owner_role.is_some() {
            client.batch_execute("RESET ROLE").await?;
        }
        client.batch_execute("RESET search_path").await
    }

    /// The version-recording UPSERT, with schema/table quoted.
    fn upsert_sql(&self) -> String {
        format!(
            "INSERT INTO {}.{} (version, content_hash, duration_ms)\n\
             VALUES ($1, $2, $3)\n\
             ON CONFLICT (version) DO UPDATE SET\n    \
                content_hash = EXCLUDED.content_hash,\n    \
                duration_ms  = EXCLUDED.duration_ms,\n    \
                applied_at   = NOW()",
            quote_identifier(&self.schema),
            quote_identifier(&self.tracking_table),
        )
    }

    /// The schema this runner targets.
    pub fn schema(&self) -> &str {
        &self.schema
    }

    /// The tracking-table name.
    pub fn tracking_table(&self) -> &str {
        &self.tracking_table
    }
}

/// Returns the row count of the LAST `CommandComplete` message in a
/// simple-query result. pgx's `Exec` returns the final command tag for a
/// multi-statement simple query, so the last count is the faithful match.
fn last_command_count(msgs: &[tokio_postgres::SimpleQueryMessage]) -> i64 {
    msgs.iter()
        .filter_map(|m| match m {
            tokio_postgres::SimpleQueryMessage::CommandComplete(n) => Some(*n as i64),
            _ => None,
        })
        .next_back()
        .unwrap_or(0)
}

/// Reports whether the source contains any `CONCURRENTLY` statement.
pub fn needs_no_tx(source: &ResolvedSource) -> bool {
    source
        .names()
        .iter()
        .any(|name| CONCURRENTLY_RE.is_match(&source.files()[name]))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::source::{resolve, SqlFile};

    fn f(name: &str, body: &str) -> SqlFile {
        SqlFile {
            name: name.to_string(),
            body: body.to_string(),
        }
    }

    #[test]
    fn new_validates_identifiers() {
        assert!(Runner::new("public", "", None).is_ok());
        assert!(Runner::new("public", "", Some("")).is_ok());
        assert!(Runner::new("BAD", "", None).is_err());
        assert!(Runner::new("public", "Bad-Table", None).is_err());
        assert!(Runner::new("public", "", Some("Bad Role")).is_err());
    }

    #[test]
    fn tracking_table_defaults_when_empty() {
        let r = Runner::new("public", "", None).unwrap();
        assert_eq!(r.tracking_table(), "schema_migrations");
    }

    #[test]
    fn needs_no_tx_detects_concurrently() {
        let with = resolve(vec![f(
            "001.sql",
            "CREATE INDEX CONCURRENTLY idx ON t (c);",
        )]);
        let without = resolve(vec![f("001.sql", "CREATE INDEX idx ON t (c);")]);
        assert!(needs_no_tx(&with));
        assert!(!needs_no_tx(&without));
        // Case-insensitive + word-bounded.
        let lower = resolve(vec![f("001.sql", "reindex index concurrently i;")]);
        assert!(needs_no_tx(&lower));
        let substr = resolve(vec![f("001.sql", "SELECT concurrentlyx FROM t;")]);
        assert!(!needs_no_tx(&substr));
    }

    #[test]
    fn upsert_sql_is_exact() {
        let r = Runner::new("public", "schema_migrations", None).unwrap();
        let expected =
            "INSERT INTO \"public\".\"schema_migrations\" (version, content_hash, duration_ms)\n\
VALUES ($1, $2, $3)\n\
ON CONFLICT (version) DO UPDATE SET\n    \
content_hash = EXCLUDED.content_hash,\n    \
duration_ms  = EXCLUDED.duration_ms,\n    \
applied_at   = NOW()";
        assert_eq!(r.upsert_sql(), expected);
    }
}
