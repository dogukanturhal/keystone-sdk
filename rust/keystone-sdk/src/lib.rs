// SPDX-License-Identifier: Apache-2.0

//! # keystone-sdk (Rust) — wire-compatibility core
//!
//! A TIER-1 faithful Rust port of the wire-compatible core of the Keystone
//! SDK: the versioned **Apply** pipeline plus the primitives it is built
//! on. It reproduces the documented behaviour of the Go reference SDK
//! exactly so the three SDKs (Go, .NET, Rust) interoperate on the wire.
//!
//! ## Wire-compatibility contract
//!
//! The following invariants are load-bearing for cross-SDK
//! interoperability — every implementation MUST agree byte-for-byte:
//!
//! - **ContentHash / FileHash** — SHA-256 over `(name ‖ 0x00 ‖ body ‖
//!   0x00)` tuples, lowercase hex. `content_hash` streams all files
//!   through one running digest in the caller's order; `file_hash` uses a
//!   fresh digest per file. See [`hash`].
//! - **Identifier validation** — strict `^[a-z_][a-z0-9_]{0,62}$` (or the
//!   hyphen-allowing `^[a-z_][a-z0-9_-]{0,62}$` for extensions), with an
//!   exact error string. Quoting doubles embedded `"` / `'`. See [`ident`].
//! - **`keystone.sum`** — canonical serialisation `h1:<root>` then sorted
//!   `<name> h1:<file_hash>` lines; root is SHA-256 of the body. Strict
//!   parsing. See [`sum`].
//! - **Statement splitting** — a char state machine matching the reference
//!   `splitSQLStatements` (quote/comment/dollar-quote aware, non-nesting
//!   block comments, trailing-`;` preserved). See [`sqlsplit`].
//! - **Tracking table DDL + UPSERT** — reproduced character-for-character,
//!   with identifiers quoted. See [`tracking`] and [`runner`].
//! - **Idempotency / anti-replay** — re-applying `(version, same hash)` is
//!   a no-op; `(version, different hash)` is refused with the exact
//!   reference message. See [`apply`].
//!
//! ## Connection model
//!
//! [`apply`] and the [`runner::Runner`] borrow a `&mut
//! tokio_postgres::Client`. The client is never closed by this crate — the
//! caller owns its lifecycle. Pooling is intentionally out of scope for
//! this wire-compat core.
//!
//! ## Scope
//!
//! This crate ships Apply + primitives, the [`drift`] inspector
//! ([`inspect`] + baselines), the [`analyze`] lint pack ([`lint`]), the
//! [`declarative`] differ ([`declarative::diff`]), and the [`authoring`] /
//! [`schemaspec`] / [`schemasource`] author workflow. A CLI is forthcoming.
//!
//! Note: there is **no advisory lock** — the reference SDK deliberately has
//! none, and this port faithfully omits it.

pub mod analyze;
pub mod authoring;
pub mod declarative;
pub mod drift;
pub mod hash;
pub mod ident;
pub mod pgconn;
pub mod runner;
pub mod schemasource;
pub mod schemaspec;
pub mod source;
pub mod sqlsplit;
pub mod sum;
pub mod tracking;

use thiserror::Error;
use tokio_postgres::Client;

// Re-exports of the most-used public types at the crate root.
pub use pgconn::{connect, ConnectError, SslMode};
pub use runner::{ApplyResult, FileResult, Runner};
pub use source::{resolve, ResolvedSource, SqlFile};
pub use sum::SumStatus;

/// Bundles the arguments [`apply`] needs to run a versioned migration.
#[derive(Debug, Clone)]
pub struct ApplyOptions {
    /// The PG schema the runner operates against.
    pub schema: String,
    /// The migration version. Recorded in the tracking table along with
    /// the content hash.
    pub version: String,
    /// The ordered slice of SQL files the runner applies.
    pub files: Vec<SqlFile>,
    /// Overrides the default `schema_migrations` tracking table. `None` =
    /// the default.
    pub tracking_table: Option<String>,
    /// When set, the runner `SET LOCAL ROLE`s to this role inside the
    /// migration so created objects are owned by it.
    pub owner_role: Option<String>,
}

/// Reports what [`apply`] ran, plus the recorded content hash.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApplyResultPublic {
    pub version: String,
    pub content_hash: String,
    pub total_duration_ms: i64,
    pub files: Vec<FileResult>,
}

/// Errors raised by the public [`apply`] entry point.
#[derive(Debug, Error)]
pub enum KeystoneError {
    #[error("keystone sdk: ApplyOptions.Schema is required")]
    SchemaRequired,
    #[error("keystone sdk: ApplyOptions.Version is required")]
    VersionRequired,
    #[error("keystone sdk: ApplyOptions.Files is empty")]
    FilesEmpty,

    /// Version already applied with a different content hash (anti-replay).
    /// The `Display` form is reproduced verbatim from the reference SDK.
    #[error(
        "keystone sdk: version {version:?} already applied with contentHash {prior:?}; \
         new content hashes to {new:?} — bump Version to ship changed SQL"
    )]
    AlreadyAppliedDifferentHash {
        version: String,
        prior: String,
        new: String,
    },

    #[error(transparent)]
    Ident(#[from] ident::IdentError),
    #[error(transparent)]
    Runner(#[from] runner::RunnerError),
    #[error(transparent)]
    Db(#[from] tokio_postgres::Error),

    /// The inspector failed. Mirrors the Go `keystone sdk: inspect: %w`.
    #[error("keystone sdk: inspect: {0}")]
    Inspect(#[source] drift::inspector::InspectError),

    /// The differ refused (or otherwise failed). Mirrors the Go
    /// `keystone sdk: diff: %w`; the carried error holds the computed plan.
    #[error("keystone sdk: diff: {0}")]
    Diff(#[source] declarative::DiffError),
}

/// The introspected structural shape of a live schema — the SDK-level
/// projection of [`drift::Snapshot`]. Tables are ordered by name; columns by
/// ordinal. Mirrors the Go SDK's public `Snapshot` (tables/indexes/
/// constraints only; the richer drift fields stay in [`drift`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Snapshot {
    pub schema: String,
    pub tables: Vec<Table>,
    pub indexes: Vec<ObjectDdl>,
    pub constraints: Vec<ObjectDdl>,
}

/// One base table or view in a [`Snapshot`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Table {
    pub name: String,
    /// `"BASE TABLE"`, `"VIEW"`, etc.
    pub kind: String,
    pub columns: Vec<Column>,
}

/// One column's shape in a [`Snapshot`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Column {
    pub name: String,
    pub ordinal: i64,
    pub data_type: String,
    pub udt_name: String,
    pub nullable: bool,
    pub default: String,
}

/// The generic (name, table, type, definition) shape used for indexes and
/// constraints in a [`Snapshot`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObjectDdl {
    pub name: String,
    pub table: String,
    pub r#type: String,
    pub definition: String,
}

/// Returns the live structural snapshot for `schema`. Runs read-only queries
/// against `information_schema` / `pg_catalog`.
pub async fn inspect(client: &Client, schema: &str) -> Result<Snapshot, KeystoneError> {
    let raw = drift::Inspector::new()
        .inspect(client, schema)
        .await
        .map_err(KeystoneError::Inspect)?;
    Ok(project_snapshot(&raw))
}

fn obj_from_drift(o: &drift::ObjectDdl) -> ObjectDdl {
    ObjectDdl {
        name: o.name.clone(),
        table: o.table.clone(),
        r#type: o.r#type.clone(),
        definition: o.definition.clone(),
    }
}

/// One lint finding from [`lint`]. `severity` is `error`/`warning`/`notice`.
/// Mirrors the Go SDK's `LintFinding`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LintFinding {
    pub rule: String,
    pub severity: String,
    pub file: String,
    pub line: i32,
    pub message: String,
}

/// Runs Keystone's native analyzer pack (53 rules) over the given SQL files
/// and returns findings. `bundle`/`version` are used for provenance. Pure —
/// no database needed. Mirrors the Go SDK's `Lint`.
pub fn lint(bundle: &str, version: &str, files: &[SqlFile]) -> Vec<LintFinding> {
    let m = analyze::Migration {
        bundle_name: bundle.to_string(),
        version: version.to_string(),
        files: files
            .iter()
            .map(|f| analyze::FileBody {
                name: f.name.clone(),
                body: f.body.clone(),
            })
            .collect(),
        ..Default::default()
    };
    analyze::default_registry()
        .run(&m)
        .into_iter()
        .map(|f| LintFinding {
            rule: f.rule,
            severity: f.severity.to_string(),
            file: f.file,
            line: f.line,
            message: f.message,
        })
        .collect()
}

/// Configures the declarative differ (`AllowDestructive` gate).
#[derive(Debug, Clone, Default)]
pub struct DiffOptions {
    pub allow_destructive: bool,
}

/// The public output of [`diff`] — the SQL to converge `observed` toward
/// `desired`. Mirrors the Go SDK's `DiffPlan` (statements + warnings +
/// destructive count; the per-statement reverse SQL stays internal to
/// [`declarative`]).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DiffPlan {
    pub statements: Vec<String>,
    pub warnings: Vec<String>,
    pub destructive_ops: usize,
}

/// Computes the statements needed to reach `desired` from the `observed`
/// snapshot. `observed` typically comes from [`inspect`]. Returns
/// [`KeystoneError::Diff`] (carrying the plan) when the diff needs
/// destructive ops and `opts.allow_destructive` is false. Mirrors the Go
/// SDK's `Diff` (including the lossy observed→drift projection).
pub fn diff(
    observed: &Snapshot,
    desired: &declarative::spec::SchemaDefinitionSpec,
    opts: DiffOptions,
) -> Result<DiffPlan, KeystoneError> {
    let mut desired_copy = desired.clone();
    desired_copy.allow_destructive = opts.allow_destructive;
    let raw = drift_snapshot_from_sdk(observed);
    match declarative::diff(&raw, &desired_copy) {
        Ok(plan) => Ok(DiffPlan {
            statements: plan.statements,
            warnings: plan.warnings,
            destructive_ops: plan.destructive_ops,
        }),
        Err(e) => Err(KeystoneError::Diff(e)),
    }
}

/// Rebuilds the internal [`drift::Snapshot`] from the public [`Snapshot`] —
/// the inverse of [`project_snapshot`]. Lossy by design (tables/indexes/
/// constraints only), mirroring the Go SDK's `driftSnapshotFromSDK`.
fn drift_snapshot_from_sdk(s: &Snapshot) -> drift::Snapshot {
    drift::Snapshot {
        schema: s.schema.clone(),
        tables: s
            .tables
            .iter()
            .map(|t| drift::TableShape {
                name: t.name.clone(),
                kind: t.kind.clone(),
                columns: t
                    .columns
                    .iter()
                    .map(|c| drift::ColumnShape {
                        name: c.name.clone(),
                        ordinal: c.ordinal,
                        data_type: c.data_type.clone(),
                        udt_name: c.udt_name.clone(),
                        nullable: c.nullable,
                        default: c.default.clone(),
                        // `formatted_type` / `identity` / `generated` are not
                        // carried on the public `Column`, so they round-trip as
                        // empty here — exactly as Go's `driftSnapshotFromSDK`
                        // leaves them zero-valued. An empty `formatted_type`
                        // makes `resolve_column_type_shape` fall back to the
                        // data_type/udt_name pair, which is the pre-modifier
                        // behaviour this path has always had. Diverging would
                        // break the Go/Rust parity this translator exists to
                        // preserve.
                        ..Default::default()
                    })
                    .collect(),
                ..Default::default()
            })
            .collect(),
        indexes: s.indexes.iter().map(drift_obj_from_pub).collect(),
        constraints: s.constraints.iter().map(drift_obj_from_pub).collect(),
        ..Default::default()
    }
}

fn drift_obj_from_pub(o: &ObjectDdl) -> drift::ObjectDdl {
    drift::ObjectDdl {
        name: o.name.clone(),
        table: o.table.clone(),
        r#type: o.r#type.clone(),
        definition: o.definition.clone(),
    }
}

/// Projects the richer [`drift::Snapshot`] down to the public [`Snapshot`]
/// (tables/indexes/constraints), mirroring the Go SDK's `Inspect`.
fn project_snapshot(raw: &drift::Snapshot) -> Snapshot {
    Snapshot {
        schema: raw.schema.clone(),
        tables: raw
            .tables
            .iter()
            .map(|t| Table {
                name: t.name.clone(),
                kind: t.kind.clone(),
                columns: t
                    .columns
                    .iter()
                    .map(|c| Column {
                        name: c.name.clone(),
                        ordinal: c.ordinal,
                        data_type: c.data_type.clone(),
                        udt_name: c.udt_name.clone(),
                        nullable: c.nullable,
                        default: c.default.clone(),
                    })
                    .collect(),
            })
            .collect(),
        indexes: raw.indexes.iter().map(obj_from_drift).collect(),
        constraints: raw.constraints.iter().map(obj_from_drift).collect(),
    }
}

/// Runs the given migration against `client`. Opens the tracking table if
/// absent, refuses on `(version, different content_hash)`, short-circuits
/// `(version, same hash)` to a no-op, and otherwise runs the runner.
///
/// The `client` is NOT closed by this function — the caller owns its
/// lifecycle.
pub async fn apply(
    client: &mut Client,
    opts: ApplyOptions,
) -> Result<ApplyResultPublic, KeystoneError> {
    if opts.schema.is_empty() {
        return Err(KeystoneError::SchemaRequired);
    }
    if opts.version.is_empty() {
        return Err(KeystoneError::VersionRequired);
    }
    if opts.files.is_empty() {
        return Err(KeystoneError::FilesEmpty);
    }

    let tracking = opts
        .tracking_table
        .clone()
        .unwrap_or_else(|| tracking::DEFAULT_TRACKING_TABLE.to_string());

    let runner = Runner::new(&opts.schema, &tracking, opts.owner_role.as_deref())?;

    // 1. Resolve the source (+ content hash).
    let src = resolve(opts.files);

    // 2. Ensure bookkeeping.
    tracking::ensure_bookkeeping(client, &opts.schema, runner.tracking_table()).await?;

    // 3. Idempotency / anti-replay gate.
    let prior =
        tracking::is_applied(client, &opts.schema, runner.tracking_table(), &opts.version).await?;
    if let Some(applied) = prior {
        if applied.content_hash != src.content_hash() {
            return Err(KeystoneError::AlreadyAppliedDifferentHash {
                version: opts.version.clone(),
                prior: applied.content_hash,
                new: src.content_hash().to_string(),
            });
        }
        // Same (version, hash) → no-op success.
        return Ok(ApplyResultPublic {
            version: opts.version,
            content_hash: src.content_hash().to_string(),
            total_duration_ms: 0,
            files: Vec::new(),
        });
    }

    // 4. Run the runner.
    let content_hash = src.content_hash().to_string();
    let result = runner
        .apply(client, &opts.version, &content_hash, &src)
        .await?;

    Ok(ApplyResultPublic {
        version: opts.version,
        content_hash,
        total_duration_ms: result.total_duration_ms,
        files: result.files,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lint_facade_returns_string_severities() {
        let files = vec![SqlFile {
            name: "001.sql".into(),
            body: "DROP TABLE users;".into(),
        }];
        let findings = lint("bundle", "001", &files);
        let drop = findings
            .iter()
            .find(|f| f.rule == "no-drop-table")
            .expect("no-drop-table finding");
        assert_eq!(drop.severity, "error");
        assert_eq!(drop.file, "001.sql");
        assert_eq!(drop.line, 1);
        // Structurally-clean SQL trips no structural rules. The SDK facade
        // leaves has_down_source=false (as Go's keystone.Lint does), so
        // require-down-migration is the one expected finding.
        let clean = vec![SqlFile {
            name: "002.sql".into(),
            body: "-- noop\nSELECT 1;".into(),
        }];
        let cf = lint("bundle", "002", &clean);
        assert!(
            cf.iter().all(|f| f.rule == "require-down-migration"),
            "got: {cf:?}"
        );
    }

    // The anti-replay refusal MESSAGE must match the reference SDK exactly,
    // including the em-dash. Construct the error directly so this is
    // covered without a database.
    #[test]
    fn already_applied_different_hash_message_is_exact() {
        let err = KeystoneError::AlreadyAppliedDifferentHash {
            version: "001".to_string(),
            prior: "abc".to_string(),
            new: "def".to_string(),
        };
        assert_eq!(
            err.to_string(),
            "keystone sdk: version \"001\" already applied with contentHash \"abc\"; \
             new content hashes to \"def\" — bump Version to ship changed SQL"
        );
    }

    #[test]
    fn validation_errors_have_exact_messages() {
        assert_eq!(
            KeystoneError::SchemaRequired.to_string(),
            "keystone sdk: ApplyOptions.Schema is required"
        );
        assert_eq!(
            KeystoneError::VersionRequired.to_string(),
            "keystone sdk: ApplyOptions.Version is required"
        );
        assert_eq!(
            KeystoneError::FilesEmpty.to_string(),
            "keystone sdk: ApplyOptions.Files is empty"
        );
    }
}
