// SPDX-License-Identifier: Apache-2.0

//! Resolves a "schema source reference" into a desired-state
//! [`SchemaDefinitionSpec`], normalising every input through a common
//! representation.
//!
//! Ported from the Go `schemasource` package. Reference forms:
//! `yaml://path` (declarative spec), `sql://path` / `file://*.sql` (raw DDL
//! normalised through a dev database), `db://<dsn>?schema=…` (inspect a live
//! database). The unifying idea — Atlas's "dev database" — is that a
//! throwaway scratch schema is the universal normaliser: DDL from any origin
//! is applied to a scratch schema via the production runner and read back by
//! the same inspector, so [`from_snapshot`] + the differ take it from there.

use std::collections::BTreeMap;

use tokio_postgres::Client;

use crate::declarative::spec::SchemaDefinitionSpec;
use crate::drift::{Inspector, Snapshot};
use crate::ident::quote_identifier;
use crate::runner::Runner;
use crate::schemaspec::from_snapshot;
use crate::source::{resolve, SqlFile};
use crate::tracking;

/// The kind of a parsed source reference.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scheme {
    /// A SchemaDefinition YAML file (declarative).
    Yaml,
    /// A raw DDL file, normalised through a dev database.
    Sql,
    /// A live database inspected directly.
    Db,
}

/// A parsed source reference.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ref {
    pub scheme: Scheme,
    /// File path for `yaml://` / `sql://`.
    pub path: String,
    /// PostgreSQL connection string for `db://`.
    pub dsn: String,
    /// Schema to inspect for `db://` (from `?schema=`); empty = caller default.
    pub schema: String,
}

/// Errors from this package.
#[derive(Debug, thiserror::Error)]
pub enum SchemaSourceError {
    #[error("{0}")]
    Parse(String),
    #[error("{0}")]
    Io(String),
    #[error("unmarshal spec: {0}")]
    Yaml(String),
    #[error("sql:// source requires a --dev-url database to normalise the DDL")]
    DevDbRequired,
    #[error(transparent)]
    Ident(#[from] crate::ident::IdentError),
    #[error(transparent)]
    Db(tokio_postgres::Error),
    #[error(transparent)]
    Connect(#[from] crate::pgconn::ConnectError),
    #[error(transparent)]
    Runner(#[from] crate::runner::RunnerError),
    #[error(transparent)]
    Inspect(#[from] crate::drift::inspector::InspectError),
}

/// Parses a source reference string. Bare paths (no scheme) are classified
/// by extension: `.sql` → SQL, `.yaml`/`.yml` → YAML.
pub fn parse_ref(s: &str) -> Result<Ref, SchemaSourceError> {
    let s = s.trim();
    if s.is_empty() {
        return Err(SchemaSourceError::Parse("empty source reference".into()));
    }
    if let Some(p) = s.strip_prefix("yaml://") {
        return Ok(Ref {
            scheme: Scheme::Yaml,
            path: p.to_string(),
            dsn: String::new(),
            schema: String::new(),
        });
    }
    if let Some(p) = s.strip_prefix("sql://") {
        return Ok(Ref {
            scheme: Scheme::Sql,
            path: p.to_string(),
            dsn: String::new(),
            schema: String::new(),
        });
    }
    if let Some(p) = s.strip_prefix("file://") {
        let scheme = if p.to_lowercase().ends_with(".sql") {
            Scheme::Sql
        } else {
            Scheme::Yaml
        };
        return Ok(Ref {
            scheme,
            path: p.to_string(),
            dsn: String::new(),
            schema: String::new(),
        });
    }
    if let Some(d) = s.strip_prefix("db://") {
        let mut dsn = d.to_string();
        if !dsn.starts_with("postgres://") && !dsn.starts_with("postgresql://") {
            dsn = format!("postgres://{dsn}");
        }
        let (schema, clean) = extract_schema_param(&dsn);
        return Ok(Ref {
            scheme: Scheme::Db,
            path: String::new(),
            dsn: clean,
            schema,
        });
    }
    let low = s.to_lowercase();
    if low.ends_with(".sql") {
        return Ok(Ref {
            scheme: Scheme::Sql,
            path: s.to_string(),
            dsn: String::new(),
            schema: String::new(),
        });
    }
    if low.ends_with(".yaml") || low.ends_with(".yml") {
        return Ok(Ref {
            scheme: Scheme::Yaml,
            path: s.to_string(),
            dsn: String::new(),
            schema: String::new(),
        });
    }
    Err(SchemaSourceError::Parse(format!(
        "cannot classify source reference {s:?}: prefix with yaml:// , sql:// , or db:// (or use a .sql/.yaml path)"
    )))
}

/// Pulls a `schema` query parameter out of a DSN, returning the schema plus
/// the DSN with that parameter removed (so PostgreSQL never sees it).
fn extract_schema_param(dsn: &str) -> (String, String) {
    let Some(qpos) = dsn.find('?') else {
        return (String::new(), dsn.to_string());
    };
    let (base, query) = dsn.split_at(qpos);
    let query = &query[1..]; // after '?'
    let mut schema = String::new();
    let kept: Vec<&str> = query
        .split('&')
        .filter(|kv| {
            if let Some(v) = kv.strip_prefix("schema=") {
                schema = v.to_string();
                false
            } else {
                !kv.is_empty()
            }
        })
        .collect();
    let clean = if kept.is_empty() {
        base.to_string()
    } else {
        format!("{base}?{}", kept.join("&"))
    };
    (schema, clean)
}

/// Parses a SchemaDefinition YAML string — accepting either a full CR
/// (`spec:` key) or a bare spec document — into a [`SchemaDefinitionSpec`].
pub fn load_spec_str(raw: &str) -> Result<SchemaDefinitionSpec, SchemaSourceError> {
    #[derive(serde::Deserialize, Default)]
    #[serde(default)]
    struct Wrapper {
        spec: SchemaDefinitionSpec,
    }
    if let Ok(w) = serde_yaml::from_str::<Wrapper>(raw) {
        if !w.spec.tables.is_empty() {
            return Ok(w.spec);
        }
    }
    serde_yaml::from_str(raw).map_err(|e| SchemaSourceError::Yaml(e.to_string()))
}

/// Reads a SchemaDefinition YAML file into a spec.
pub fn load_spec_file(path: &str) -> Result<SchemaDefinitionSpec, SchemaSourceError> {
    let raw = std::fs::read_to_string(path)
        .map_err(|e| SchemaSourceError::Io(format!("read {path}: {e}")))?;
    load_spec_str(&raw)
}

/// Resolves `reference` into a desired-state spec.
///
/// - `yaml://` reads the file (`dev_client` unused).
/// - `sql://` applies the DDL to a scratch schema on `dev_client` (REQUIRED),
///   inspects it, and converts.
/// - `db://` opens its own connection to `reference.dsn`, inspects
///   `reference.schema` (or `default_schema`), and converts.
pub async fn resolve_desired(
    reference: &Ref,
    dev_client: Option<&mut Client>,
    default_schema: &str,
) -> Result<SchemaDefinitionSpec, SchemaSourceError> {
    match reference.scheme {
        Scheme::Yaml => load_spec_file(&reference.path),
        Scheme::Sql => {
            let dev = dev_client.ok_or(SchemaSourceError::DevDbRequired)?;
            let ddl = std::fs::read_to_string(&reference.path)
                .map_err(|e| SchemaSourceError::Io(format!("read {}: {e}", reference.path)))?;
            let snap = snapshot_from_ddl(dev, &ddl, default_schema).await?;
            Ok(from_snapshot(&snap))
        }
        Scheme::Db => {
            let schema = if reference.schema.is_empty() {
                default_schema
            } else {
                &reference.schema
            };
            let (client, conn_task) = crate::pgconn::connect(&reference.dsn)
                .await
                .map_err(SchemaSourceError::Connect)?;
            let snap = Inspector::new().inspect(&client, schema).await;
            drop(client); // ends the connection so the spawned task finishes
            let _ = conn_task.await;
            Ok(from_snapshot(&snap?))
        }
    }
}

/// Applies a DDL blob to a fresh scratch schema on `client`, inspects it, and
/// returns the Snapshot (the dev-database normalisation). `target_schema` is
/// the logical schema the snapshot should report (its `.schema` and the
/// schema qualifier in inspected DDL).
pub async fn snapshot_from_ddl(
    client: &mut Client,
    ddl: &str,
    target_schema: &str,
) -> Result<Snapshot, SchemaSourceError> {
    materialize(
        client,
        vec![SqlFile {
            name: "desired.up.sql".into(),
            body: ddl.to_string(),
        }],
        target_schema,
    )
    .await
}

/// Replays an ordered set of migration files onto a scratch schema and
/// inspects the result. Apply order is lexicographic by name (mirroring the
/// runner). Pass `*.up.sql` files only.
pub async fn snapshot_from_files(
    client: &mut Client,
    files: BTreeMap<String, String>,
    target_schema: &str,
) -> Result<Snapshot, SchemaSourceError> {
    // BTreeMap iterates sorted by name → SqlFile vec in lexicographic order.
    let v: Vec<SqlFile> = files
        .into_iter()
        .map(|(name, body)| SqlFile { name, body })
        .collect();
    materialize(client, v, target_schema).await
}

/// The shared dev-database normaliser: create scratch schema → replay files
/// via the production runner → inspect → drop scratch schema (always, even on
/// error). Reusing [`Runner`] means the dev replay is the exact apply path
/// production uses, so the snapshot is high-fidelity.
async fn materialize(
    client: &mut Client,
    files: Vec<SqlFile>,
    target_schema: &str,
) -> Result<Snapshot, SchemaSourceError> {
    let scratch = scratch_schema_name();
    client
        .batch_execute(&format!("CREATE SCHEMA {}", quote_identifier(&scratch)))
        .await
        .map_err(SchemaSourceError::Db)?;

    let result = materialize_inner(client, &scratch, files, target_schema).await;

    // Always tear the scratch schema down.
    let drop_res = client
        .batch_execute(&format!(
            "DROP SCHEMA IF EXISTS {} CASCADE",
            quote_identifier(&scratch)
        ))
        .await;

    match (result, drop_res) {
        (Ok(snap), Ok(_)) => Ok(snap),
        (Ok(_), Err(e)) => Err(SchemaSourceError::Db(e)),
        (Err(e), _) => Err(e),
    }
}

async fn materialize_inner(
    client: &mut Client,
    scratch: &str,
    files: Vec<SqlFile>,
    target_schema: &str,
) -> Result<Snapshot, SchemaSourceError> {
    let runner = Runner::new(scratch, "keystone_schema_migrations", None)?;
    tracking::ensure_bookkeeping(client, scratch, "keystone_schema_migrations")
        .await
        .map_err(SchemaSourceError::Db)?;

    let src = resolve(files);
    let content_hash = src.content_hash().to_string();
    runner
        .apply(client, "materialize", &content_hash, &src)
        .await?;

    let mut snap = Inspector::new().inspect(client, scratch).await?;
    if !target_schema.is_empty() && target_schema != scratch {
        rewrite_snapshot_schema(&mut snap, scratch, target_schema);
    }
    Ok(snap)
}

/// Replaces every occurrence of schema name `from` with `to` across the
/// snapshot's schema-qualified DDL strings. Safe because `from` is the unique
/// scratch-schema token.
fn rewrite_snapshot_schema(snap: &mut Snapshot, from: &str, to: &str) {
    snap.schema = to.to_string();
    for idx in &mut snap.indexes {
        idx.definition = idx.definition.replace(from, to);
    }
    for c in &mut snap.constraints {
        c.definition = c.definition.replace(from, to);
    }
    for t in &mut snap.tables {
        t.view_definition = t.view_definition.replace(from, to);
    }
    for f in &mut snap.functions {
        f.definition = f.definition.replace(from, to);
    }
    for p in &mut snap.policies {
        p.using = p.using.replace(from, to);
        p.with_check = p.with_check.replace(from, to);
    }
    for mv in &mut snap.materialized_views {
        mv.definition = mv.definition.replace(from, to);
    }
}

/// A unique, identifier-valid scratch schema name (process id + monotonic
/// counter + time, avoiding collisions between concurrent runs).
fn scratch_schema_name() -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let c = COUNTER.fetch_add(1, Ordering::Relaxed);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);
    format!("keystone_dev_{:x}{:x}{:x}", std::process::id(), nanos, c)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_ref_schemes() {
        assert_eq!(parse_ref("yaml://a/b.yaml").unwrap().scheme, Scheme::Yaml);
        assert_eq!(parse_ref("sql://a/b.sql").unwrap().scheme, Scheme::Sql);
        assert_eq!(parse_ref("file://x.sql").unwrap().scheme, Scheme::Sql);
        assert_eq!(parse_ref("file://x.yaml").unwrap().scheme, Scheme::Yaml);
        // Bare-path classification by extension.
        assert_eq!(parse_ref("schema.sql").unwrap().scheme, Scheme::Sql);
        assert_eq!(parse_ref("def.yml").unwrap().scheme, Scheme::Yaml);
        // Unclassifiable.
        assert!(parse_ref("nope.txt").is_err());
        assert!(parse_ref("  ").is_err());
    }

    #[test]
    fn parse_ref_db_dsn() {
        let r = parse_ref("db://user:pw@host/db?schema=public&sslmode=disable").unwrap();
        assert_eq!(r.scheme, Scheme::Db);
        assert_eq!(r.schema, "public");
        // `schema` removed; `postgres://` prepended; other params kept.
        assert_eq!(r.dsn, "postgres://user:pw@host/db?sslmode=disable");

        // schema is the only param → '?' dropped.
        let r = parse_ref("db://postgres://h/db?schema=app").unwrap();
        assert_eq!(r.schema, "app");
        assert_eq!(r.dsn, "postgres://h/db");

        // No schema param.
        let r = parse_ref("db://postgresql://h/db").unwrap();
        assert_eq!(r.schema, "");
        assert_eq!(r.dsn, "postgresql://h/db");
    }

    #[test]
    fn load_spec_str_bare_and_wrapped() {
        let bare = "tables:\n  - name: users\n    columns:\n      - name: id\n        type: bigint\n        nullable: false\n        primaryKey: true\n";
        let spec = load_spec_str(bare).unwrap();
        assert_eq!(spec.tables.len(), 1);
        assert_eq!(spec.tables[0].name, "users");
        assert!(spec.tables[0].columns[0].primary_key);
        assert_eq!(spec.tables[0].columns[0].r#type, "bigint");

        let wrapped = "apiVersion: keystone.hexxlock.io/v1alpha1\nkind: SchemaDefinition\nmetadata:\n  name: x\nspec:\n  allowDestructive: true\n  tables:\n    - name: t\n      columns:\n        - name: id\n          type: int\n";
        let spec = load_spec_str(wrapped).unwrap();
        assert_eq!(spec.tables.len(), 1);
        assert!(spec.allow_destructive);
        assert_eq!(spec.tables[0].name, "t");
    }

    #[test]
    fn load_spec_str_camelcase_fields() {
        // enableRLS + where + columnRefs round-trip through the camelCase tags.
        let y = "tables:\n  - name: t\n    enableRLS: true\n    columns:\n      - name: id\n        type: int\n    indexes:\n      - name: ix\n        where: deleted_at IS NULL\n        columnRefs:\n          - name: a\n            direction: desc\n";
        let spec = load_spec_str(y).unwrap();
        assert!(spec.tables[0].enable_rls);
        assert_eq!(spec.tables[0].indexes[0].where_, "deleted_at IS NULL");
        assert_eq!(spec.tables[0].indexes[0].column_refs[0].direction, "desc");
    }
}
