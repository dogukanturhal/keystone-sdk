// SPDX-License-Identifier: Apache-2.0

//! Integration tests against a live PostgreSQL.
//!
//! These are gated behind the `integration` cargo feature so the default
//! `cargo test` needs no database. Run with:
//!
//! ```sh
//! KEYSTONE_TEST_DATABASE_URL=postgres://user:pass@localhost/db \
//!   cargo test --features integration
//! ```
//!
//! Each test connects, creates a throwaway schema, applies migrations, and
//! drops the schema. The connection string comes from
//! `KEYSTONE_TEST_DATABASE_URL`; tests are skipped (pass trivially) when it
//! is unset so a feature-on build without a DB still goes green in CI that
//! lacks Postgres.

#![cfg(feature = "integration")]

use keystone_sdk::declarative::spec::{
    DesiredCheckConstraint, DesiredColumn, DesiredEnum, DesiredForeignKey, DesiredFunction,
    DesiredIndex, DesiredSequence, DesiredTable, DesiredTrigger, DesiredView, SchemaDefinitionSpec,
};
use keystone_sdk::drift::{
    self, ensure_baseline_table, ensure_snapshot_column, read_baseline, read_snapshot,
    write_baseline, write_snapshot, Inspector, BASELINE_KIND_STRUCTURE,
};
use keystone_sdk::schemasource::{parse_ref, resolve_desired, snapshot_from_ddl};
use keystone_sdk::schemaspec::from_snapshot;
use keystone_sdk::tracking::{ensure_bookkeeping, is_applied, list_applied, record};
use keystone_sdk::{apply, inspect, ApplyOptions, SqlFile};
use tokio_postgres::NoTls;

fn dsn() -> Option<String> {
    std::env::var("KEYSTONE_TEST_DATABASE_URL").ok()
}

async fn connect(dsn: &str) -> tokio_postgres::Client {
    let (client, connection) = tokio_postgres::connect(dsn, NoTls)
        .await
        .expect("connect to test database");
    tokio::spawn(async move {
        if let Err(e) = connection.await {
            eprintln!("connection error: {e}");
        }
    });
    client
}

async fn fresh_schema(client: &tokio_postgres::Client, name: &str) {
    client
        .batch_execute(&format!(
            "DROP SCHEMA IF EXISTS {name} CASCADE; CREATE SCHEMA {name};"
        ))
        .await
        .expect("create schema");
}

#[tokio::test]
async fn apply_tx_path_records_version() {
    let Some(dsn) = dsn() else {
        eprintln!("KEYSTONE_TEST_DATABASE_URL unset; skipping");
        return;
    };
    let mut client = connect(&dsn).await;
    let schema = "keystone_it_tx";
    fresh_schema(&client, schema).await;

    let opts = ApplyOptions {
        schema: schema.to_string(),
        version: "001".to_string(),
        files: vec![SqlFile {
            name: "001_init.up.sql".to_string(),
            body: "CREATE TABLE t (id int);".to_string(),
        }],
        tracking_table: None,
        owner_role: None,
    };
    let res = apply(&mut client, opts).await.expect("apply");
    assert_eq!(res.version, "001");
    assert_eq!(res.files.len(), 1);

    let applied = is_applied(&client, schema, "schema_migrations", "001")
        .await
        .expect("is_applied");
    assert!(applied.is_some());
    assert_eq!(applied.unwrap().content_hash, res.content_hash);

    client
        .batch_execute(&format!("DROP SCHEMA {schema} CASCADE"))
        .await
        .unwrap();
}

#[tokio::test]
async fn apply_same_version_same_hash_is_noop() {
    let Some(dsn) = dsn() else {
        eprintln!("KEYSTONE_TEST_DATABASE_URL unset; skipping");
        return;
    };
    let mut client = connect(&dsn).await;
    let schema = "keystone_it_noop";
    fresh_schema(&client, schema).await;

    let mk = || ApplyOptions {
        schema: schema.to_string(),
        version: "001".to_string(),
        files: vec![SqlFile {
            name: "001_init.up.sql".to_string(),
            body: "CREATE TABLE t (id int);".to_string(),
        }],
        tracking_table: None,
        owner_role: None,
    };
    apply(&mut client, mk()).await.expect("first apply");
    let second = apply(&mut client, mk()).await.expect("second apply");
    assert!(second.files.is_empty());
    assert_eq!(second.total_duration_ms, 0);

    client
        .batch_execute(&format!("DROP SCHEMA {schema} CASCADE"))
        .await
        .unwrap();
}

#[tokio::test]
async fn apply_same_version_different_hash_is_refused() {
    let Some(dsn) = dsn() else {
        eprintln!("KEYSTONE_TEST_DATABASE_URL unset; skipping");
        return;
    };
    let mut client = connect(&dsn).await;
    let schema = "keystone_it_refuse";
    fresh_schema(&client, schema).await;

    let first = ApplyOptions {
        schema: schema.to_string(),
        version: "001".to_string(),
        files: vec![SqlFile {
            name: "001_init.up.sql".to_string(),
            body: "CREATE TABLE t (id int);".to_string(),
        }],
        tracking_table: None,
        owner_role: None,
    };
    apply(&mut client, first).await.expect("first apply");

    let changed = ApplyOptions {
        schema: schema.to_string(),
        version: "001".to_string(),
        files: vec![SqlFile {
            name: "001_init.up.sql".to_string(),
            body: "CREATE TABLE t (id bigint);".to_string(),
        }],
        tracking_table: None,
        owner_role: None,
    };
    let err = apply(&mut client, changed).await.unwrap_err();
    assert!(err.to_string().contains("bump Version to ship changed SQL"));

    client
        .batch_execute(&format!("DROP SCHEMA {schema} CASCADE"))
        .await
        .unwrap();
}

#[tokio::test]
async fn no_tx_path_handles_concurrently() {
    let Some(dsn) = dsn() else {
        eprintln!("KEYSTONE_TEST_DATABASE_URL unset; skipping");
        return;
    };
    let mut client = connect(&dsn).await;
    let schema = "keystone_it_conc";
    fresh_schema(&client, schema).await;

    // Seed a table in a first migration (tx path).
    apply(
        &mut client,
        ApplyOptions {
            schema: schema.to_string(),
            version: "001".to_string(),
            files: vec![SqlFile {
                name: "001_init.up.sql".to_string(),
                body: "CREATE TABLE t (id int);".to_string(),
            }],
            tracking_table: None,
            owner_role: None,
        },
    )
    .await
    .expect("seed apply");

    // CONCURRENTLY forces the no-tx path.
    apply(
        &mut client,
        ApplyOptions {
            schema: schema.to_string(),
            version: "002".to_string(),
            files: vec![SqlFile {
                name: "002_idx.up.sql".to_string(),
                body: "CREATE INDEX CONCURRENTLY idx_t_id ON t (id);".to_string(),
            }],
            tracking_table: None,
            owner_role: None,
        },
    )
    .await
    .expect("concurrently apply");

    let rows = list_applied(&client, schema, "schema_migrations")
        .await
        .expect("list");
    assert_eq!(rows.len(), 2);

    client
        .batch_execute(&format!("DROP SCHEMA {schema} CASCADE"))
        .await
        .unwrap();
}

#[tokio::test]
async fn tx_path_rows_affected_is_last_statement_count() {
    let Some(dsn) = dsn() else {
        eprintln!("KEYSTONE_TEST_DATABASE_URL unset; skipping");
        return;
    };
    let mut client = connect(&dsn).await;
    let schema = "keystone_it_rows_tx";
    fresh_schema(&client, schema).await;

    // TX path (no CONCURRENTLY): the whole file is one simple-query
    // round-trip, so rows_affected mirrors pgx's Exec = the LAST statement's
    // command tag. Here the trailing INSERT affects 3 rows.
    let res = apply(
        &mut client,
        ApplyOptions {
            schema: schema.to_string(),
            version: "001".to_string(),
            files: vec![SqlFile {
                name: "001_init.up.sql".to_string(),
                body: "CREATE TABLE t (id int);\nINSERT INTO t VALUES (1), (2), (3);".to_string(),
            }],
            tracking_table: None,
            owner_role: None,
        },
    )
    .await
    .expect("apply");
    assert_eq!(res.files.len(), 1);
    assert_eq!(res.files[0].rows_affected, 3);

    client
        .batch_execute(&format!("DROP SCHEMA {schema} CASCADE"))
        .await
        .unwrap();
}

#[tokio::test]
async fn no_tx_path_rows_affected_sums_statements() {
    let Some(dsn) = dsn() else {
        eprintln!("KEYSTONE_TEST_DATABASE_URL unset; skipping");
        return;
    };
    let mut client = connect(&dsn).await;
    let schema = "keystone_it_rows_conc";
    fresh_schema(&client, schema).await;

    // CONCURRENTLY forces the no-tx path, which splits the file and SUMS the
    // per-statement counts: CREATE TABLE (0) + INSERT 2 + CREATE INDEX
    // CONCURRENTLY (0) = 2.
    let res = apply(
        &mut client,
        ApplyOptions {
            schema: schema.to_string(),
            version: "001".to_string(),
            files: vec![SqlFile {
                name: "001_init.up.sql".to_string(),
                body: "CREATE TABLE t (id int);\nINSERT INTO t VALUES (1), (2);\n\
                       CREATE INDEX CONCURRENTLY idx_t_id ON t (id);"
                    .to_string(),
            }],
            tracking_table: None,
            owner_role: None,
        },
    )
    .await
    .expect("apply");
    assert_eq!(res.files.len(), 1);
    assert_eq!(res.files[0].rows_affected, 2);

    client
        .batch_execute(&format!("DROP SCHEMA {schema} CASCADE"))
        .await
        .unwrap();
}

#[tokio::test]
async fn record_baseline_upsert() {
    let Some(dsn) = dsn() else {
        eprintln!("KEYSTONE_TEST_DATABASE_URL unset; skipping");
        return;
    };
    let client = connect(&dsn).await;
    let schema = "keystone_it_record";
    fresh_schema(&client, schema).await;

    ensure_bookkeeping(&client, schema, "schema_migrations")
        .await
        .expect("ensure");
    record(&client, schema, "schema_migrations", "baseline", "deadbeef")
        .await
        .expect("record");
    let applied = is_applied(&client, schema, "schema_migrations", "baseline")
        .await
        .expect("is_applied")
        .expect("row present");
    assert_eq!(applied.content_hash, "deadbeef");
    assert_eq!(applied.duration_ms, 0);

    client
        .batch_execute(&format!("DROP SCHEMA {schema} CASCADE"))
        .await
        .unwrap();
}

/// Seeds a schema exercising every inspector query path: a base table with
/// array + enum + check columns, a view, indexes, a PK + CHECK constraint, an
/// enum type, a sequence, a function, an RLS policy, a trigger (with WHEN),
/// and a materialized view.
async fn seed_inspect_schema(client: &tokio_postgres::Client, schema: &str) {
    fresh_schema(client, schema).await;
    client
        .batch_execute(&format!(
            "SET search_path TO {schema};
             CREATE TYPE status AS ENUM ('new', 'paid', 'shipped');
             CREATE SEQUENCE ord_seq;
             CREATE TABLE orders (
                 id    bigint PRIMARY KEY DEFAULT nextval('ord_seq'),
                 email text NOT NULL,
                 tags  text[],
                 st    status,
                 qty   int CONSTRAINT orders_qty_chk CHECK (qty > 0)
             );
             CREATE INDEX orders_email_idx ON orders (email);
             CREATE VIEW order_emails AS SELECT email FROM orders;
             ALTER TABLE orders ENABLE ROW LEVEL SECURITY;
             CREATE POLICY p_sel ON orders FOR SELECT USING (true);
             CREATE FUNCTION bump() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RETURN NEW; END $$;
             CREATE TRIGGER trg BEFORE INSERT ON orders FOR EACH ROW WHEN (NEW.qty > 0) EXECUTE FUNCTION bump();
             CREATE MATERIALIZED VIEW mv AS SELECT count(*) AS c FROM orders;
             RESET search_path;"
        ))
        .await
        .expect("seed inspect schema");
}

#[tokio::test]
async fn inspect_full_schema_decodes_every_query() {
    let Some(dsn) = dsn() else {
        eprintln!("KEYSTONE_TEST_DATABASE_URL unset; skipping");
        return;
    };
    let client = connect(&dsn).await;
    let schema = "keystone_it_inspect";
    seed_inspect_schema(&client, schema).await;

    let snap = Inspector::new()
        .inspect(&client, schema)
        .await
        .expect("inspect");

    assert_eq!(snap.schema, schema);

    // Tables: information_schema.tables yields the base table + the view,
    // sorted by name. Matviews are NOT in information_schema.tables.
    let table_names: Vec<&str> = snap.tables.iter().map(|t| t.name.as_str()).collect();
    assert_eq!(table_names, vec!["order_emails", "orders"]);

    let orders = snap.tables.iter().find(|t| t.name == "orders").unwrap();
    assert_eq!(orders.kind, "BASE TABLE");
    assert!(orders.rls_enabled, "RLS flag should be set");
    let col = |n: &str| orders.columns.iter().find(|c| c.name == n).unwrap();
    // Columns ordered by ordinal.
    assert_eq!(
        orders
            .columns
            .iter()
            .map(|c| c.name.as_str())
            .collect::<Vec<_>>(),
        vec!["id", "email", "tags", "st", "qty"]
    );
    assert!(col("id").default.contains("nextval"));
    assert!(!col("email").nullable);
    // ARRAY / USER-DEFINED type reporting (the resolve_column_type inputs).
    assert_eq!(col("tags").data_type, "ARRAY");
    assert_eq!(col("tags").udt_name, "_text");
    assert_eq!(col("st").data_type, "USER-DEFINED");
    assert_eq!(col("st").udt_name, "status");

    let view = snap
        .tables
        .iter()
        .find(|t| t.name == "order_emails")
        .unwrap();
    assert_eq!(view.kind, "VIEW");
    assert!(view.view_definition.contains("email"), "view def captured");

    // Indexes: the explicit one + the PK-backing index.
    let idx_names: Vec<&str> = snap.indexes.iter().map(|i| i.name.as_str()).collect();
    assert!(idx_names.contains(&"orders_email_idx"));
    assert!(idx_names.contains(&"orders_pkey"));
    assert!(snap.indexes.iter().all(|i| i.r#type == "index"));

    // Constraints: PK + CHECK, with contype → human name.
    let pk = snap
        .constraints
        .iter()
        .find(|c| c.r#type == "PRIMARY KEY")
        .unwrap();
    assert_eq!(pk.table, "orders");
    let chk = snap
        .constraints
        .iter()
        .find(|c| c.r#type == "CHECK")
        .unwrap();
    assert!(chk.definition.to_uppercase().contains("CHECK"));

    // Enums.
    let status_enum = snap.enums.iter().find(|e| e.name == "status").unwrap();
    assert_eq!(status_enum.labels, vec!["new", "paid", "shipped"]);

    // Sequences (regtype data_type decoded via ::text).
    let seq = snap.sequences.iter().find(|s| s.name == "ord_seq").unwrap();
    assert_eq!(seq.data_type, "bigint");
    assert_eq!(seq.increment_by, 1);

    // Functions (extension-owned filtered; bump() should appear).
    let bump = snap.functions.iter().find(|f| f.name == "bump").unwrap();
    assert_eq!(bump.language, "plpgsql");
    assert!(bump.definition.contains("CREATE OR REPLACE FUNCTION"));

    // Policies.
    let pol = snap.policies.iter().find(|p| p.name == "p_sel").unwrap();
    assert_eq!(pol.table, "orders");
    assert_eq!(pol.command, "SELECT");
    assert!(pol.permissive);

    // Triggers (WHEN extracted from pg_get_triggerdef).
    let trg = snap.triggers.iter().find(|t| t.name == "trg").unwrap();
    assert_eq!(trg.timing, "BEFORE");
    assert_eq!(trg.events, vec!["INSERT"]);
    assert!(trg.for_each_row);
    assert_eq!(trg.function, "bump");
    assert!(trg.when.contains("new.qty"), "WHEN clause: {:?}", trg.when);

    // Materialized views.
    let mv = snap
        .materialized_views
        .iter()
        .find(|m| m.name == "mv")
        .unwrap();
    assert!(mv.definition.to_lowercase().contains("count"));

    // Hash is deterministic.
    assert_eq!(drift::hash(&snap).unwrap(), drift::hash(&snap).unwrap());

    // Public projection: tables/indexes/constraints carry through.
    let pub_snap = inspect(&client, schema).await.expect("public inspect");
    assert_eq!(pub_snap.schema, schema);
    assert_eq!(pub_snap.tables.len(), snap.tables.len());
    assert_eq!(pub_snap.indexes.len(), snap.indexes.len());
    assert_eq!(pub_snap.constraints.len(), snap.constraints.len());

    client
        .batch_execute(&format!("DROP SCHEMA {schema} CASCADE"))
        .await
        .unwrap();
}

#[tokio::test]
async fn baseline_and_snapshot_store_roundtrip() {
    let Some(dsn) = dsn() else {
        eprintln!("KEYSTONE_TEST_DATABASE_URL unset; skipping");
        return;
    };
    let client = connect(&dsn).await;
    let schema = "keystone_it_baseline";
    seed_inspect_schema(&client, schema).await;

    let snap = Inspector::new()
        .inspect(&client, schema)
        .await
        .expect("inspect");
    let h = drift::hash(&snap).unwrap();

    ensure_baseline_table(&client, schema)
        .await
        .expect("ensure baseline");
    ensure_snapshot_column(&client, schema)
        .await
        .expect("ensure snapshot column");

    // No baseline yet.
    assert!(read_baseline(&client, schema, BASELINE_KIND_STRUCTURE)
        .await
        .expect("read")
        .is_none());

    write_baseline(
        &client,
        schema,
        BASELINE_KIND_STRUCTURE,
        &h,
        "drift-acceptance",
    )
    .await
    .expect("write baseline");
    let b = read_baseline(&client, schema, BASELINE_KIND_STRUCTURE)
        .await
        .expect("read")
        .expect("row present");
    assert_eq!(b.kind, "structure");
    assert_eq!(b.hash, h);
    assert_eq!(b.source, "drift-acceptance");

    // Snapshot JSONB round-trips back to an equal snapshot (and thus an
    // equal hash — drift detection is self-consistent).
    write_snapshot(&client, schema, &snap)
        .await
        .expect("write snapshot");
    let back = read_snapshot(&client, schema)
        .await
        .expect("read snapshot")
        .expect("snapshot present");
    assert_eq!(back, snap);
    assert_eq!(drift::hash(&back).unwrap(), h);

    client
        .batch_execute(&format!("DROP SCHEMA {schema} CASCADE"))
        .await
        .unwrap();
}

/// Builds a representative desired spec covering tables (FK topo), unique
/// index, CHECK, enum, sequence, function, trigger, RLS, and a view.
fn roundtrip_spec() -> SchemaDefinitionSpec {
    let dcol = |name: &str, ty: &str, nullable: bool, pk: bool| DesiredColumn {
        name: name.into(),
        r#type: ty.into(),
        nullable,
        primary_key: pk,
        ..Default::default()
    };
    SchemaDefinitionSpec {
        enums: vec![DesiredEnum {
            name: "status".into(),
            values: vec!["new".into(), "active".into()],
        }],
        sequences: vec![DesiredSequence {
            name: "s1".into(),
            data_type: "bigint".into(),
            increment_by: 1,
            ..Default::default()
        }],
        tables: vec![
            DesiredTable {
                name: "orders".into(),
                columns: vec![
                    dcol("id", "bigint", false, true),
                    dcol("user_id", "bigint", false, false),
                ],
                foreign_keys: vec![DesiredForeignKey {
                    name: "fk_orders_user".into(),
                    columns: vec!["user_id".into()],
                    references_table: "users".into(),
                    references_columns: vec!["id".into()],
                    on_delete: "CASCADE".into(),
                }],
                check_constraints: vec![DesiredCheckConstraint {
                    name: "chk_pos".into(),
                    definition: "id > 0".into(),
                }],
                ..Default::default()
            },
            DesiredTable {
                name: "users".into(),
                enable_rls: true,
                columns: vec![
                    dcol("id", "bigint", false, true),
                    dcol("email", "text", false, false),
                ],
                indexes: vec![DesiredIndex {
                    name: "idx_users_email".into(),
                    columns: vec!["email".into()],
                    unique: true,
                    method: "btree".into(),
                    ..Default::default()
                }],
                ..Default::default()
            },
        ],
        views: vec![DesiredView {
            name: "v_emails".into(),
            query: "SELECT email FROM users".into(),
            replace: true,
        }],
        functions: vec![DesiredFunction {
            name: "bump".into(),
            returns: "trigger".into(),
            language: "plpgsql".into(),
            body: " BEGIN RETURN NEW; END ".into(),
            replace: true,
            ..Default::default()
        }],
        triggers: vec![DesiredTrigger {
            name: "trg_bump".into(),
            table: "users".into(),
            timing: "BEFORE".into(),
            events: vec!["INSERT".into()],
            for_each_row: true,
            function: "bump".into(),
            ..Default::default()
        }],
        ..Default::default()
    }
}

/// Applies a freshly-diffed greenfield plan to a real schema, then
/// re-inspects and re-diffs. The generated SQL must apply cleanly (valid PG
/// in dependency order), and the second diff must produce NO destructive ops
/// and NO structural churn — validating the differ's match functions
/// (index/constraint/function/trigger/policy/enum/sequence) against REAL
/// pg_get_* canonical output, the gap the byte-golden can't cover.
#[tokio::test]
async fn diff_roundtrip_applies_and_converges() {
    let Some(dsn) = dsn() else {
        eprintln!("KEYSTONE_TEST_DATABASE_URL unset; skipping");
        return;
    };
    let client = connect(&dsn).await;
    let schema = "keystone_it_diff";
    fresh_schema(&client, schema).await;

    let desired = roundtrip_spec();

    let empty = Inspector::new()
        .inspect(&client, schema)
        .await
        .expect("inspect empty");
    let plan = keystone_sdk::declarative::diff(&empty, &desired).expect("diff");
    assert!(!plan.statements.is_empty());

    // The runner sets search_path to the target schema before applying so
    // unqualified references (e.g. the view's `FROM users`) resolve.
    client
        .batch_execute(&format!("SET search_path TO {schema}"))
        .await
        .expect("set search_path");

    // Apply each statement in autocommit (CONCURRENTLY can't run in a tx).
    for stmt in &plan.statements {
        client
            .batch_execute(stmt)
            .await
            .unwrap_or_else(|e| panic!("apply failed for statement:\n{stmt}\nerror: {e}"));
    }

    let live = Inspector::new()
        .inspect(&client, schema)
        .await
        .expect("inspect live");
    let replan = keystone_sdk::declarative::diff(&live, &desired).expect("re-diff");

    assert_eq!(
        replan.destructive_ops, 0,
        "re-diff churn:\n{:#?}",
        replan.statements
    );
    for stmt in &replan.statements {
        assert!(
            !stmt.starts_with("DROP")
                && !stmt.starts_with("CREATE TABLE")
                && !stmt.contains("ADD COLUMN")
                && !stmt.contains("CREATE SEQUENCE")
                && !stmt.contains("ADD CONSTRAINT")
                && !stmt.contains("CREATE UNIQUE INDEX")
                && !stmt.contains("CREATE TYPE"),
            "unexpected structural churn on re-diff: {stmt}"
        );
    }

    client
        .batch_execute(&format!("DROP SCHEMA {schema} CASCADE"))
        .await
        .unwrap();
}

/// Exercises the dev-database normaliser: `snapshot_from_ddl` applies raw DDL
/// to a throwaway scratch schema (via the production runner), inspects it,
/// rewrites the scratch name to the target schema, and drops the scratch. Then
/// `from_snapshot` lifts it into a spec, and the sql:// `resolve_desired` path
/// produces the same. Validates the whole "SQL → dev DB → Snapshot → Spec"
/// pipeline against real PostgreSQL.
#[tokio::test]
async fn schemasource_dev_db_normaliser_and_resolve() {
    let Some(dsn) = dsn() else {
        eprintln!("KEYSTONE_TEST_DATABASE_URL unset; skipping");
        return;
    };
    let mut client = connect(&dsn).await;

    let ddl = "CREATE TABLE widgets (id bigint PRIMARY KEY, name text NOT NULL);\n\
               CREATE INDEX idx_widgets_name ON widgets (name);";

    let snap = snapshot_from_ddl(&mut client, ddl, "app")
        .await
        .expect("snapshot_from_ddl");
    // The snapshot reports the target schema, NOT the scratch name.
    assert_eq!(snap.schema, "app");
    assert!(snap
        .tables
        .iter()
        .any(|t| t.name == "widgets" && t.kind == "BASE TABLE"));
    let idx = snap
        .indexes
        .iter()
        .find(|i| i.name == "idx_widgets_name")
        .expect("index inspected");
    assert!(
        idx.definition.contains("app."),
        "scratch name rewritten to target: {}",
        idx.definition
    );
    assert!(
        !idx.definition.contains("keystone_dev_"),
        "scratch leaked: {}",
        idx.definition
    );

    // from_snapshot lifts it into a desired spec.
    let spec = from_snapshot(&snap);
    let widgets = spec.tables.iter().find(|t| t.name == "widgets").unwrap();
    assert!(widgets
        .columns
        .iter()
        .any(|c| c.name == "id" && c.primary_key));
    assert!(widgets.indexes.iter().any(|i| i.name == "idx_widgets_name"));

    // The sql:// resolve path goes through the same normaliser.
    let dir = std::env::temp_dir();
    let path = dir.join(format!("keystone_it_{}.sql", std::process::id()));
    std::fs::write(&path, ddl).unwrap();
    let reference = parse_ref(&format!("sql://{}", path.display())).expect("parse_ref");
    let resolved = resolve_desired(&reference, Some(&mut client), "app")
        .await
        .expect("resolve sql://");
    assert!(resolved.tables.iter().any(|t| t.name == "widgets"));
    std::fs::remove_file(&path).ok();

    // No scratch schemas leaked.
    let rows = client
        .query(
            "SELECT schema_name FROM information_schema.schemata WHERE schema_name LIKE 'keystone_dev_%'",
            &[],
        )
        .await
        .unwrap();
    assert!(rows.is_empty(), "scratch schemas leaked: {}", rows.len());
}
