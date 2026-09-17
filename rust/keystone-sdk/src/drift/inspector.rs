// SPDX-License-Identifier: Apache-2.0

//! The live-schema inspector.
//!
//! Ported from the Go `drift.Inspector`. Runs read-only queries against
//! `information_schema` + `pg_catalog` for the named schema and returns a
//! deterministic [`Snapshot`]. The Go reference binds to a `pgxpool.Pool`;
//! this port borrows a `&tokio_postgres::Client` per call (the caller owns
//! the connection lifecycle — same model as the runner).
//!
//! ## Query fidelity
//!
//! The SQL is reproduced verbatim from the Go inspector, with one class of
//! adaptation: `information_schema` exposes several columns through SQL-
//! standard *domains* (`sql_identifier`, `cardinal_number`, …) and
//! `pg_sequences.data_type` is a `regtype`. pgx decodes those transparently;
//! tokio-postgres is stricter, so those columns are cast to a concrete type
//! (`::text` / `::int`) that yields a byte-identical value. Such casts are
//! marked inline. No predicate, join, ordering, or filter is changed.

use tokio_postgres::Client;

use crate::ident::{validate_identifier, IdentError};

use super::{
    constraint_type_name, extract_trigger_when, ColumnShape, EnumShape, ExtShape, FuncShape,
    MatViewShape, ObjectDdl, PolicyShape, SeqShape, Snapshot, TableShape, TriggerShape,
};

/// Errors raised by the inspector.
#[derive(Debug, thiserror::Error)]
pub enum InspectError {
    #[error(transparent)]
    Ident(#[from] IdentError),
    #[error(transparent)]
    Db(#[from] tokio_postgres::Error),
}

/// Queries the live schema and returns a [`Snapshot`].
#[derive(Debug, Default, Clone, Copy)]
pub struct Inspector;

impl Inspector {
    /// Creates a new inspector.
    pub fn new() -> Self {
        Inspector
    }

    /// Queries `information_schema` + `pg_catalog` for `schema` and returns
    /// a deterministic [`Snapshot`].
    pub async fn inspect(&self, client: &Client, schema: &str) -> Result<Snapshot, InspectError> {
        validate_identifier("schema", schema)?;

        let mut out = Snapshot {
            schema: schema.to_string(),
            ..Default::default()
        };

        // Tables.
        let table_rows = client
            .query(
                "SELECT table_name, table_type
                   FROM information_schema.tables
                  WHERE table_schema = $1
                    AND table_name NOT IN ('schema_migrations', 'keystone_baselines', 'keystone_schema_migrations', 'keystone_smoke_marker', 'keystone_pipeline_test_sentinel', 'keystone_e2e_test', 'keystone_e2e_audit_test')
                  ORDER BY table_name",
                &[&schema],
            )
            .await?;
        for row in &table_rows {
            // table_name / table_type are sql_identifier / character_data
            // domains; ::text yields the same value for the strict driver.
            let name: String = row.get(0);
            let kind: String = row.get(1);
            out.tables.push(TableShape {
                name,
                kind,
                ..Default::default()
            });
        }

        // Index of table name → position for back-filling columns/views/RLS.
        let table_pos: std::collections::HashMap<String, usize> = out
            .tables
            .iter()
            .enumerate()
            .map(|(i, t)| (t.name.clone(), i))
            .collect();

        // View definitions — populate `view_definition` for VIEW entries.
        //
        // `pg_get_viewdef(oid, pretty => true)`, not
        // `information_schema.views.view_definition`. Two reasons:
        //
        //  1. Canonical form. `information_schema.views.view_definition` is the
        //     raw ruleutils output: it fully-parenthesises every expression and
        //     join — `sum((a * b))`, `((ap.id = ta.addon_id))`, `(0)::bigint`,
        //     `FROM ((((t CROSS JOIN q) LEFT JOIN …)))`.
        //     `pg_get_viewdef(oid, true)` is the PRETTY-printed form that strips
        //     those redundant parens — the exact form `\d+`, pgAdmin, and a hand
        //     `pg_get_viewdef` capture all produce, i.e. the form humans author
        //     `spec.views[].query` in. The differ's `normalise_view_body`
        //     collapses whitespace/case/quotes but does NOT re-parenthesise, so
        //     an info_schema-form observed body never equals a pretty-form
        //     desired body → the differ re-emits `CREATE OR REPLACE VIEW` every
        //     reconcile, forever (the schema never converges to Ready).
        //
        //  2. Robustness. `information_schema.views.view_definition` is NULL
        //     when the caller lacks USAGE on the view's schema or EXECUTE on a
        //     function it references. `pg_get_viewdef` reconstructs from the
        //     catalog regardless of privilege on referenced objects.
        //
        // This mirrors `go/drift/inspector.go` exactly; the two inspectors must
        // agree byte-for-byte because `drift::hash` is compared across them.
        // `relkind = 'v'` is the exact set `information_schema.views` exposed
        // (regular views only); materialized views (relkind 'm') are inspected
        // separately.
        let view_rows = client
            .query(
                "SELECT c.relname AS table_name,
                        COALESCE(pg_get_viewdef(c.oid, true), '') AS view_definition
                   FROM pg_class c
                   JOIN pg_namespace n ON n.oid = c.relnamespace
                  WHERE n.nspname = $1
                    AND c.relkind = 'v'
                  ORDER BY c.relname",
                &[&schema],
            )
            .await?;
        for row in &view_rows {
            let name: String = row.get(0);
            let def: String = row.get(1);
            if let Some(&i) = table_pos.get(&name) {
                out.tables[i].view_definition = def;
            }
        }

        // Columns.
        let col_rows = client
            .query(
                // format_type / attidentity come from pg_attribute, which
                // information_schema.columns does not expose: data_type drops
                // every type modifier (varchar(64) → "character varying") and
                // there is no identity column at all. Both are load-bearing —
                // see the field docs on `ColumnShape`. LEFT JOIN so a table
                // that races out from under us degrades to empty strings
                // rather than dropping the column row entirely.
                "SELECT c.table_name, c.column_name, c.ordinal_position,
                        c.data_type, c.udt_name,
                        (c.is_nullable = 'YES') AS nullable,
                        COALESCE(c.column_default, '') AS column_default,
                        COALESCE(format_type(a.atttypid, a.atttypmod), '') AS formatted_type,
                        COALESCE(a.attidentity::text, '') AS identity,
                        COALESCE(c.generation_expression, '') AS generation_expression
                   FROM information_schema.columns c
                   LEFT JOIN pg_namespace n ON n.nspname = c.table_schema
                   LEFT JOIN pg_class     k ON k.relname = c.table_name AND k.relnamespace = n.oid
                   LEFT JOIN pg_attribute a ON a.attrelid = k.oid
                                           AND a.attname = c.column_name
                                           AND NOT a.attisdropped
                  WHERE c.table_schema = $1
                    AND c.table_name NOT IN ('schema_migrations', 'keystone_baselines', 'keystone_schema_migrations', 'keystone_smoke_marker', 'keystone_pipeline_test_sentinel', 'keystone_e2e_test', 'keystone_e2e_audit_test')
                  ORDER BY c.table_name, c.ordinal_position",
                &[&schema],
            )
            .await?;
        for row in &col_rows {
            let tname: String = row.get(0);
            // ordinal_position is a cardinal_number domain over int4.
            let ordinal: i32 = row.get(2);
            let c = ColumnShape {
                name: row.get(1),
                ordinal: ordinal as i64,
                data_type: row.get(3),
                udt_name: row.get(4),
                nullable: row.get(5),
                default: row.get(6),
                formatted_type: row.get(7),
                generated: row.get(9),
                identity: row.get(8),
            };
            if let Some(&i) = table_pos.get(&tname) {
                out.tables[i].columns.push(c);
            }
        }

        // Indexes — pg_indexes gives the CREATE INDEX statement verbatim.
        let idx_rows = client
            .query(
                "SELECT indexname, tablename, indexdef
                   FROM pg_indexes
                  WHERE schemaname = $1
                  ORDER BY tablename, indexname",
                &[&schema],
            )
            .await?;
        for row in &idx_rows {
            out.indexes.push(ObjectDdl {
                name: row.get(0),
                table: row.get(1),
                r#type: "index".to_string(),
                definition: row.get(2),
            });
        }

        // Constraints.
        let cst_rows = client
            .query(
                "SELECT con.conname,
                        cls.relname,
                        con.contype,
                        pg_get_constraintdef(con.oid) AS def
                   FROM pg_constraint con
                   JOIN pg_class      cls ON cls.oid = con.conrelid
                   JOIN pg_namespace  ns  ON ns.oid  = cls.relnamespace
                  WHERE ns.nspname = $1
                  ORDER BY cls.relname, con.conname",
                &[&schema],
            )
            .await?;
        for row in &cst_rows {
            // contype is PG's internal "char" type → i8 over the wire.
            let ctyp: i8 = row.get(2);
            out.constraints.push(ObjectDdl {
                name: row.get(0),
                table: row.get(1),
                r#type: constraint_type_name(ctyp as u8).to_string(),
                definition: row.get(3),
            });
        }

        // Enums.
        let enum_rows = client
            .query(
                "SELECT t.typname, array_agg(e.enumlabel ORDER BY e.enumsortorder)
                   FROM pg_type t
                   JOIN pg_enum e ON e.enumtypid = t.oid
                   JOIN pg_namespace n ON n.oid = t.typnamespace
                  WHERE n.nspname = $1
                  GROUP BY t.typname
                  ORDER BY t.typname",
                &[&schema],
            )
            .await?;
        for row in &enum_rows {
            out.enums.push(EnumShape {
                name: row.get(0),
                labels: row.get(1),
            });
        }

        // Extensions installed INTO this schema only. An extension a schema
        // depends on but does not own — the common `pgcrypto` in `public`
        // supplying gen_random_uuid() — is provisioned a layer up, by
        // `LogicalDatabase.spec.extensions`, which runs before any schema
        // exists. Recording every database-scoped extension here would write
        // another tenant's schema name into an authored
        // `CREATE EXTENSION … SCHEMA <other-tenant>`.
        //
        // Built-in plpgsql is excluded: it is present in every database by
        // default, so declaring it would make every generated spec carry a line
        // that means nothing.
        let ext_rows = client
            .query(
                "SELECT e.extname, n.nspname, e.extversion
                   FROM pg_extension e
                   JOIN pg_namespace n ON n.oid = e.extnamespace
                  WHERE e.extname <> 'plpgsql'
                    AND n.nspname = $1
                  ORDER BY e.extname",
                &[&schema],
            )
            .await?;
        for row in &ext_rows {
            out.extensions.push(ExtShape {
                name: row.get(0),
                schema: row.get(1),
                version: row.get(2),
            });
        }

        // Sequences. pg_sequences.data_type is a regtype; ::text gives the
        // same name (e.g. "bigint") for the strict driver.
        let seq_rows = client
            .query(
                "SELECT s.sequencename,
                        s.data_type::text,
                        s.increment_by,
                        s.min_value,
                        s.max_value,
                        s.start_value
                   FROM pg_sequences s
                  WHERE s.schemaname = $1
                  ORDER BY s.sequencename",
                &[&schema],
            )
            .await?;
        for row in &seq_rows {
            out.sequences.push(SeqShape {
                name: row.get(0),
                data_type: row.get(1),
                increment_by: row.get(2),
                min_value: row.get(3),
                max_value: row.get(4),
                start_value: row.get(5),
            });
        }

        // Functions — filter out extension-owned functions via the
        // LEFT JOIN on pg_depend deptype='e'.
        let func_rows = client
            .query(
                "SELECT p.proname,
                        pg_get_function_arguments(p.oid) AS args,
                        pg_get_function_result(p.oid) AS returns,
                        l.lanname AS language,
                        pg_get_functiondef(p.oid) AS definition
                   FROM pg_proc p
                   JOIN pg_namespace n ON n.oid = p.pronamespace
                   JOIN pg_language l ON l.oid = p.prolang
                   LEFT JOIN pg_depend d
                          ON d.objid = p.oid
                         AND d.classid = 'pg_proc'::regclass
                         AND d.deptype = 'e'
                  WHERE n.nspname = $1
                    AND p.prokind IN ('f', 'p')
                    AND d.objid IS NULL
                  ORDER BY p.proname",
                &[&schema],
            )
            .await?;
        for row in &func_rows {
            out.functions.push(FuncShape {
                name: row.get(0),
                args: row.get(1),
                returns: row.get(2),
                language: row.get(3),
                definition: row.get(4),
            });
        }

        // RLS flags per table. Both bits are read for every ordinary table
        // rather than filtering to `relrowsecurity = true`: a filtered query
        // cannot distinguish a table whose RLS was turned off from one that
        // never had it, and the snapshot needs to record protection being
        // removed. See the Go inspector's TableShape.RLSForced for why FORCE
        // is tracked separately.
        let rls_rows = client
            .query(
                "SELECT c.relname, c.relrowsecurity, c.relforcerowsecurity
                   FROM pg_class c
                   JOIN pg_namespace n ON n.oid = c.relnamespace
                  WHERE n.nspname = $1
                    AND c.relkind = 'r'",
                &[&schema],
            )
            .await?;
        for row in &rls_rows {
            let name: String = row.get(0);
            if let Some(&i) = table_pos.get(&name) {
                out.tables[i].rls_enabled = row.get(1);
                // Always `Some`: an inspected table's FORCE state is known,
                // and `None` is reserved for snapshots predating the field.
                out.tables[i].rls_forced = Some(row.get(2));
            }
        }

        // Policies.
        let pol_rows = client
            .query(
                "SELECT tablename,
                        policyname,
                        permissive,
                        COALESCE(roles, '{public}'::name[]) AS roles,
                        COALESCE(cmd, 'ALL') AS cmd,
                        COALESCE(qual, '') AS using_expr,
                        COALESCE(with_check, '') AS with_check
                   FROM pg_policies
                  WHERE schemaname = $1
                  ORDER BY tablename, policyname",
                &[&schema],
            )
            .await?;
        for row in &pol_rows {
            let permissive: String = row.get(2);
            out.policies.push(PolicyShape {
                table: row.get(0),
                name: row.get(1),
                permissive: permissive == "PERMISSIVE",
                roles: row.get(3),
                command: row.get(4),
                using: row.get(5),
                with_check: row.get(6),
            });
        }

        // Triggers.
        let trg_rows = client
            .query(
                "SELECT c.relname                                 AS tbl,
                        t.tgname                                  AS name,
                        CASE WHEN (t.tgtype::integer & 64) != 0 THEN 'INSTEAD OF'
                             WHEN (t.tgtype::integer & 2)  != 0 THEN 'BEFORE'
                             ELSE 'AFTER' END                     AS timing,
                        ARRAY_REMOVE(ARRAY[
                            CASE WHEN (t.tgtype::integer & 4)  != 0 THEN 'INSERT'   END,
                            CASE WHEN (t.tgtype::integer & 8)  != 0 THEN 'DELETE'   END,
                            CASE WHEN (t.tgtype::integer & 16) != 0 THEN 'UPDATE'   END,
                            CASE WHEN (t.tgtype::integer & 32) != 0 THEN 'TRUNCATE' END
                        ], NULL)                                  AS events,
                        (t.tgtype::integer & 1) != 0              AS for_each_row,
                        p.proname                                 AS fn,
                        pg_get_triggerdef(t.oid)                  AS trigger_def
                   FROM pg_trigger t
                   JOIN pg_class c ON c.oid = t.tgrelid
                   JOIN pg_namespace n ON n.oid = c.relnamespace
                   JOIN pg_proc p ON p.oid = t.tgfoid
                  WHERE n.nspname = $1
                    AND NOT t.tgisinternal
                  ORDER BY c.relname, t.tgname",
                &[&schema],
            )
            .await?;
        for row in &trg_rows {
            let def: String = row.get(6);
            out.triggers.push(TriggerShape {
                table: row.get(0),
                name: row.get(1),
                timing: row.get(2),
                events: row.get(3),
                for_each_row: row.get(4),
                function: row.get(5),
                when: extract_trigger_when(&def),
            });
        }

        // Materialized views.
        let mv_rows = client
            .query(
                "SELECT matviewname, definition
                   FROM pg_matviews
                  WHERE schemaname = $1
                  ORDER BY matviewname",
                &[&schema],
            )
            .await?;
        for row in &mv_rows {
            out.materialized_views.push(MatViewShape {
                name: row.get(0),
                definition: row.get(1),
            });
        }

        // Defensive sort — the queries ORDER BY, but re-sort for safety
        // against driver row-order surprises.
        out.tables.sort_by(|a, b| a.name.cmp(&b.name));
        for t in &mut out.tables {
            t.columns.sort_by_key(|a| a.ordinal);
        }
        out.indexes
            .sort_by(|a, b| a.table.cmp(&b.table).then_with(|| a.name.cmp(&b.name)));
        out.constraints
            .sort_by(|a, b| a.table.cmp(&b.table).then_with(|| a.name.cmp(&b.name)));

        Ok(out)
    }
}
