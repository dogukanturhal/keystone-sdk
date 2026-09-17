// SPDX-License-Identifier: Apache-2.0

//! Keystone's declarative schema differ.
//!
//! Ported from the Go `declarative` package. [`diff`] takes an observed
//! [`crate::drift::Snapshot`] and a desired [`spec::SchemaDefinitionSpec`]
//! and produces a [`Plan`] of forward + reverse SQL, warnings, and a
//! destructive-op count — refusing (via [`DiffError::DestructiveRefused`])
//! when the diff needs destructive ops and `allow_destructive` is false.
//!
//! Statements are emitted safe-first (creates before alters; adds before
//! drops). Where the Go differ ranges over a map to emit independent DROP
//! statements (order-irrelevant, non-deterministic in Go), this port
//! iterates in sorted key order for reproducibility.

pub mod spec;

mod normalise;

use std::collections::{BTreeMap, BTreeSet, HashMap};

use crate::drift::{self, ObjectDdl as DriftObjectDdl, Snapshot};
use crate::ident::{quote_identifier, quote_string};
use normalise::{defaults_equal, index_ddl_match, normalise_ddl};
use spec::*;

/// The differ's output. `reverse_statements` is index-aligned with
/// `statements` (`reverse_statements[i]` undoes `statements[i]`; empty means
/// not reversible).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Plan {
    pub statements: Vec<String>,
    pub reverse_statements: Vec<String>,
    pub warnings: Vec<String>,
    /// Counts statements that cannot be taken back by re-running the differ:
    /// DROP TABLE/COLUMN/INDEX/CONSTRAINT/TYPE/SEQUENCE/VIEW/FUNCTION, plus
    /// `NO FORCE ROW LEVEL SECURITY`. The last one destroys no data but
    /// exempts the table owner from every policy on the table, which on a
    /// multi-tenant schema is a wider blast radius than most DROPs — it
    /// belongs behind the same approval gate.
    pub destructive_ops: usize,
}

impl Plan {
    /// Whether the plan contains no statements.
    pub fn is_empty(&self) -> bool {
        self.statements.is_empty()
    }

    fn emit(&mut self, forward: String, reverse: String) {
        self.statements.push(forward);
        self.reverse_statements.push(reverse);
    }

    fn emit_destructive(&mut self, forward: String, reverse: String) {
        self.emit(forward, reverse);
        self.destructive_ops += 1;
    }
}

/// Error from [`diff`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DiffError {
    /// The diff needs destructive ops but `allow_destructive` is false. The
    /// computed [`Plan`] is attached so callers can surface the would-be
    /// statements without re-running the differ.
    DestructiveRefused { count: usize, plan: Plan },
}

impl std::fmt::Display for DiffError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DiffError::DestructiveRefused { count, .. } => write!(
                f,
                "{count} destructive operation(s) refused; set spec.allowDestructive=true to permit"
            ),
        }
    }
}

impl std::error::Error for DiffError {}

/// Computes the SQL transformation from `observed` to `desired`. On
/// destructive refusal returns [`DiffError::DestructiveRefused`] carrying the
/// plan (mirroring the Go `Diff` returning both plan and error).
pub fn diff(observed: &Snapshot, desired: &SchemaDefinitionSpec) -> Result<Plan, DiffError> {
    let mut plan = Plan::default();
    let schema = observed.schema.as_str();

    let obs_tables = observed_tables(observed);
    let obs_idx_by_table = observed_indexes_by_table(observed);
    let obs_cst_by_table = observed_constraints_by_table(observed);
    let des_tables = desired_tables(desired);

    // Phase 0a: Extensions — before every other object, since a column cannot
    // be declared with a type an extension has not yet created.
    diff_extensions(&mut plan, observed, desired);
    // Phase 0: Enums.
    diff_enums(&mut plan, schema, observed, desired);
    // Phase 1: Sequences.
    diff_sequences(&mut plan, schema, observed, desired);

    // Phase 2: Tables (topo-sorted CREATE, then ALTER).
    let (create_order, has_cycle) = topo_sort_tables(&desired.tables);
    if has_cycle {
        plan.warnings.push(
            "circular foreign key dependencies detected; tables with cycles \
             are appended alphabetically — consider using deferred constraints"
                .to_string(),
        );
    }
    for name in &create_order {
        let dt = des_tables[name];
        if !obs_tables.contains_key(name) {
            plan.emit(
                render_create_table(schema, dt),
                format!(
                    "DROP TABLE IF EXISTS {}.{}",
                    quote_identifier(schema),
                    quote_identifier(name)
                ),
            );
        }
    }

    let obs_table_names: BTreeSet<String> = obs_tables.keys().cloned().collect();

    // ALTER existing tables.
    for name in &create_order {
        let dt = des_tables[name];
        let Some(ot) = obs_tables.get(name) else {
            continue;
        };
        let empty_idx: Vec<&DriftObjectDdl> = Vec::new();
        let empty_cst: Vec<&DriftObjectDdl> = Vec::new();
        let obs_idx = obs_idx_by_table.get(name).unwrap_or(&empty_idx);
        let obs_cst = obs_cst_by_table.get(name).unwrap_or(&empty_cst);
        diff_table_full(
            &mut plan,
            schema,
            ot,
            dt,
            obs_idx,
            obs_cst,
            &obs_table_names,
        );
    }

    // New tables: emit secondary objects (indexes, FKs, CHECKs).
    for name in &create_order {
        if obs_tables.contains_key(name) {
            continue;
        }
        diff_table_objects(
            &mut plan,
            schema,
            des_tables[name],
            &[],
            &[],
            &obs_table_names,
        );
    }

    // Tables in observed but not desired → DROP TABLE.
    for o in sorted_observed_names(&obs_tables) {
        if des_tables.contains_key(&o) {
            continue;
        }
        plan.emit_destructive(
            format!(
                "DROP TABLE IF EXISTS {}.{}",
                quote_identifier(schema),
                quote_identifier(&o)
            ),
            String::new(),
        );
    }

    // Phase 2b–6.
    diff_rls(&mut plan, schema, observed, desired);
    diff_views(&mut plan, schema, observed, desired);
    diff_materialized_views(&mut plan, schema, observed, desired);
    diff_functions(&mut plan, schema, observed, desired);
    diff_triggers(&mut plan, schema, observed, desired);
    diff_policies(&mut plan, schema, observed, desired);

    if !desired.allow_destructive && plan.destructive_ops > 0 {
        let count = plan.destructive_ops;
        return Err(DiffError::DestructiveRefused { count, plan });
    }
    Ok(plan)
}

// --- Extension diffing ---

/// Emits `CREATE EXTENSION` for anything the desired spec declares that is not
/// already installed.
///
/// Creation only. `DROP EXTENSION` is deliberately never authored: extensions
/// are database-scoped and routinely shared by other schemas in the same
/// database, so dropping one because a single schema stopped referencing it
/// would break tenants the differ cannot see.
fn diff_extensions(plan: &mut Plan, observed: &Snapshot, desired: &SchemaDefinitionSpec) {
    let installed: BTreeSet<&str> = observed
        .extensions
        .iter()
        .map(|x| x.name.as_str())
        .collect();

    for x in &desired.extensions {
        if installed.contains(x.name.as_str()) {
            continue;
        }
        let mut stmt = format!(
            "CREATE EXTENSION IF NOT EXISTS {}",
            quote_identifier(&x.name)
        );
        if !x.schema.is_empty() {
            stmt.push_str(&format!(" SCHEMA {}", quote_identifier(&x.schema)));
        }
        plan.statements.push(stmt);
    }
}

// --- Enum diffing ---

fn escape_enum_value(v: &str) -> String {
    v.replace('\'', "''")
}

fn diff_enums(plan: &mut Plan, schema: &str, observed: &Snapshot, desired: &SchemaDefinitionSpec) {
    let mut obs_enums: HashMap<&str, BTreeSet<&str>> = HashMap::new();
    for e in &observed.enums {
        obs_enums.insert(
            e.name.as_str(),
            e.labels.iter().map(|s| s.as_str()).collect(),
        );
    }

    for e in &desired.enums {
        let qualified = format!("{}.{}", quote_identifier(schema), quote_identifier(&e.name));
        match obs_enums.get(e.name.as_str()) {
            None => {
                let val_list: Vec<String> = e
                    .values
                    .iter()
                    .map(|v| format!("'{}'", escape_enum_value(v)))
                    .collect();
                let create_sql = format!(
                    "DO $$ BEGIN CREATE TYPE {qualified} AS ENUM ({}); EXCEPTION WHEN duplicate_object THEN NULL; END $$",
                    val_list.join(", ")
                );
                plan.emit(create_sql, format!("DROP TYPE IF EXISTS {qualified}"));
            }
            Some(existing_labels) => {
                for v in &e.values {
                    if existing_labels.contains(v.as_str()) {
                        continue;
                    }
                    plan.emit(
                        format!(
                            "ALTER TYPE {qualified} ADD VALUE IF NOT EXISTS '{}'",
                            escape_enum_value(v)
                        ),
                        String::new(),
                    );
                }
                // Warn about labels in observed but not desired (sorted for
                // reproducibility; Go's map iteration is non-deterministic).
                for label in existing_labels {
                    if !e.values.iter().any(|v| v == label) {
                        plan.warnings.push(format!(
                            "enum {} has label {:?} in database but not in desired spec — \
                             PostgreSQL does not support removing enum values",
                            e.name, label
                        ));
                    }
                }
            }
        }
    }
}

// --- Sequence diffing ---

fn diff_sequences(
    plan: &mut Plan,
    schema: &str,
    observed: &Snapshot,
    desired: &SchemaDefinitionSpec,
) {
    let mut obs_seqs: HashMap<&str, &drift::SeqShape> = HashMap::new();
    for s in &observed.sequences {
        obs_seqs.insert(s.name.as_str(), s);
    }

    for s in &desired.sequences {
        let qualified = format!("{}.{}", quote_identifier(schema), quote_identifier(&s.name));
        let dt = if s.data_type.is_empty() {
            "bigint"
        } else {
            &s.data_type
        };
        let inc = if s.increment_by == 0 {
            1
        } else {
            s.increment_by
        };

        if let Some(obs) = obs_seqs.get(s.name.as_str()) {
            if sequence_matches(obs, dt, inc, s) {
                continue;
            }
        }

        let mut b = format!("CREATE SEQUENCE IF NOT EXISTS {qualified} AS {dt} INCREMENT BY {inc}");
        if s.min_value != 0 {
            b.push_str(&format!(" MINVALUE {}", s.min_value));
        }
        if s.max_value != 0 {
            b.push_str(&format!(" MAXVALUE {}", s.max_value));
        }
        if s.start_with != 0 {
            b.push_str(&format!(" START WITH {}", s.start_with));
        }
        plan.emit(b, format!("DROP SEQUENCE IF EXISTS {qualified}"));

        if !s.owned_by.is_empty() {
            plan.emit(
                format!(
                    "ALTER SEQUENCE {qualified} OWNED BY {}.{}",
                    quote_identifier(schema),
                    s.owned_by
                ),
                format!("ALTER SEQUENCE {qualified} OWNED BY NONE"),
            );
        }
    }
}

fn sequence_matches(
    observed: &drift::SeqShape,
    desired_dt: &str,
    desired_inc: i64,
    s: &DesiredSequence,
) -> bool {
    if !observed.data_type.eq_ignore_ascii_case(desired_dt) {
        return false;
    }
    if observed.increment_by != desired_inc {
        return false;
    }
    let asc = desired_inc > 0;
    sequence_bound_equal(observed.min_value, s.min_value, desired_dt, "min", asc)
        && sequence_bound_equal(observed.max_value, s.max_value, desired_dt, "max", asc)
        && sequence_bound_equal(observed.start_value, s.start_with, desired_dt, "start", asc)
}

fn sequence_bound_equal(
    observed: i64,
    desired: i64,
    data_type: &str,
    kind: &str,
    ascending: bool,
) -> bool {
    if desired != 0 {
        return observed == desired;
    }
    let (max_val, min_val): (i64, i64) = match data_type.to_lowercase().as_str() {
        "smallint" => (32767, -32768),
        "integer" => (2147483647, -2147483648),
        _ => (9223372036854775807, -9223372036854775808),
    };
    match kind {
        "min" => {
            if ascending {
                observed == 1
            } else {
                observed == min_val
            }
        }
        "max" => {
            if ascending {
                observed == max_val
            } else {
                observed == -1
            }
        }
        "start" => {
            if ascending {
                observed == 1
            } else {
                observed == max_val
            }
        }
        _ => false,
    }
}

// --- View diffing ---

fn normalise_view_body(s: &str) -> String {
    let s = s.trim();
    let s = s.strip_suffix(';').unwrap_or(s);
    normalise_ddl(s.trim())
}

fn diff_views(plan: &mut Plan, schema: &str, observed: &Snapshot, desired: &SchemaDefinitionSpec) {
    let mut obs_views: HashMap<&str, &str> = HashMap::new();
    for t in &observed.tables {
        if t.kind == "VIEW" {
            obs_views.insert(t.name.as_str(), t.view_definition.as_str());
        }
    }

    for v in &desired.views {
        let qualified = format!("{}.{}", quote_identifier(schema), quote_identifier(&v.name));
        if v.query.trim().is_empty() {
            plan.warnings.push(format!(
                "view {} has empty query; skipped to avoid emitting invalid `CREATE OR REPLACE VIEW … AS ;`. \
                 Either remove the row from spec.views or fill in the SELECT body.",
                v.name
            ));
            continue;
        }
        match obs_views.get(v.name.as_str()) {
            None => {
                plan.emit(
                    format!("CREATE OR REPLACE VIEW {qualified} AS {}", v.query),
                    format!("DROP VIEW IF EXISTS {qualified}"),
                );
            }
            Some(obs_def) => {
                if normalise_view_body(obs_def) == normalise_view_body(&v.query) {
                    continue;
                }
                if v.replace {
                    plan.emit(
                        format!("CREATE OR REPLACE VIEW {qualified} AS {}", v.query),
                        format!("DROP VIEW IF EXISTS {qualified}"),
                    );
                } else {
                    plan.warnings.push(format!(
                        "view {} exists with different body; set replace=true to update it",
                        v.name
                    ));
                }
            }
        }
    }
}

// --- Function diffing ---

fn extract_function_body(def: &str) -> String {
    let open_start = match def.find('$') {
        Some(i) => i,
        None => return def.to_string(),
    };
    let open_end = match def[open_start + 1..].find('$') {
        Some(i) => i,
        None => return def.to_string(),
    };
    let tag = &def[open_start..open_start + open_end + 2]; // `$function$` etc.
    let body_start = open_start + open_end + 2;
    match def[body_start..].find(tag) {
        None => def.to_string(),
        Some(close_idx) => def[body_start..body_start + close_idx].trim().to_string(),
    }
}

fn normalise_function_body(s: &str) -> String {
    s.to_lowercase()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

fn function_matches(observed: &drift::FuncShape, desired: &DesiredFunction) -> bool {
    if observed.args != desired.args {
        return false;
    }
    if observed.returns.trim().to_lowercase() != desired.returns.trim().to_lowercase() {
        return false;
    }
    let desired_lang = if desired.language.is_empty() {
        "plpgsql"
    } else {
        &desired.language
    };
    if !observed.language.eq_ignore_ascii_case(desired_lang) {
        return false;
    }
    let obs_body = extract_function_body(&observed.definition);
    let desired_body = desired.body.trim();
    normalise_function_body(&obs_body) == normalise_function_body(desired_body)
}

fn diff_functions(
    plan: &mut Plan,
    schema: &str,
    observed: &Snapshot,
    desired: &SchemaDefinitionSpec,
) {
    let mut obs_funcs: HashMap<String, &drift::FuncShape> = HashMap::new();
    for f in &observed.functions {
        obs_funcs.insert(format!("{}({})", f.name, f.args), f);
    }

    for f in &desired.functions {
        if let Some(obs) = obs_funcs.get(&format!("{}({})", f.name, f.args)) {
            if function_matches(obs, f) {
                continue;
            }
        }
        let qualified = format!("{}.{}", quote_identifier(schema), quote_identifier(&f.name));
        let lang = if f.language.is_empty() {
            "plpgsql"
        } else {
            &f.language
        };
        if lang.trim().eq_ignore_ascii_case("c") {
            plan.warnings.push(format!(
                "function {} skipped: LANGUAGE c is not supported in the declarative \
                 diff (requires PG superuser, non-portable). Move this function to \
                 a hand-authored migration bundle that runs as a DBA-privileged role.",
                f.name
            ));
            continue;
        }
        let create_verb = if f.replace {
            "CREATE OR REPLACE"
        } else {
            "CREATE"
        };
        let args = &f.args;
        let create_sql = format!(
            "{create_verb} FUNCTION {qualified}({args}) RETURNS {} LANGUAGE {lang} AS $fn${}$fn$",
            f.returns, f.body
        );
        let drop_sql = format!("DROP FUNCTION IF EXISTS {qualified}({args})");
        plan.emit(create_sql, drop_sql);
    }
}

// --- Table diffing ---

#[allow(clippy::too_many_arguments)]
fn diff_table_full(
    plan: &mut Plan,
    schema: &str,
    observed: &drift::TableShape,
    desired: &DesiredTable,
    obs_indexes: &[&DriftObjectDdl],
    obs_constraints: &[&DriftObjectDdl],
    obs_table_names: &BTreeSet<String>,
) {
    let qualified = format!(
        "{}.{}",
        quote_identifier(schema),
        quote_identifier(&desired.name)
    );

    let obs_cols = index_observed_columns(&observed.columns);
    let des_cols = index_desired_columns(&desired.columns);

    for dc in &desired.columns {
        let Some(oc) = obs_cols.get(dc.name.as_str()) else {
            plan.emit(
                format!(
                    "ALTER TABLE {qualified} ADD COLUMN IF NOT EXISTS {}",
                    render_column_def(dc)
                ),
                format!(
                    "ALTER TABLE {qualified} DROP COLUMN IF EXISTS {}",
                    quote_identifier(&dc.name)
                ),
            );
            continue;
        };
        let qcol = quote_identifier(&dc.name);
        if oc.nullable && !dc.nullable {
            if !dc.default.is_empty() {
                if !defaults_equal(&dc.default, &oc.default) {
                    plan.emit(
                        format!(
                            "ALTER TABLE {qualified} ALTER COLUMN {qcol} SET DEFAULT {}",
                            dc.default
                        ),
                        format!("ALTER TABLE {qualified} ALTER COLUMN {qcol} DROP DEFAULT"),
                    );
                }
                plan.emit(
                    format!(
                        "UPDATE {qualified} SET {qcol} = {} WHERE {qcol} IS NULL",
                        dc.default
                    ),
                    String::new(),
                );
                plan.emit(
                    format!("ALTER TABLE {qualified} ALTER COLUMN {qcol} SET NOT NULL"),
                    format!("ALTER TABLE {qualified} ALTER COLUMN {qcol} DROP NOT NULL"),
                );
            } else {
                plan.warnings.push(format!(
                    "column {}.{} becoming NOT NULL without DEFAULT — will fail if existing rows have NULL",
                    desired.name, dc.name
                ));
                plan.emit(
                    format!("ALTER TABLE {qualified} ALTER COLUMN {qcol} SET NOT NULL"),
                    format!("ALTER TABLE {qualified} ALTER COLUMN {qcol} DROP NOT NULL"),
                );
            }
        } else if !oc.nullable && dc.nullable {
            if is_primary_key_column(&dc.name, desired) {
                plan.warnings.push(format!(
                    "column {}.{} declared Nullable=true but is in the \
                     primary key; PG implicitly enforces NOT NULL on \
                     PK columns — DROP NOT NULL would fail SQLSTATE \
                     42P16. Either remove the column from primaryKey \
                     or set Nullable=false in spec.",
                    desired.name, dc.name
                ));
            } else {
                plan.emit(
                    format!("ALTER TABLE {qualified} ALTER COLUMN {qcol} DROP NOT NULL"),
                    format!("ALTER TABLE {qualified} ALTER COLUMN {qcol} SET NOT NULL"),
                );
            }
        } else if !dc.default.is_empty() && !defaults_equal(&dc.default, &oc.default) {
            let reverse = if oc.default.is_empty() {
                format!("ALTER TABLE {qualified} ALTER COLUMN {qcol} DROP DEFAULT")
            } else {
                format!(
                    "ALTER TABLE {qualified} ALTER COLUMN {qcol} SET DEFAULT {}",
                    oc.default
                )
            };
            plan.emit(
                format!(
                    "ALTER TABLE {qualified} ALTER COLUMN {qcol} SET DEFAULT {}",
                    dc.default
                ),
                reverse,
            );
        } else if dc.default.is_empty()
            && !oc.default.is_empty()
            && !defaults_equal(&dc.default, &oc.default)
        {
            plan.emit(
                format!("ALTER TABLE {qualified} ALTER COLUMN {qcol} DROP DEFAULT"),
                format!(
                    "ALTER TABLE {qualified} ALTER COLUMN {qcol} SET DEFAULT {}",
                    oc.default
                ),
            );
        }

        // Column TYPE drift: warn, don't emit.
        // `resolve_column_type_shape`, not the bare data_type/udt_name pair:
        // information_schema.data_type reports the type family without
        // modifiers, so a `character(64)` column reads back as `character` and
        // a declared `character(64)` warns as drift on every single reconcile.
        let observed_type = drift::resolve_column_type_shape(oc);
        if dc.r#type != observed_type {
            plan.warnings.push(format!(
                "column {}.{} type drift: observed={} desired={} — \
                 type changes require pgroll-expand-contract \
                 alter_column_type; NOT emitted",
                desired.name, dc.name, observed_type, dc.r#type
            ));
        }
    }

    // Columns in observed but not desired → DROP COLUMN (source order).
    for oc in &observed.columns {
        if des_cols.contains_key(oc.name.as_str()) {
            continue;
        }
        plan.emit_destructive(
            format!(
                "ALTER TABLE {qualified} DROP COLUMN IF EXISTS {}",
                quote_identifier(&oc.name)
            ),
            String::new(),
        );
    }

    diff_table_objects(
        plan,
        schema,
        desired,
        obs_indexes,
        obs_constraints,
        obs_table_names,
    );
}

/// The `DO $$ … pg_constraint existence guard … END $$` wrapper, reproduced
/// byte-for-byte (tabs included) from the Go raw-string template.
fn do_block_exists_guard(conname_quoted: &str, qualified_quoted: &str, inner: &str) -> String {
    format!(
        "DO $$ BEGIN\n\t\t\t\tIF NOT EXISTS (\n\t\t\t\t\tSELECT 1 FROM pg_constraint\n\t\t\t\t\t WHERE conname = {conname_quoted}\n\t\t\t\t\t   AND conrelid = {qualified_quoted}::regclass\n\t\t\t\t) THEN\n\t\t\t\t\t{inner};\n\t\t\t\tEND IF;\n\t\t\tEND $$"
    )
}

fn diff_table_objects(
    plan: &mut Plan,
    schema: &str,
    desired: &DesiredTable,
    obs_indexes: &[&DriftObjectDdl],
    obs_constraints: &[&DriftObjectDdl],
    obs_table_names: &BTreeSet<String>,
) {
    let qualified = format!(
        "{}.{}",
        quote_identifier(schema),
        quote_identifier(&desired.name)
    );

    // Index diff.
    //
    // The indexes backing a PRIMARY KEY or UNIQUE constraint are excluded from
    // the observed set, because the desired set never contains them: schemaspec
    // carries those constraints as constraints. Leaving them in makes every one
    // look like an index the user deleted, and the diff emits `DROP INDEX` for
    // the index a live constraint depends on — which PostgreSQL refuses
    // ("cannot drop index … because constraint … requires it"), so the whole
    // migration fails rather than just that statement.
    //
    // PostgreSQL always names a constraint's backing index after the
    // constraint, so the constraint list is the exact filter.
    let constraint_backed_idx: BTreeSet<&str> = obs_constraints
        .iter()
        .filter(|c| c.table == desired.name)
        .filter(|c| c.r#type == "PRIMARY KEY" || c.r#type == "UNIQUE")
        .map(|c| c.name.as_str())
        .collect();
    let mut obs_idx_map: BTreeMap<&str, &DriftObjectDdl> = BTreeMap::new();
    for idx in obs_indexes {
        if constraint_backed_idx.contains(idx.name.as_str()) {
            continue;
        }
        obs_idx_map.insert(idx.name.as_str(), idx);
    }

    for d_idx in &desired.indexes {
        match obs_idx_map.get(d_idx.name.as_str()) {
            None => {
                let fwd = render_create_index_concurrently(schema, &desired.name, d_idx);
                plan.emit(
                    fwd,
                    format!(
                        "DROP INDEX CONCURRENTLY IF EXISTS {}.{}",
                        quote_identifier(schema),
                        quote_identifier(&d_idx.name)
                    ),
                );
            }
            Some(o_idx) => {
                let expected = render_create_index(schema, &desired.name, d_idx);
                if !index_ddl_match(&o_idx.definition, &expected) {
                    plan.emit_destructive(
                        format!(
                            "DROP INDEX CONCURRENTLY IF EXISTS {}.{}",
                            quote_identifier(schema),
                            quote_identifier(&d_idx.name)
                        ),
                        String::new(),
                    );
                    plan.emit(
                        render_create_index_concurrently(schema, &desired.name, d_idx),
                        format!(
                            "DROP INDEX CONCURRENTLY IF EXISTS {}.{}",
                            quote_identifier(schema),
                            quote_identifier(&d_idx.name)
                        ),
                    );
                }
            }
        }
    }

    // Indexes in observed but not desired → DROP (sorted).
    let des_idx_by_name = index_desired_by_name(&desired.indexes);
    for name in obs_idx_map.keys() {
        if des_idx_by_name.contains_key(*name) {
            continue;
        }
        if name.ends_with("_pkey") {
            continue;
        }
        plan.emit_destructive(
            format!(
                "DROP INDEX CONCURRENTLY IF EXISTS {}.{}",
                quote_identifier(schema),
                quote_identifier(name)
            ),
            String::new(),
        );
    }

    // FK constraint diff.
    let mut obs_fks: BTreeMap<&str, &DriftObjectDdl> = BTreeMap::new();
    for c in obs_constraints {
        if c.r#type == "FOREIGN KEY" {
            obs_fks.insert(c.name.as_str(), c);
        }
    }
    let des_fks: BTreeSet<&str> = desired
        .foreign_keys
        .iter()
        .map(|fk| fk.name.as_str())
        .collect();

    for fk in &desired.foreign_keys {
        if obs_fks.contains_key(fk.name.as_str()) {
            continue;
        }
        if !table_reachable(&fk.references_table, plan, schema, obs_table_names) {
            plan.warnings.push(format!(
                "foreign key {} on {}.{} skipped: target table \
                 {:?} is neither in observed nor being created in \
                 this diff. Either add the table to spec.tables \
                 or remove the FK declaration.",
                fk.name, schema, desired.name, fk.references_table
            ));
            continue;
        }
        let on_delete = if fk.on_delete.is_empty() {
            "NO ACTION"
        } else {
            &fk.on_delete
        };
        let add_inner = format!(
            "ALTER TABLE {qualified} ADD CONSTRAINT {} FOREIGN KEY ({}) REFERENCES {}.{} ({}) ON DELETE {} NOT VALID",
            quote_identifier(&fk.name),
            quote_list(&fk.columns),
            quote_identifier(schema),
            quote_identifier(&fk.references_table),
            quote_list(&fk.references_columns),
            on_delete
        );
        let add_sql = do_block_exists_guard(
            &quote_string(&fk.name),
            &quote_string(&qualified),
            &add_inner,
        );
        plan.emit(
            add_sql,
            format!(
                "ALTER TABLE {qualified} DROP CONSTRAINT IF EXISTS {}",
                quote_identifier(&fk.name)
            ),
        );
        plan.emit(
            format!(
                "ALTER TABLE {qualified} VALIDATE CONSTRAINT {}",
                quote_identifier(&fk.name)
            ),
            String::new(),
        );
    }

    // FKs in observed but not desired → DROP (sorted).
    for name in obs_fks.keys() {
        if des_fks.contains(*name) {
            continue;
        }
        plan.emit_destructive(
            format!(
                "ALTER TABLE {qualified} DROP CONSTRAINT IF EXISTS {}",
                quote_identifier(name)
            ),
            String::new(),
        );
    }

    // CHECK constraint diff (match by name+table only).
    let mut obs_chks: BTreeMap<&str, &DriftObjectDdl> = BTreeMap::new();
    for c in obs_constraints {
        if c.r#type == "CHECK" && c.table == desired.name {
            obs_chks.insert(c.name.as_str(), c);
        }
    }
    let des_chks: BTreeSet<&str> = desired
        .check_constraints
        .iter()
        .map(|cc| cc.name.as_str())
        .collect();

    for cc in &desired.check_constraints {
        if obs_chks.contains_key(cc.name.as_str()) {
            continue;
        }
        let add_inner = format!(
            "ALTER TABLE {qualified} ADD CONSTRAINT {} CHECK ({}) NOT VALID",
            quote_identifier(&cc.name),
            cc.definition
        );
        let add_sql = do_block_exists_guard(
            &quote_string(&cc.name),
            &quote_string(&qualified),
            &add_inner,
        );
        plan.emit(
            add_sql,
            format!(
                "ALTER TABLE {qualified} DROP CONSTRAINT IF EXISTS {}",
                quote_identifier(&cc.name)
            ),
        );
        plan.emit(
            format!(
                "ALTER TABLE {qualified} VALIDATE CONSTRAINT {}",
                quote_identifier(&cc.name)
            ),
            String::new(),
        );
    }

    // CHECKs in observed but not desired → DROP (sorted).
    for name in obs_chks.keys() {
        if des_chks.contains(*name) {
            continue;
        }
        plan.emit_destructive(
            format!(
                "ALTER TABLE {qualified} DROP CONSTRAINT IF EXISTS {}",
                quote_identifier(name)
            ),
            String::new(),
        );
    }

    // UNIQUE constraint diff.
    //
    // Emitted as ALTER TABLE ADD CONSTRAINT rather than folded into the CREATE
    // TABLE body, matching how CHECKs and FKs are handled: the CREATE
    // renderer's trailing-comma bookkeeping around the optional PRIMARY KEY
    // line has already produced invalid SQL once, and a second optional clause
    // there would widen that surface for no gain.
    //
    // Matched by name, like CHECKs. A change to the column list or to NULLS NOT
    // DISTINCT under the same name is not detected — rename the constraint to
    // express a shape change, which is the same idiom the CHECK path documents.
    let mut obs_uniq: BTreeSet<&str> = BTreeSet::new();
    for c in obs_constraints {
        if c.r#type == "UNIQUE" && c.table == desired.name {
            obs_uniq.insert(c.name.as_str());
        }
    }
    let des_uniq: BTreeSet<&str> = desired
        .unique_constraints
        .iter()
        .map(|uc| uc.name.as_str())
        .collect();

    for uc in &desired.unique_constraints {
        if obs_uniq.contains(uc.name.as_str()) {
            continue;
        }
        if uc.columns.is_empty() {
            plan.warnings.push(format!(
                "unique constraint {:?} on {} declares no columns; skipped",
                uc.name, desired.name
            ));
            continue;
        }
        let nulls = if uc.nulls_not_distinct {
            " NULLS NOT DISTINCT"
        } else {
            ""
        };
        let add_inner = format!(
            "ALTER TABLE {qualified} ADD CONSTRAINT {} UNIQUE{nulls} ({})",
            quote_identifier(&uc.name),
            quote_list(&uc.columns)
        );
        // pg_constraint existence guard, as for CHECKs: adding a constraint that
        // already exists raises 42710, and a re-applied migration must be a
        // no-op.
        //
        // Not split into ADD NOT VALID + VALIDATE the way CHECK and FK are:
        // PostgreSQL has no NOT VALID for UNIQUE — it must build the backing
        // index to prove uniqueness — so the two-phase form is simply not
        // available here.
        let add_sql = do_block_exists_guard(
            &quote_string(&uc.name),
            &quote_string(&qualified),
            &add_inner,
        );
        plan.emit(
            add_sql,
            format!(
                "ALTER TABLE {qualified} DROP CONSTRAINT IF EXISTS {}",
                quote_identifier(&uc.name)
            ),
        );
    }

    // UNIQUEs in observed but not desired → DROP CONSTRAINT (destructive: it
    // drops the backing index and the uniqueness guarantee with it).
    for name in &obs_uniq {
        if des_uniq.contains(name) {
            continue;
        }
        plan.emit_destructive(
            format!(
                "ALTER TABLE {qualified} DROP CONSTRAINT IF EXISTS {}",
                quote_identifier(name)
            ),
            // The original column list is not reconstructed from the drop.
            String::new(),
        );
    }
}

// --- Topological sort for CREATE TABLE ---

fn topo_sort_tables(tables: &[DesiredTable]) -> (Vec<String>, bool) {
    let names: BTreeSet<&str> = tables.iter().map(|t| t.name.as_str()).collect();

    // child → set of parents.
    let mut deps: BTreeMap<&str, BTreeSet<&str>> = BTreeMap::new();
    for t in tables {
        let entry = deps.entry(t.name.as_str()).or_default();
        for fk in &t.foreign_keys {
            if names.contains(fk.references_table.as_str()) && fk.references_table != t.name {
                entry.insert(fk.references_table.as_str());
            }
        }
    }

    let mut in_degree: BTreeMap<&str, usize> = BTreeMap::new();
    for t in tables {
        in_degree.insert(t.name.as_str(), 0);
    }
    for (child, parents) in &deps {
        *in_degree.get_mut(child).unwrap() += parents.len();
    }

    let mut queue: Vec<&str> = in_degree
        .iter()
        .filter(|&(_, &deg)| deg == 0)
        .map(|(&n, _)| n)
        .collect();
    queue.sort_unstable();

    let mut result: Vec<String> = Vec::new();
    while !queue.is_empty() {
        let node = queue.remove(0);
        result.push(node.to_string());
        for (child, parents) in &deps {
            if parents.contains(node) {
                let d = in_degree.get_mut(child).unwrap();
                *d -= 1;
                if *d == 0 {
                    queue.push(child);
                    queue.sort_unstable();
                }
            }
        }
    }

    let mut has_cycle = false;
    if result.len() < tables.len() {
        let in_result: BTreeSet<&str> = result.iter().map(|s| s.as_str()).collect();
        let mut remaining: Vec<&str> = tables
            .iter()
            .map(|t| t.name.as_str())
            .filter(|n| !in_result.contains(n))
            .collect();
        remaining.sort_unstable();
        result.extend(remaining.into_iter().map(|s| s.to_string()));
        has_cycle = true;
    }

    (result, has_cycle)
}

// --- RLS diffing ---

/// Converges the two row-level-security bits: `relrowsecurity` (ENABLE) and
/// `relforcerowsecurity` (FORCE).
///
/// Both statements are idempotent in PostgreSQL, so this used to emit them
/// for every RLS table unconditionally. That is correct but not honest: a
/// schema already in its desired state produced two statements per RLS table,
/// and a plan that is never empty is a plan nobody reads. Now that the
/// snapshot carries the FORCE bit, both can be compared, and an unchanged
/// schema plans to nothing.
///
/// Unknown counts as "needs the statement": a table absent from `observed` is
/// being created by this same plan, and a `None` `rls_forced` comes from a
/// snapshot written before the field existed.
///
/// Note the deliberate asymmetry: nothing here ever emits `DISABLE ROW LEVEL
/// SECURITY`. Clearing `enableRLS` skips the table rather than turning RLS
/// off on a live one. Un-forcing is reachable — a declaration saying
/// `forceRLS: false` against a database that ignores it is exactly the drift
/// this path exists to close — but it goes through
/// [`Plan::emit_destructive`], so `allow_destructive = false` refuses it
/// outright. Dropping the owner's exemption from every policy on a
/// multi-tenant table is a cross-tenant exposure, not a schema tweak.
fn diff_rls(plan: &mut Plan, schema: &str, observed: &Snapshot, desired: &SchemaDefinitionSpec) {
    let obs = observed_tables(observed);

    for t in &desired.tables {
        if !t.enable_rls {
            continue;
        }
        let qualified = format!("{}.{}", quote_identifier(schema), quote_identifier(&t.name));

        let cur = obs.get(&t.name);

        if !cur.is_some_and(|c| c.rls_enabled) {
            plan.emit(
                format!("ALTER TABLE {qualified} ENABLE ROW LEVEL SECURITY"),
                format!("ALTER TABLE {qualified} DISABLE ROW LEVEL SECURITY"),
            );
        }

        // Unset means forced — what this emitted unconditionally before
        // `forceRLS` existed, so existing SchemaDefinitions are unaffected.
        let want_forced = t.force_rls.unwrap_or(true);
        let cur_forced = cur.and_then(|c| c.rls_forced);

        match (want_forced, cur_forced) {
            (true, Some(true)) | (false, Some(false)) => {}
            (true, _) => plan.emit(
                format!("ALTER TABLE {qualified} FORCE ROW LEVEL SECURITY"),
                format!("ALTER TABLE {qualified} NO FORCE ROW LEVEL SECURITY"),
            ),
            (false, _) => plan.emit_destructive(
                format!("ALTER TABLE {qualified} NO FORCE ROW LEVEL SECURITY"),
                format!("ALTER TABLE {qualified} FORCE ROW LEVEL SECURITY"),
            ),
        }
    }
}

// --- Materialized view diffing ---

fn diff_materialized_views(
    plan: &mut Plan,
    schema: &str,
    observed: &Snapshot,
    desired: &SchemaDefinitionSpec,
) {
    let mut obs_mvs: BTreeSet<&str> = BTreeSet::new();
    for mv in &observed.materialized_views {
        obs_mvs.insert(mv.name.as_str());
    }

    for mv in &desired.materialized_views {
        let qualified = format!(
            "{}.{}",
            quote_identifier(schema),
            quote_identifier(&mv.name)
        );
        let with_data = if mv.with_data {
            "WITH DATA"
        } else {
            "WITH NO DATA"
        };
        if !obs_mvs.contains(mv.name.as_str()) {
            plan.emit(
                format!(
                    "CREATE MATERIALIZED VIEW IF NOT EXISTS {qualified} AS {} {with_data}",
                    mv.query
                ),
                format!("DROP MATERIALIZED VIEW IF EXISTS {qualified}"),
            );
        }
        for idx in &mv.indexes {
            plan.emit(
                render_create_index_concurrently(schema, &mv.name, idx),
                format!(
                    "DROP INDEX CONCURRENTLY IF EXISTS {}.{}",
                    quote_identifier(schema),
                    quote_identifier(&idx.name)
                ),
            );
        }
    }
}

// --- Trigger diffing ---

fn trigger_matches(observed: &drift::TriggerShape, desired: &DesiredTrigger) -> bool {
    if observed.name != desired.name || observed.table != desired.table {
        return false;
    }
    if !observed.timing.eq_ignore_ascii_case(&desired.timing) {
        return false;
    }
    if observed.for_each_row != desired.for_each_row {
        return false;
    }
    if observed.function != desired.function {
        return false;
    }
    if !string_set_equal_ci(&observed.events, &desired.events) {
        return false;
    }
    normalise_ddl(&observed.when) == normalise_ddl(&desired.when)
}

fn diff_triggers(
    plan: &mut Plan,
    schema: &str,
    observed: &Snapshot,
    desired: &SchemaDefinitionSpec,
) {
    let mut obs_triggers: HashMap<String, &drift::TriggerShape> = HashMap::new();
    for t in &observed.triggers {
        obs_triggers.insert(format!("{}\x00{}", t.table, t.name), t);
    }

    let mut known_functions: BTreeSet<&str> = BTreeSet::new();
    for of in &observed.functions {
        known_functions.insert(of.name.as_str());
    }
    for df in &desired.functions {
        if df.language.trim().eq_ignore_ascii_case("c") {
            continue;
        }
        known_functions.insert(df.name.as_str());
    }

    for tr in &desired.triggers {
        if let Some(obs) = obs_triggers.get(&format!("{}\x00{}", tr.table, tr.name)) {
            if trigger_matches(obs, tr) {
                continue;
            }
        }
        if !tr.function.is_empty() && !known_functions.contains(tr.function.as_str()) {
            plan.warnings.push(format!(
                "trigger {} on {} skipped: function {:?} is not in observed nor in \
                 desired.functions. Add a DesiredFunction for {:?} to the \
                 SchemaDefinition spec, or remove the trigger.",
                tr.name, tr.table, tr.function, tr.function
            ));
            continue;
        }

        let qualified = format!(
            "{}.{}",
            quote_identifier(schema),
            quote_identifier(&tr.table)
        );
        let events = tr.events.join(" OR ");
        let for_each = if tr.for_each_row {
            "FOR EACH ROW"
        } else {
            "FOR EACH STATEMENT"
        };
        let when_clause = if tr.when.is_empty() {
            String::new()
        } else {
            format!(" WHEN ({})", tr.when)
        };

        plan.emit(
            format!(
                "DROP TRIGGER IF EXISTS {} ON {qualified}",
                quote_identifier(&tr.name)
            ),
            String::new(),
        );
        plan.emit(
            format!(
                "CREATE TRIGGER {} {} {events} ON {qualified} {for_each}{when_clause} EXECUTE FUNCTION {}.{}()",
                quote_identifier(&tr.name),
                tr.timing,
                quote_identifier(schema),
                quote_identifier(&tr.function)
            ),
            format!("DROP TRIGGER IF EXISTS {} ON {qualified}", quote_identifier(&tr.name)),
        );
    }
}

// --- RLS policy diffing ---

fn policy_matches(observed: &drift::PolicyShape, desired: &DesiredPolicy) -> bool {
    if observed.name != desired.name || observed.table != desired.table {
        return false;
    }
    let desired_cmd = if desired.command.is_empty() {
        "ALL"
    } else {
        &desired.command
    };
    if !observed.command.eq_ignore_ascii_case(desired_cmd) {
        return false;
    }
    if observed.permissive != desired.permissive {
        return false;
    }
    if !roles_equal(&observed.roles, &desired.roles) {
        return false;
    }
    if normalise_ddl(&observed.using) != normalise_ddl(&desired.using) {
        return false;
    }
    normalise_ddl(&observed.with_check) == normalise_ddl(&desired.with_check)
}

fn diff_policies(
    plan: &mut Plan,
    schema: &str,
    observed: &Snapshot,
    desired: &SchemaDefinitionSpec,
) {
    let mut obs_policies: HashMap<String, &drift::PolicyShape> = HashMap::new();
    for p in &observed.policies {
        obs_policies.insert(format!("{}\x00{}", p.table, p.name), p);
    }

    for p in &desired.policies {
        if let Some(obs) = obs_policies.get(&format!("{}\x00{}", p.table, p.name)) {
            if policy_matches(obs, p) {
                continue;
            }
        }
        let qualified = format!(
            "{}.{}",
            quote_identifier(schema),
            quote_identifier(&p.table)
        );
        let cmd = if p.command.is_empty() {
            "ALL"
        } else {
            &p.command
        };
        let policy_type = if p.permissive {
            "PERMISSIVE"
        } else {
            "RESTRICTIVE"
        };
        let roles = if p.roles.is_empty() {
            "PUBLIC".to_string()
        } else {
            p.roles.join(", ")
        };
        let mut clauses: Vec<String> = Vec::new();
        if !p.using.is_empty() {
            clauses.push(format!("USING ({})", p.using));
        }
        if !p.with_check.is_empty() {
            clauses.push(format!("WITH CHECK ({})", p.with_check));
        }

        plan.emit(
            format!(
                "DROP POLICY IF EXISTS {} ON {qualified}",
                quote_identifier(&p.name)
            ),
            String::new(),
        );
        plan.emit(
            format!(
                "CREATE POLICY {} ON {qualified} AS {policy_type} FOR {cmd} TO {roles} {}",
                quote_identifier(&p.name),
                clauses.join(" ")
            ),
            format!(
                "DROP POLICY IF EXISTS {} ON {qualified}",
                quote_identifier(&p.name)
            ),
        );
    }
}

// --- comparison helpers ---

fn string_set_equal_ci(a: &[String], b: &[String]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut seen: HashMap<String, i64> = HashMap::new();
    for s in a {
        *seen.entry(s.to_lowercase()).or_default() += 1;
    }
    for s in b {
        *seen.entry(s.to_lowercase()).or_default() -= 1;
    }
    seen.values().all(|&n| n == 0)
}

fn roles_equal(a: &[String], b: &[String]) -> bool {
    fn canon(roles: &[String]) -> Vec<String> {
        if roles.is_empty() {
            return vec!["public".to_string()];
        }
        roles.iter().map(|r| r.to_lowercase()).collect()
    }
    string_set_equal_ci(&canon(a), &canon(b))
}

fn is_primary_key_column(col_name: &str, t: &DesiredTable) -> bool {
    if t.primary_key.iter().any(|pk| pk == col_name) {
        return true;
    }
    t.columns
        .iter()
        .any(|c| c.name == col_name && c.primary_key)
}

fn table_reachable(
    name: &str,
    plan: &Plan,
    schema: &str,
    obs_table_names: &BTreeSet<String>,
) -> bool {
    if obs_table_names.contains(name) {
        return true;
    }
    let prefix = format!(
        "CREATE TABLE {}.{} (",
        quote_identifier(schema),
        quote_identifier(name)
    );
    plan.statements.iter().any(|stmt| stmt.starts_with(&prefix))
}

// --- rendering ---

fn render_create_table(schema: &str, t: &DesiredTable) -> String {
    // Multiple-PRIMARY-KEY guard: if ≥2 columns carry `primary_key: true`
    // inline, OR the table-level primary-key list is being rendered, the inline
    // `PRIMARY KEY` on each column would produce "multiple primary keys for
    // table" (PG error 42P16). User intent in that case is a composite PK —
    // suppress all inline `PRIMARY KEY` and let the table-level constraint
    // (`PRIMARY KEY (col1, col2)`) be authoritative.
    //
    // Verified live on prod 2026-05-18:
    //   CREATE TABLE iam_oauth_client_trusted_external_issuers (
    //     "client_id" uuid NOT NULL PRIMARY KEY,    -- ← inline #1
    //     "issuer_id" uuid NOT NULL PRIMARY KEY,    -- ← inline #2 → ERROR
    //     ...
    //   )
    // → SQLSTATE 42P16 "multiple primary keys for table".
    //
    // The PK line is decided once, up front, and everything else reads off it.
    // Previously three conditions (a `needs_pk_line` helper, `inline_pk_count
    // > 1`, and `suppress_inline_pk`) each re-derived "is there a table-level
    // PK clause?"
    // from the inputs, and they disagreed: with two inline PKs and no
    // table-level list, the trailing comma was omitted and the emitted SQL was
    // a syntax error. Naming the constraint would have added a fourth.
    let pk_line = render_pk_line(t);

    // A trailing comma is required after the last column exactly when a
    // table-level clause follows it, and the inline `PRIMARY KEY` shorthand
    // must be suppressed in the same case — emitting both yields 42P16.
    let suppress_inline_pk = !pk_line.is_empty();

    let mut b = format!(
        "CREATE TABLE {}.{} (\n",
        quote_identifier(schema),
        quote_identifier(&t.name)
    );
    for (i, c) in t.columns.iter().enumerate() {
        b.push_str(&format!(
            "    {}",
            render_column_def_ex(c, suppress_inline_pk)
        ));
        if i < t.columns.len() - 1 || !pk_line.is_empty() {
            b.push(',');
        }
        b.push('\n');
    }
    b.push_str(&pk_line);
    b.push(')');
    b
}

/// Returns the table-level PRIMARY KEY clause for `t`, including its trailing
/// newline, or `""` when the primary key is carried by the inline column
/// shorthand or the table has none.
///
/// The table-level form is required whenever the shorthand cannot express the
/// intent:
///
///   - the PK spans several columns — two inline marks are 42P16, not a
///     composite key, so the inline marks are synthesised into one clause
///     rather than silently dropping the PK;
///   - the PK column carries no inline mark, so there is nothing to hang the
///     shorthand on;
///   - the constraint is named, and the shorthand has nowhere to put a name.
fn render_pk_line(t: &DesiredTable) -> String {
    let mut cols: Vec<String> = t.primary_key.clone();
    if cols.is_empty() {
        cols = t
            .columns
            .iter()
            .filter(|c| c.primary_key)
            .map(|c| c.name.clone())
            .collect();
    }
    if cols.is_empty() {
        return String::new();
    }
    // Single column already marked inline, unnamed: the shorthand is the
    // canonical spelling, so keep it.
    if t.primary_key_name.is_empty() && cols.len() == 1 && is_inline_pk(t, &cols[0]) {
        return String::new();
    }
    if !t.primary_key_name.is_empty() {
        return format!(
            "    CONSTRAINT {} PRIMARY KEY ({})\n",
            quote_identifier(&t.primary_key_name),
            quote_list(&cols)
        );
    }
    format!("    PRIMARY KEY ({})\n", quote_list(&cols))
}

/// Reports whether the named column carries `primary_key: true`.
fn is_inline_pk(t: &DesiredTable, name: &str) -> bool {
    t.columns.iter().any(|c| c.name == name && c.primary_key)
}

fn render_column_def(c: &DesiredColumn) -> String {
    render_column_def_ex(c, false)
}

fn render_column_def_ex(c: &DesiredColumn, suppress_inline_pk: bool) -> String {
    let mut b = format!("{} {}", quote_identifier(&c.name), c.r#type);
    // GENERATED … STORED goes immediately after the type, matching pg_dump. It
    // is mutually exclusive with DEFAULT: PostgreSQL rejects a column that
    // declares both, and the generation expression is the column's only source
    // of value.
    if !c.generated.is_empty() {
        b.push_str(&format!(" GENERATED ALWAYS AS ({}) STORED", c.generated));
    }
    if !c.nullable {
        b.push_str(" NOT NULL");
    }
    if !c.default.is_empty() && c.generated.is_empty() {
        b.push_str(&format!(" DEFAULT {}", c.default));
    }
    // Identity before PRIMARY KEY: PostgreSQL accepts either order, but this
    // matches the ordering pg_dump emits, which keeps hand-diffing sane.
    match c.identity.as_str() {
        "ALWAYS" => b.push_str(" GENERATED ALWAYS AS IDENTITY"),
        "BY DEFAULT" => b.push_str(" GENERATED BY DEFAULT AS IDENTITY"),
        _ => {}
    }
    if c.primary_key && !suppress_inline_pk {
        b.push_str(" PRIMARY KEY");
    }
    b
}

fn render_create_index(schema: &str, table: &str, idx: &DesiredIndex) -> String {
    render_index_ddl(schema, table, idx, false)
}

fn render_create_index_concurrently(schema: &str, table: &str, idx: &DesiredIndex) -> String {
    render_index_ddl(schema, table, idx, true)
}

fn render_index_ddl(schema: &str, table: &str, idx: &DesiredIndex, concurrent: bool) -> String {
    let mut b = String::from("CREATE ");
    if idx.unique {
        b.push_str("UNIQUE ");
    }
    if concurrent {
        b.push_str(&format!(
            "INDEX CONCURRENTLY IF NOT EXISTS {} ON {}.{}",
            quote_identifier(&idx.name),
            quote_identifier(schema),
            quote_identifier(table)
        ));
    } else {
        b.push_str(&format!(
            "INDEX {} ON {}.{}",
            quote_identifier(&idx.name),
            quote_identifier(schema),
            quote_identifier(table)
        ));
    }
    let method = if idx.method.is_empty() {
        "btree"
    } else {
        &idx.method
    };
    b.push_str(&format!(
        " USING {method} ({})",
        render_index_column_list(idx)
    ));
    if !idx.include.is_empty() {
        b.push_str(&format!(" INCLUDE ({})", quote_list(&idx.include)));
    }
    if idx.unique && idx.nulls_not_distinct {
        b.push_str(" NULLS NOT DISTINCT");
    }
    if !idx.where_.is_empty() {
        b.push_str(&format!(" WHERE {}", idx.where_));
    }
    b
}

fn render_index_column_list(idx: &DesiredIndex) -> String {
    if !idx.expression.is_empty() {
        format!("({})", idx.expression)
    } else if !idx.column_refs.is_empty() {
        idx.column_refs
            .iter()
            .map(render_index_column)
            .collect::<Vec<_>>()
            .join(", ")
    } else if !idx.columns.is_empty() {
        quote_list(&idx.columns)
    } else {
        String::new()
    }
}

fn render_index_column(c: &DesiredIndexColumn) -> String {
    let mut b = if !c.expression.is_empty() {
        format!("({})", c.expression)
    } else {
        quote_identifier(&c.name)
    };
    if !c.op_class.is_empty() {
        b.push_str(&format!(" {}", quote_identifier(&c.op_class)));
    }
    if c.direction.eq_ignore_ascii_case("desc") {
        b.push_str(" DESC");
    }
    match c.nulls.to_lowercase().as_str() {
        "first" => b.push_str(" NULLS FIRST"),
        "last" => b.push_str(" NULLS LAST"),
        _ => {}
    }
    b
}

fn quote_list(names: &[String]) -> String {
    names
        .iter()
        .map(|n| quote_identifier(n))
        .collect::<Vec<_>>()
        .join(", ")
}

// --- index/lookup helpers ---

fn index_desired_by_name(in_: &[DesiredIndex]) -> BTreeMap<&str, &DesiredIndex> {
    in_.iter().map(|i| (i.name.as_str(), i)).collect()
}

fn observed_tables(s: &Snapshot) -> BTreeMap<String, &drift::TableShape> {
    s.tables
        .iter()
        .filter(|t| t.kind == "BASE TABLE")
        .map(|t| (t.name.clone(), t))
        .collect()
}

fn desired_tables(s: &SchemaDefinitionSpec) -> HashMap<String, &DesiredTable> {
    s.tables.iter().map(|t| (t.name.clone(), t)).collect()
}

fn observed_indexes_by_table(s: &Snapshot) -> HashMap<String, Vec<&DriftObjectDdl>> {
    let mut m: HashMap<String, Vec<&DriftObjectDdl>> = HashMap::new();
    for idx in &s.indexes {
        m.entry(idx.table.clone()).or_default().push(idx);
    }
    m
}

fn observed_constraints_by_table(s: &Snapshot) -> HashMap<String, Vec<&DriftObjectDdl>> {
    let mut m: HashMap<String, Vec<&DriftObjectDdl>> = HashMap::new();
    for c in &s.constraints {
        m.entry(c.table.clone()).or_default().push(c);
    }
    m
}

fn index_observed_columns(in_: &[drift::ColumnShape]) -> HashMap<&str, &drift::ColumnShape> {
    in_.iter().map(|c| (c.name.as_str(), c)).collect()
}

fn index_desired_columns(in_: &[DesiredColumn]) -> HashMap<&str, &DesiredColumn> {
    in_.iter().map(|c| (c.name.as_str(), c)).collect()
}

fn sorted_observed_names(m: &BTreeMap<String, &drift::TableShape>) -> Vec<String> {
    m.keys().cloned().collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::drift::{ColumnShape, ExtShape, ObjectDdl, Snapshot, TableShape};

    fn col(name: &str, ord: i64, dt: &str, udt: &str, nullable: bool) -> ColumnShape {
        ColumnShape {
            name: name.into(),
            ordinal: ord,
            data_type: dt.into(),
            udt_name: udt.into(),
            nullable,
            default: String::new(),
            ..Default::default()
        }
    }

    /// Asserts a plan against the JSON golden generated from the Go `Diff`.
    fn assert_plan(plan: &Plan, json: &str) {
        let v: serde_json::Value = serde_json::from_str(json).expect("golden json");
        let arr = |k: &str| -> Vec<String> {
            v[k].as_array()
                .unwrap()
                .iter()
                .map(|x| x.as_str().unwrap().to_string())
                .collect()
        };
        assert_eq!(plan.statements, arr("stmts"), "statements");
        assert_eq!(plan.reverse_statements, arr("rev"), "reverse_statements");
        assert_eq!(plan.warnings, arr("warn"), "warnings");
        assert_eq!(
            plan.destructive_ops,
            v["destructive"].as_u64().unwrap() as usize
        );
    }

    fn dcol(name: &str, ty: &str, nullable: bool, pk: bool) -> DesiredColumn {
        DesiredColumn {
            name: name.into(),
            r#type: ty.into(),
            nullable,
            primary_key: pk,
            ..Default::default()
        }
    }

    // ---- RLS -----------------------------------------------------------
    //
    // Mirrors go/declarative/differ_rls_test.go case for case. The two
    // differs are expected to plan identical SQL, and RLS is the one place
    // where a silent divergence is a security difference rather than a
    // cosmetic one, so the pairs are kept in lockstep deliberately.

    /// An observed snapshot holding one table in a known RLS state. `forced`
    /// is three-valued: `None` is a snapshot written before the FORCE bit was
    /// recorded, not a table that is unforced.
    fn rls_seen(name: &str, enabled: bool, forced: Option<bool>) -> Snapshot {
        Snapshot {
            schema: "app".into(),
            tables: vec![TableShape {
                name: name.into(),
                kind: "BASE TABLE".into(),
                rls_enabled: enabled,
                rls_forced: forced,
                ..Default::default()
            }],
            ..Default::default()
        }
    }

    fn rls_want(name: &str, enable: bool, force: Option<bool>) -> DesiredTable {
        DesiredTable {
            name: name.into(),
            enable_rls: enable,
            force_rls: force,
            ..Default::default()
        }
    }

    fn rls_plan(observed: &Snapshot, table: DesiredTable) -> Plan {
        let mut plan = Plan::default();
        diff_rls(
            &mut plan,
            "app",
            observed,
            &SchemaDefinitionSpec {
                tables: vec![table],
                ..Default::default()
            },
        );
        plan
    }

    fn has(steps: &[String], needle: &str) -> bool {
        steps.iter().any(|s| s.contains(needle))
    }

    /// Both statements are idempotent, so emitting them unconditionally was
    /// never wrong — it was just noise, and a plan that is never empty is a
    /// plan nobody reads.
    #[test]
    fn rls_emits_nothing_when_already_converged() {
        let plan = rls_plan(
            &rls_seen("users", true, Some(true)),
            rls_want("users", true, Some(true)),
        );
        assert!(plan.statements.is_empty(), "{:?}", plan.statements);
    }

    /// Unset means forced, so an already-forced table converges against a
    /// declaration that never mentions the field.
    #[test]
    fn rls_emits_nothing_when_converged_and_force_unset() {
        let plan = rls_plan(
            &rls_seen("users", true, Some(true)),
            rls_want("users", true, None),
        );
        assert!(plan.statements.is_empty(), "{:?}", plan.statements);
    }

    /// The half that actually matters. ENABLE alone exempts the table owner
    /// from every policy, and applications routinely connect as the owning
    /// role, so an enabled-but-not-forced table is unprotected in practice.
    #[test]
    fn rls_emits_force_only_when_enabled_but_not_forced() {
        let plan = rls_plan(
            &rls_seen("users", true, Some(false)),
            rls_want("users", true, None),
        );
        assert!(
            !has(&plan.statements, "ENABLE ROW LEVEL SECURITY"),
            "{:?}",
            plan.statements
        );
        assert!(
            has(&plan.statements, "FORCE ROW LEVEL SECURITY"),
            "{:?}",
            plan.statements
        );
    }

    #[test]
    fn rls_emits_enable_when_observed_disabled() {
        let plan = rls_plan(
            &rls_seen("users", false, Some(true)),
            rls_want("users", true, None),
        );
        assert!(
            has(&plan.statements, "ENABLE ROW LEVEL SECURITY"),
            "{:?}",
            plan.statements
        );
    }

    /// A `None` FORCE bit comes from a snapshot taken before the field was
    /// recorded, which is not the same as observing an unforced table.
    /// Treating unknown as "already forced" would skip the statement on
    /// exactly the tables whose state nobody has ever checked.
    #[test]
    fn rls_unknown_force_bit_still_emits_force() {
        let plan = rls_plan(
            &rls_seen("users", true, None),
            rls_want("users", true, None),
        );
        assert!(
            has(&plan.statements, "FORCE ROW LEVEL SECURITY"),
            "{:?}",
            plan.statements
        );
    }

    /// A table this same plan is about to CREATE is absent from the snapshot.
    /// It still needs both statements, or it lands with no row-level security
    /// at all.
    #[test]
    fn rls_emits_both_for_table_absent_from_observed() {
        let plan = rls_plan(
            &rls_seen("orders", true, Some(true)),
            rls_want("users", true, None),
        );
        assert_eq!(
            plan.statements,
            vec![
                "ALTER TABLE \"app\".\"users\" ENABLE ROW LEVEL SECURITY".to_string(),
                "ALTER TABLE \"app\".\"users\" FORCE ROW LEVEL SECURITY".to_string(),
            ]
        );
    }

    /// Un-forcing destroys no data, so it is easy to mistake for an ordinary
    /// ALTER. It hands the application role a blanket exemption from every
    /// policy on the table, which on a multi-tenant schema is a cross-tenant
    /// read. It has to count as destructive so `allow_destructive = false`
    /// refuses it outright.
    #[test]
    fn rls_no_force_is_destructive() {
        let plan = rls_plan(
            &rls_seen("users", true, Some(true)),
            rls_want("users", true, Some(false)),
        );
        assert!(
            has(&plan.statements, "NO FORCE ROW LEVEL SECURITY"),
            "{:?}",
            plan.statements
        );
        assert_eq!(plan.destructive_ops, 1);
    }

    /// ...but only when it changes something. An already-unforced table
    /// matching a `forceRLS: false` declaration is converged, and must not
    /// trip the destructive gate on every reconcile.
    #[test]
    fn rls_no_force_skipped_when_already_unforced() {
        let plan = rls_plan(
            &rls_seen("users", true, Some(false)),
            rls_want("users", true, Some(false)),
        );
        assert!(plan.statements.is_empty(), "{:?}", plan.statements);
        assert_eq!(plan.destructive_ops, 0);
    }

    /// The rollback of NO FORCE is FORCE — inverted relative to the default
    /// branch, so it is worth pinning: a rollback that re-applied NO FORCE
    /// would turn an undo into a second way to lose owner-side enforcement.
    #[test]
    fn rls_no_force_reverses_to_force() {
        let plan = rls_plan(
            &rls_seen("users", true, Some(true)),
            rls_want("users", true, Some(false)),
        );
        assert_eq!(
            plan.reverse_statements,
            vec!["ALTER TABLE \"app\".\"users\" FORCE ROW LEVEL SECURITY".to_string()]
        );
    }

    /// Clearing `enableRLS` skips the table rather than turning RLS off on a
    /// live one. That asymmetry against the NO FORCE path is deliberate —
    /// deleting a line from a manifest should not be able to strip row-level
    /// security from a table that has it — so it is pinned rather than left
    /// to be "fixed" later.
    #[test]
    fn rls_never_disables_an_observed_enabled_table() {
        let plan = rls_plan(
            &rls_seen("users", true, Some(true)),
            rls_want("users", false, None),
        );
        assert!(plan.statements.is_empty(), "{:?}", plan.statements);
    }

    const GREENFIELD_JSON: &str = r#"{"stmts":["DO $$ BEGIN CREATE TYPE \"app\".\"status\" AS ENUM ('new', 'active'); EXCEPTION WHEN duplicate_object THEN NULL; END $$","CREATE SEQUENCE IF NOT EXISTS \"app\".\"s1\" AS bigint INCREMENT BY 1","CREATE TABLE \"app\".\"users\" (\n    \"id\" bigint NOT NULL PRIMARY KEY,\n    \"email\" text NOT NULL\n)","CREATE TABLE \"app\".\"orders\" (\n    \"id\" bigint NOT NULL PRIMARY KEY,\n    \"user_id\" bigint NOT NULL\n)","CREATE UNIQUE INDEX CONCURRENTLY IF NOT EXISTS \"idx_users_email\" ON \"app\".\"users\" USING btree (\"email\")","DO $$ BEGIN\n\t\t\t\tIF NOT EXISTS (\n\t\t\t\t\tSELECT 1 FROM pg_constraint\n\t\t\t\t\t WHERE conname = 'fk_orders_user'\n\t\t\t\t\t   AND conrelid = '\"app\".\"orders\"'::regclass\n\t\t\t\t) THEN\n\t\t\t\t\tALTER TABLE \"app\".\"orders\" ADD CONSTRAINT \"fk_orders_user\" FOREIGN KEY (\"user_id\") REFERENCES \"app\".\"users\" (\"id\") ON DELETE CASCADE NOT VALID;\n\t\t\t\tEND IF;\n\t\t\tEND $$","ALTER TABLE \"app\".\"orders\" VALIDATE CONSTRAINT \"fk_orders_user\"","DO $$ BEGIN\n\t\t\t\tIF NOT EXISTS (\n\t\t\t\t\tSELECT 1 FROM pg_constraint\n\t\t\t\t\t WHERE conname = 'chk_pos'\n\t\t\t\t\t   AND conrelid = '\"app\".\"orders\"'::regclass\n\t\t\t\t) THEN\n\t\t\t\t\tALTER TABLE \"app\".\"orders\" ADD CONSTRAINT \"chk_pos\" CHECK (id > 0) NOT VALID;\n\t\t\t\tEND IF;\n\t\t\tEND $$","ALTER TABLE \"app\".\"orders\" VALIDATE CONSTRAINT \"chk_pos\"","ALTER TABLE \"app\".\"users\" ENABLE ROW LEVEL SECURITY","ALTER TABLE \"app\".\"users\" FORCE ROW LEVEL SECURITY","CREATE OR REPLACE VIEW \"app\".\"v_emails\" AS SELECT email FROM users","CREATE OR REPLACE FUNCTION \"app\".\"bump\"() RETURNS trigger LANGUAGE plpgsql AS $fn$ BEGIN RETURN NEW; END $fn$","DROP TRIGGER IF EXISTS \"trg_bump\" ON \"app\".\"users\"","CREATE TRIGGER \"trg_bump\" BEFORE INSERT ON \"app\".\"users\" FOR EACH ROW EXECUTE FUNCTION \"app\".\"bump\"()"],"rev":["DROP TYPE IF EXISTS \"app\".\"status\"","DROP SEQUENCE IF EXISTS \"app\".\"s1\"","DROP TABLE IF EXISTS \"app\".\"users\"","DROP TABLE IF EXISTS \"app\".\"orders\"","DROP INDEX CONCURRENTLY IF EXISTS \"app\".\"idx_users_email\"","ALTER TABLE \"app\".\"orders\" DROP CONSTRAINT IF EXISTS \"fk_orders_user\"","","ALTER TABLE \"app\".\"orders\" DROP CONSTRAINT IF EXISTS \"chk_pos\"","","ALTER TABLE \"app\".\"users\" DISABLE ROW LEVEL SECURITY","ALTER TABLE \"app\".\"users\" NO FORCE ROW LEVEL SECURITY","DROP VIEW IF EXISTS \"app\".\"v_emails\"","DROP FUNCTION IF EXISTS \"app\".\"bump\"()","","DROP TRIGGER IF EXISTS \"trg_bump\" ON \"app\".\"users\""],"warn":[],"destructive":0,"err":""}"#;

    const ALTER_JSON: &str = r#"{"stmts":["ALTER TABLE \"app\".\"users\" ALTER COLUMN \"email\" SET DEFAULT 'x'::text","UPDATE \"app\".\"users\" SET \"email\" = 'x'::text WHERE \"email\" IS NULL","ALTER TABLE \"app\".\"users\" ALTER COLUMN \"email\" SET NOT NULL","ALTER TABLE \"app\".\"users\" ADD COLUMN IF NOT EXISTS \"note\" integer","ALTER TABLE \"app\".\"users\" DROP COLUMN IF EXISTS \"legacy\"","DROP INDEX CONCURRENTLY IF EXISTS \"app\".\"idx_old\""],"rev":["ALTER TABLE \"app\".\"users\" ALTER COLUMN \"email\" DROP DEFAULT","","ALTER TABLE \"app\".\"users\" ALTER COLUMN \"email\" DROP NOT NULL","ALTER TABLE \"app\".\"users\" DROP COLUMN IF EXISTS \"note\"","",""],"warn":[],"destructive":2,"err":""}"#;

    #[test]
    fn greenfield_full_matches_go() {
        let obs = Snapshot {
            schema: "app".into(),
            ..Default::default()
        };
        let des = SchemaDefinitionSpec {
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
        };
        let plan = diff(&obs, &des).expect("ok");
        assert_plan(&plan, GREENFIELD_JSON);
    }

    #[test]
    fn alter_and_drop_matches_go() {
        let obs = Snapshot {
            schema: "app".into(),
            tables: vec![TableShape {
                name: "users".into(),
                kind: "BASE TABLE".into(),
                columns: vec![
                    col("id", 1, "bigint", "int8", false),
                    col("email", 2, "text", "text", true),
                    col("legacy", 3, "text", "text", true),
                ],
                ..Default::default()
            }],
            indexes: vec![ObjectDdl {
                name: "idx_old".into(),
                table: "users".into(),
                r#type: "index".into(),
                definition: "CREATE INDEX idx_old ON app.users USING btree (legacy)".into(),
            }],
            ..Default::default()
        };
        let des = SchemaDefinitionSpec {
            allow_destructive: true,
            tables: vec![DesiredTable {
                name: "users".into(),
                columns: vec![
                    dcol("id", "bigint", false, true),
                    DesiredColumn {
                        name: "email".into(),
                        r#type: "text".into(),
                        nullable: false,
                        default: "'x'::text".into(),
                        ..Default::default()
                    },
                    dcol("note", "integer", true, false),
                ],
                ..Default::default()
            }],
            ..Default::default()
        };
        let plan = diff(&obs, &des).expect("ok");
        assert_plan(&plan, ALTER_JSON);
    }

    #[test]
    fn destructive_refused_matches_go() {
        let obs = Snapshot {
            schema: "app".into(),
            tables: vec![
                TableShape {
                    name: "t1".into(),
                    kind: "BASE TABLE".into(),
                    columns: vec![col("id", 1, "integer", "int4", false)],
                    ..Default::default()
                },
                TableShape {
                    name: "t2".into(),
                    kind: "BASE TABLE".into(),
                    columns: vec![col("id", 1, "integer", "int4", false)],
                    ..Default::default()
                },
            ],
            ..Default::default()
        };
        let des = SchemaDefinitionSpec {
            tables: vec![DesiredTable {
                name: "t2".into(),
                columns: vec![dcol("id", "integer", false, true)],
                ..Default::default()
            }],
            ..Default::default()
        };
        let err = diff(&obs, &des).unwrap_err();
        let DiffError::DestructiveRefused { count, plan } = &err;
        assert_eq!(*count, 1);
        assert_eq!(plan.statements, vec!["DROP TABLE IF EXISTS \"app\".\"t1\""]);
        assert_eq!(plan.destructive_ops, 1);
        assert_eq!(
            err.to_string(),
            "1 destructive operation(s) refused; set spec.allowDestructive=true to permit"
        );
    }

    // ---- constraint-backed indexes -------------------------------------
    //
    // PostgreSQL names a PRIMARY KEY / UNIQUE constraint's backing index after
    // the constraint, and schemaspec carries those as constraints — never as
    // indexes — so the desired set never contains them. Leaving them in the
    // observed set makes each look like an index the user deleted, and the
    // differ emits DROP INDEX for an index a live constraint depends on.
    // PostgreSQL refuses that ("cannot drop index … because constraint …
    // requires it"), so the whole migration fails, not just that statement.

    /// The backing index of a PK or UNIQUE constraint must never be dropped.
    #[test]
    fn constraint_backed_indexes_are_not_dropped() {
        let idx = |name: &str, cols: &str| ObjectDdl {
            name: name.into(),
            table: "users".into(),
            r#type: "btree".into(),
            definition: format!("CREATE UNIQUE INDEX {name} ON app.users USING btree ({cols})"),
        };
        let obs = Snapshot {
            schema: "app".into(),
            tables: vec![TableShape {
                name: "users".into(),
                kind: "BASE TABLE".into(),
                columns: vec![
                    col("id", 1, "uuid", "uuid", false),
                    col("email", 2, "text", "text", false),
                ],
                ..Default::default()
            }],
            indexes: vec![idx("users_pkey", "id"), idx("users_email_key", "email")],
            constraints: vec![
                ObjectDdl {
                    name: "users_pkey".into(),
                    table: "users".into(),
                    r#type: "PRIMARY KEY".into(),
                    definition: "PRIMARY KEY (id)".into(),
                },
                ObjectDdl {
                    name: "users_email_key".into(),
                    table: "users".into(),
                    r#type: "UNIQUE".into(),
                    definition: "UNIQUE (email)".into(),
                },
            ],
            ..Default::default()
        };
        let des = SchemaDefinitionSpec {
            tables: vec![DesiredTable {
                name: "users".into(),
                columns: vec![
                    dcol("id", "uuid", false, true),
                    dcol("email", "text", false, false),
                ],
                // Declared, so the diff is the true round-trip of `obs`: the
                // constraint is matched and only the index filter is under
                // test. Omitting it would make the UNIQUE look removed and the
                // resulting DROP CONSTRAINT would mask the assertion below.
                unique_constraints: vec![DesiredUniqueConstraint {
                    name: "users_email_key".into(),
                    columns: vec!["email".into()],
                    ..Default::default()
                }],
                ..Default::default()
            }],
            ..Default::default()
        };

        let plan = diff(&obs, &des).expect("diff");
        let dropped: Vec<&String> = plan
            .statements
            .iter()
            .filter(|s| s.contains("DROP INDEX"))
            .collect();
        assert!(dropped.is_empty(), "unexpected DROP INDEX: {dropped:?}");
        assert_eq!(plan.destructive_ops, 0);
    }

    /// Negative control: an index with no constraint of the same name is still
    /// dropped, so the filter can't mask a genuinely removed index.
    #[test]
    fn plain_index_absent_from_desired_is_still_dropped() {
        let obs = Snapshot {
            schema: "app".into(),
            tables: vec![TableShape {
                name: "users".into(),
                kind: "BASE TABLE".into(),
                columns: vec![col("id", 1, "uuid", "uuid", false)],
                ..Default::default()
            }],
            indexes: vec![ObjectDdl {
                name: "ix_users_id".into(),
                table: "users".into(),
                r#type: "btree".into(),
                definition: "CREATE INDEX ix_users_id ON app.users USING btree (id)".into(),
            }],
            ..Default::default()
        };
        let des = SchemaDefinitionSpec {
            tables: vec![DesiredTable {
                name: "users".into(),
                columns: vec![dcol("id", "uuid", false, true)],
                ..Default::default()
            }],
            ..Default::default()
        };

        // Dropping an index is destructive, so it surfaces through the refusal
        // path rather than a plain plan — which is itself the point: the
        // constraint-backed filter must not be what suppresses it.
        let DiffError::DestructiveRefused { count, plan } = diff(&obs, &des).unwrap_err();
        assert_eq!(count, 1);
        assert!(
            plan.statements
                .iter()
                .any(|s| s.contains("DROP INDEX") && s.contains("ix_users_id")),
            "expected DROP INDEX for ix_users_id, got {:?}",
            plan.statements
        );
    }

    // ---- identity / generated column rendering --------------------------
    //
    // Ports go/declarative/identity_typmod_test.go. Observed against a real
    // 50-table schema (2026-07-26): a diff from an empty baseline turned ten
    // GENERATED BY DEFAULT AS IDENTITY columns into plain NOT NULL columns.
    // The migration applied cleanly and every subsequent insert failed with
    // 23502 null value in column "id" — the worst place for it to surface,
    // since apply-time looked healthy.

    #[test]
    fn render_column_def_emits_identity() {
        for (identity, want) in [
            ("BY DEFAULT", "GENERATED BY DEFAULT AS IDENTITY"),
            ("ALWAYS", "GENERATED ALWAYS AS IDENTITY"),
        ] {
            let got = render_column_def(&DesiredColumn {
                name: "id".into(),
                r#type: "smallint".into(),
                identity: identity.into(),
                ..Default::default()
            });
            assert!(
                got.contains(want),
                "got {got:?}, want it to contain {want:?}"
            );
        }

        let plain = render_column_def(&DesiredColumn {
            name: "slug".into(),
            r#type: "text".into(),
            ..Default::default()
        });
        assert!(!plain.contains("IDENTITY"), "got {plain:?}");
    }

    /// Identity must precede PRIMARY KEY: PostgreSQL accepts either order, but
    /// matching pg_dump's ordering keeps hand-diffing a migration against a
    /// dump readable.
    #[test]
    fn render_column_def_orders_identity_before_primary_key() {
        let got = render_column_def(&DesiredColumn {
            name: "id".into(),
            r#type: "bigint".into(),
            identity: "BY DEFAULT".into(),
            primary_key: true,
            ..Default::default()
        });
        let id_idx = got.find("IDENTITY").expect("identity clause");
        let pk_idx = got.find("PRIMARY KEY").expect("primary key clause");
        assert!(id_idx < pk_idx, "got {got:?}");
    }

    /// A generated column carries its expression in `generation_expression`,
    /// never in `column_default`. A renderer that emits only the default
    /// produces a column that exists, accepts no writes, and reads as NULL
    /// forever.
    #[test]
    fn render_column_def_emits_generated_stored() {
        let got = render_column_def(&DesiredColumn {
            name: "name_en".into(),
            r#type: "text".into(),
            nullable: true,
            generated: "name ->> 'en'".into(),
            ..Default::default()
        });
        assert!(
            got.contains("GENERATED ALWAYS AS (name ->> 'en') STORED"),
            "got {got:?}"
        );
    }

    /// PostgreSQL rejects a column declaring both, and the expression is the
    /// column's only source of value.
    #[test]
    fn render_column_def_suppresses_default_on_generated_column() {
        let got = render_column_def(&DesiredColumn {
            name: "computed".into(),
            r#type: "integer".into(),
            nullable: true,
            default: "0".into(),
            generated: "1 + 1".into(),
            ..Default::default()
        });
        assert!(!got.contains("DEFAULT"), "got {got:?}");
    }

    /// The generated clause belongs immediately after the type, as pg_dump
    /// writes it.
    #[test]
    fn render_column_def_orders_generated_before_not_null() {
        let got = render_column_def(&DesiredColumn {
            name: "total".into(),
            r#type: "integer".into(),
            nullable: false,
            generated: "a + b".into(),
            ..Default::default()
        });
        let gen_idx = got.find("GENERATED").expect("generated clause");
        let nn_idx = got.find("NOT NULL").expect("not null");
        assert!(gen_idx < nn_idx, "got {got:?}");
    }

    // --- D7: extensions ---

    #[test]
    fn missing_extension_is_created_before_tables() {
        let obs = Snapshot {
            schema: "app".into(),
            ..Default::default()
        };
        let des = SchemaDefinitionSpec {
            extensions: vec![
                DesiredExtension {
                    name: "pgcrypto".into(),
                    ..Default::default()
                },
                DesiredExtension {
                    name: "uuid-ossp".into(),
                    schema: "ext".into(),
                },
            ],
            tables: vec![DesiredTable {
                name: "t".into(),
                columns: vec![DesiredColumn {
                    name: "id".into(),
                    r#type: "uuid".into(),
                    default: "gen_random_uuid()".into(),
                    primary_key: true,
                    ..Default::default()
                }],
                ..Default::default()
            }],
            ..Default::default()
        };
        let plan = diff(&obs, &des).expect("diff");
        assert_eq!(
            plan.statements[0],
            r#"CREATE EXTENSION IF NOT EXISTS "pgcrypto""#
        );
        assert_eq!(
            plan.statements[1],
            r#"CREATE EXTENSION IF NOT EXISTS "uuid-ossp" SCHEMA "ext""#
        );
        // The default above calls gen_random_uuid(), which does not exist until
        // pgcrypto is installed — ordering here is the difference between a
        // migration that applies and one that fails 42883.
        let create_idx = plan
            .statements
            .iter()
            .position(|s| s.starts_with("CREATE TABLE"))
            .expect("CREATE TABLE");
        assert!(create_idx > 1, "extensions must precede tables");
    }

    #[test]
    fn installed_extension_is_not_recreated_and_extra_is_never_dropped() {
        let obs = Snapshot {
            schema: "app".into(),
            extensions: vec![
                ExtShape {
                    name: "pgcrypto".into(),
                    schema: "public".into(),
                    ..Default::default()
                },
                // Installed but undeclared. Extensions are database-scoped and
                // routinely shared, so this must NOT produce a DROP.
                ExtShape {
                    name: "hstore".into(),
                    schema: "public".into(),
                    ..Default::default()
                },
            ],
            ..Default::default()
        };
        let des = SchemaDefinitionSpec {
            extensions: vec![DesiredExtension {
                name: "pgcrypto".into(),
                ..Default::default()
            }],
            ..Default::default()
        };
        let plan = diff(&obs, &des).expect("diff");
        assert!(
            plan.statements.is_empty(),
            "no-op expected, got {:?}",
            plan.statements
        );
    }

    // --- D8: UNIQUE constraints ---

    #[test]
    fn unique_constraint_is_added_with_existence_guard() {
        let obs = Snapshot {
            schema: "app".into(),
            tables: vec![TableShape {
                name: "users".into(),
                kind: "BASE TABLE".into(),
                columns: vec![col("email", 1, "text", "text", false)],
                ..Default::default()
            }],
            ..Default::default()
        };
        let des = SchemaDefinitionSpec {
            tables: vec![DesiredTable {
                name: "users".into(),
                columns: vec![dcol("email", "text", false, false)],
                unique_constraints: vec![DesiredUniqueConstraint {
                    name: "users_email_key".into(),
                    columns: vec!["email".into()],
                    ..Default::default()
                }],
                ..Default::default()
            }],
            ..Default::default()
        };
        let plan = diff(&obs, &des).expect("diff");
        let add = plan
            .statements
            .iter()
            .find(|s| s.contains("ADD CONSTRAINT"))
            .expect("ADD CONSTRAINT");
        assert!(add.starts_with("DO $$"), "guarded: {add:?}");
        assert!(
            add.contains(
                r#"ALTER TABLE "app"."users" ADD CONSTRAINT "users_email_key" UNIQUE ("email")"#
            ),
            "got {add:?}"
        );
        // UNIQUE has no NOT VALID form — PostgreSQL must build the backing
        // index to prove uniqueness — so the two-phase spelling used for CHECK
        // and FK must not appear here.
        assert!(!add.contains("NOT VALID"), "got {add:?}");
        assert!(
            !plan
                .statements
                .iter()
                .any(|s| s.contains("VALIDATE CONSTRAINT")),
            "no VALIDATE pass for UNIQUE"
        );
    }

    #[test]
    fn unique_constraint_nulls_not_distinct_is_carried() {
        let plan = unique_plan(DesiredUniqueConstraint {
            name: "u".into(),
            columns: vec!["a".into(), "b".into()],
            nulls_not_distinct: true,
        });
        assert!(
            plan.statements[0]
                .contains(r#"ADD CONSTRAINT "u" UNIQUE NULLS NOT DISTINCT ("a", "b")"#),
            "got {:?}",
            plan.statements[0]
        );
    }

    #[test]
    fn unique_constraint_without_columns_warns_instead_of_emitting() {
        let plan = unique_plan(DesiredUniqueConstraint {
            name: "u".into(),
            columns: Vec::new(),
            ..Default::default()
        });
        assert!(plan.statements.is_empty(), "got {:?}", plan.statements);
        assert_eq!(plan.warnings.len(), 1, "got {:?}", plan.warnings);
        assert!(plan.warnings[0].contains("declares no columns"));
    }

    /// Diffs a single-column table that already exists against a desired shape
    /// carrying exactly `uc`, so only the UNIQUE path can contribute.
    fn unique_plan(uc: DesiredUniqueConstraint) -> Plan {
        let obs = Snapshot {
            schema: "app".into(),
            tables: vec![TableShape {
                name: "t".into(),
                kind: "BASE TABLE".into(),
                columns: vec![
                    col("a", 1, "text", "text", true),
                    col("b", 2, "text", "text", true),
                ],
                ..Default::default()
            }],
            ..Default::default()
        };
        let des = SchemaDefinitionSpec {
            tables: vec![DesiredTable {
                name: "t".into(),
                columns: vec![
                    dcol("a", "text", true, false),
                    dcol("b", "text", true, false),
                ],
                unique_constraints: vec![uc],
                ..Default::default()
            }],
            ..Default::default()
        };
        diff(&obs, &des).expect("diff")
    }

    #[test]
    fn unique_constraint_absent_from_desired_is_dropped_destructively() {
        let obs = Snapshot {
            schema: "app".into(),
            tables: vec![TableShape {
                name: "t".into(),
                kind: "BASE TABLE".into(),
                columns: vec![col("a", 1, "text", "text", true)],
                ..Default::default()
            }],
            constraints: vec![ObjectDdl {
                name: "t_a_key".into(),
                table: "t".into(),
                r#type: "UNIQUE".into(),
                definition: "UNIQUE (a)".into(),
            }],
            ..Default::default()
        };
        let des = SchemaDefinitionSpec {
            tables: vec![DesiredTable {
                name: "t".into(),
                columns: vec![dcol("a", "text", true, false)],
                ..Default::default()
            }],
            ..Default::default()
        };
        // Dropping a UNIQUE takes the uniqueness guarantee with it, so the
        // refusal is the behaviour under test, not an obstacle to it.
        let err = diff(&obs, &des).expect_err("destructive");
        let DiffError::DestructiveRefused { count, plan } = err;
        assert_eq!(count, 1);
        assert_eq!(
            plan.statements,
            vec![r#"ALTER TABLE "app"."t" DROP CONSTRAINT IF EXISTS "t_a_key""#]
        );
    }

    // --- D9: named / composite primary keys ---

    #[test]
    fn named_primary_key_renders_as_table_level_constraint() {
        let t = DesiredTable {
            name: "Todos".into(),
            columns: vec![
                dcol("Id", "uuid", false, true),
                dcol("Title", "text", false, false),
            ],
            primary_key_name: "PK_Todos".into(),
            ..Default::default()
        };
        // The inline shorthand has nowhere to carry a name, so marking the
        // column PK is not enough — an ORM-generated schema must round-trip
        // under its own constraint name.
        assert_eq!(
            render_create_table("app", &t),
            "CREATE TABLE \"app\".\"Todos\" (\n    \"Id\" uuid NOT NULL,\n    \"Title\" text NOT NULL,\n    CONSTRAINT \"PK_Todos\" PRIMARY KEY (\"Id\")\n)"
        );
    }

    #[test]
    fn two_inline_primary_keys_render_one_composite_clause() {
        let t = DesiredTable {
            name: "j".into(),
            columns: vec![
                dcol("client_id", "uuid", false, true),
                dcol("issuer_id", "uuid", false, true),
            ],
            ..Default::default()
        };
        // Two inline marks are 42P16 ("multiple primary keys for table"), not a
        // composite key. Before the pk_line rewrite the trailing comma was also
        // omitted here, so the emitted SQL was a syntax error on top of that.
        assert_eq!(
            render_create_table("app", &t),
            "CREATE TABLE \"app\".\"j\" (\n    \"client_id\" uuid NOT NULL,\n    \"issuer_id\" uuid NOT NULL,\n    PRIMARY KEY (\"client_id\", \"issuer_id\")\n)"
        );
    }

    #[test]
    fn single_unnamed_inline_primary_key_keeps_the_shorthand() {
        let t = DesiredTable {
            name: "t".into(),
            columns: vec![
                dcol("id", "uuid", false, true),
                dcol("x", "text", true, false),
            ],
            ..Default::default()
        };
        assert_eq!(
            render_create_table("app", &t),
            "CREATE TABLE \"app\".\"t\" (\n    \"id\" uuid NOT NULL PRIMARY KEY,\n    \"x\" text\n)"
        );
    }

    #[test]
    fn table_level_primary_key_suppresses_inline_marks() {
        let t = DesiredTable {
            name: "t".into(),
            columns: vec![
                dcol("a", "uuid", false, true),
                dcol("b", "uuid", false, false),
            ],
            primary_key: vec!["a".into(), "b".into()],
            ..Default::default()
        };
        let got = render_create_table("app", &t);
        assert_eq!(got.matches("PRIMARY KEY").count(), 1, "got {got:?}");
        assert!(
            got.ends_with("    PRIMARY KEY (\"a\", \"b\")\n)"),
            "got {got:?}"
        );
    }
}
