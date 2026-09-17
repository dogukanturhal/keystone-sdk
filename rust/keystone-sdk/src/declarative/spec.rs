// SPDX-License-Identifier: Apache-2.0

//! The declarative desired-state spec types.
//!
//! Ported from `~/projects/keystone/api/v1alpha1/types_schemadefinition.go`
//! (the operator CRD). These are the desired-side inputs to the differ. Go
//! zero-values (empty string/slice, `false`, `0`) drive much of the differ's
//! branching, so the Rust structs use plain `String`/`Vec`/`bool`/`i64` with
//! `Default` to reproduce that exactly. Callers are expected to supply a
//! fully-defaulted spec (as Kubernetes admission would — e.g. `nullable`
//! defaults to `true`, `method` to `"btree"`).
//!
//! `serde` is derived with the CRD's camelCase JSON keys + container-level
//! `default` (so a YAML spec that omits a field gets the Go zero-value, which
//! is what `sigs.k8s.io/yaml` does too — kubebuilder defaults are applied by
//! the API server, NOT by file unmarshalling). The reconciler-only fields
//! (`schemaRef`, `schemaSelector`, …) are not modelled — the differ ignores
//! them, and serde ignores unknown YAML keys.

use serde::{Deserialize, Serialize};

/// One column declaration.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct DesiredColumn {
    pub name: String,
    /// The PostgreSQL data type (CRD `ColumnType`, an alias for string).
    pub r#type: String,
    pub nullable: bool,
    pub default: String,
    pub primary_key: bool,
    /// `ALWAYS` or `BY DEFAULT` for a PostgreSQL identity column, `""`
    /// otherwise. Rendered as `GENERATED … AS IDENTITY`; without it the
    /// differ authors `CREATE TABLE` with a plain NOT NULL column that has no
    /// value source, and every insert fails `23502` on the first write.
    pub identity: String,
    /// The expression of a STORED generated column, `""` otherwise. Mutually
    /// exclusive with [`default`](Self::default) — PostgreSQL rejects a column
    /// that declares both, and the generation expression is the column's only
    /// source of value.
    pub generated: String,
}

/// One column entry in [`DesiredIndex::column_refs`].
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct DesiredIndexColumn {
    pub name: String,
    pub expression: String,
    /// `asc`/`desc` (empty = asc).
    pub direction: String,
    /// `first`/`last`.
    pub nulls: String,
    pub op_class: String,
}

/// One index declaration. Use exactly one of `columns` / `column_refs` /
/// `expression`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct DesiredIndex {
    pub name: String,
    pub columns: Vec<String>,
    pub column_refs: Vec<DesiredIndexColumn>,
    pub expression: String,
    pub include: Vec<String>,
    pub unique: bool,
    pub nulls_not_distinct: bool,
    /// Index method (`btree` default, `gin`, `gist`, `hash`, `brin`, `spgist`).
    pub method: String,
    /// Partial-index predicate (emitted verbatim after `WHERE`).
    #[serde(rename = "where")]
    pub where_: String,
}

/// One foreign key declaration.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct DesiredForeignKey {
    pub name: String,
    pub columns: Vec<String>,
    pub references_table: String,
    pub references_columns: Vec<String>,
    /// `CASCADE`/`SET NULL`/`SET DEFAULT`/`RESTRICT`/`NO ACTION`.
    pub on_delete: String,
}

/// One table-level CHECK constraint.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct DesiredCheckConstraint {
    pub name: String,
    pub definition: String,
}

/// One table-level UNIQUE constraint.
///
/// Carried as a constraint rather than folded into
/// [`DesiredTable::indexes`]: PostgreSQL only accepts a PRIMARY KEY or UNIQUE
/// *constraint* as a foreign-key target, so demoting one to a unique index
/// round-trips the schema into a shape where existing FKs referencing these
/// columns can no longer be created.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct DesiredUniqueConstraint {
    pub name: String,
    /// Ordered column list. Order is significant — it is the backing index's
    /// column order, and decides which prefix lookups that index can serve.
    pub columns: Vec<String>,
    /// Selects `UNIQUE NULLS NOT DISTINCT`, where two NULLs collide instead of
    /// being treated as distinct (PostgreSQL 15+). A semantic difference, not a
    /// tuning knob.
    pub nulls_not_distinct: bool,
}

/// One PostgreSQL extension the schema declares.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct DesiredExtension {
    pub name: String,
    /// Schema to install into. Empty means "wherever PostgreSQL puts it",
    /// which is the portable choice.
    pub schema: String,
}

/// One per-table GRANT statement (unused by the differ; kept for fidelity).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct DesiredTablePrivilege {
    pub to_role: String,
    pub privileges: Vec<String>,
    pub with_grant_option: bool,
}

/// One `ALTER DEFAULT PRIVILEGES` (unused by the differ; kept for fidelity).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct DesiredDefaultPrivilege {
    pub for_role: String,
    pub to_role: String,
    pub schema: String,
    pub object_type: String,
    pub privileges: Vec<String>,
    pub with_grant_option: bool,
}

/// One table's desired shape.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct DesiredTable {
    pub name: String,
    pub columns: Vec<DesiredColumn>,
    /// Composite primary-key column list.
    pub primary_key: Vec<String>,
    /// Name of the PRIMARY KEY constraint. Empty lets PostgreSQL pick
    /// `<table>_pkey`.
    ///
    /// Every ORM names the primary key explicitly — EF Core emits
    /// `PK_<Table>` — so an adopted schema must round-trip under its own name
    /// rather than silently acquiring PostgreSQL's default. The name is not
    /// merely cosmetic: `ON CONFLICT ON CONSTRAINT` and `ALTER TABLE DROP
    /// CONSTRAINT` both address it.
    ///
    /// Naming forces the table-level `CONSTRAINT <name> PRIMARY KEY (…)`
    /// spelling, since the inline column shorthand has nowhere to carry a name.
    pub primary_key_name: String,
    pub indexes: Vec<DesiredIndex>,
    pub foreign_keys: Vec<DesiredForeignKey>,
    #[serde(rename = "enableRLS")]
    pub enable_rls: bool,
    /// Whether RLS also applies to the table's owner
    /// (`ALTER TABLE … FORCE ROW LEVEL SECURITY`). Ignored unless
    /// [`enable_rls`](Self::enable_rls) is set.
    ///
    /// `None` means forced — matching the operator's `forceRLS` field, which
    /// defaults to true because ENABLE-without-FORCE exempts the owning role
    /// from the policies it is meant to be constrained by. `Some(false)` is
    /// an explicit opt-out and is honoured.
    #[serde(rename = "forceRLS", skip_serializing_if = "Option::is_none")]
    pub force_rls: Option<bool>,
    pub privileges: Vec<DesiredTablePrivilege>,
    pub check_constraints: Vec<DesiredCheckConstraint>,
    pub unique_constraints: Vec<DesiredUniqueConstraint>,
}

/// A PostgreSQL enum type.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct DesiredEnum {
    pub name: String,
    pub values: Vec<String>,
}

/// A PostgreSQL sequence.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct DesiredSequence {
    pub name: String,
    pub data_type: String,
    pub increment_by: i64,
    pub min_value: i64,
    pub max_value: i64,
    pub start_with: i64,
    pub owned_by: String,
}

/// A PostgreSQL view.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct DesiredView {
    pub name: String,
    pub query: String,
    pub replace: bool,
}

/// A PostgreSQL function or procedure.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct DesiredFunction {
    pub name: String,
    pub args: String,
    pub returns: String,
    pub language: String,
    pub body: String,
    pub replace: bool,
}

/// A PostgreSQL materialized view.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct DesiredMaterializedView {
    pub name: String,
    pub query: String,
    pub indexes: Vec<DesiredIndex>,
    pub with_data: bool,
}

/// A PostgreSQL row-level security policy.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct DesiredPolicy {
    pub name: String,
    pub table: String,
    /// `ALL`/`SELECT`/`INSERT`/`UPDATE`/`DELETE`.
    pub command: String,
    pub permissive: bool,
    pub roles: Vec<String>,
    pub using: String,
    pub with_check: String,
}

/// A PostgreSQL trigger binding.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct DesiredTrigger {
    pub name: String,
    pub table: String,
    /// `BEFORE`/`AFTER`/`INSTEAD OF`.
    pub timing: String,
    pub events: Vec<String>,
    pub for_each_row: bool,
    pub function: String,
    pub when: String,
}

/// The declarative desired-state for one schema. Only the fields the differ
/// consumes are modelled; reconciler-only fields (schemaRef, policyRef,
/// cleanup, …) are omitted (serde ignores those YAML keys).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct SchemaDefinitionSpec {
    pub tables: Vec<DesiredTable>,
    pub enums: Vec<DesiredEnum>,
    pub extensions: Vec<DesiredExtension>,
    pub sequences: Vec<DesiredSequence>,
    pub views: Vec<DesiredView>,
    pub functions: Vec<DesiredFunction>,
    pub materialized_views: Vec<DesiredMaterializedView>,
    pub policies: Vec<DesiredPolicy>,
    pub triggers: Vec<DesiredTrigger>,
    pub allow_destructive: bool,
    pub default_privileges: Vec<DesiredDefaultPrivilege>,
}
