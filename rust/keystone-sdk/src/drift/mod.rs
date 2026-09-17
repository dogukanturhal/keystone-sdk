// SPDX-License-Identifier: Apache-2.0

//! Schema-fingerprint inspector + baseline bookkeeping.
//!
//! Ported from the Go `drift` package. The strategy mirrors the reference:
//! instead of shelling out to `pg_dump`, query `information_schema` and
//! `pg_catalog` directly for the structural shape of a schema (tables,
//! columns, indexes, constraints, enums, sequences, functions, policies,
//! triggers, materialized views), canonicalise, and hash. Drift = hash
//! mismatch vs. a stored baseline.
//!
//! ## JSON / hash fidelity
//!
//! [`hash`] is SHA-256 over the snapshot's canonical JSON. To stay
//! byte-for-byte compatible with the Go `drift.Hash` (so a baseline written
//! by the operator can be compared by this crate), the serialisation
//! reproduces Go's `encoding/json` exactly:
//!
//! - field order = struct order; snake_case keys;
//! - `omitempty` fields are dropped when empty; the non-omitempty slices
//!   (`tables`/`indexes`/`constraints`/`columns`/`labels`/`events`)
//!   serialise as `null` when empty (Go marshals a nil slice as `null`);
//! - HTML escaping: `<`→`<`, `>`→`>`, `&`→`&`, plus
//!   `U+2028`/`U+2029`, and `\b`/`\f` as ``/`` — see
//!   [`GoFormatter`].

use std::io;

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest, Sha256};

pub mod baseline;
pub mod diff;
pub mod inspector;
pub mod snapshot_store;

pub use baseline::{
    ensure_baseline_table, read_baseline, write_baseline, Baseline, BaselineKind,
    BASELINE_KIND_STRUCTURE, SNAPSHOT_KIND,
};
pub use diff::{diff, severity, DriftFinding, DriftSeverity};
pub use inspector::Inspector;
pub use snapshot_store::{ensure_snapshot_column, read_snapshot, write_snapshot};

/// Canonicalised structural shape of a schema. JSON-serialised in
/// deterministic order so hashes are stable across runs.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Snapshot {
    pub schema: String,
    #[serde(
        serialize_with = "ser_nil_seq",
        deserialize_with = "de_nil_seq",
        default
    )]
    pub tables: Vec<TableShape>,
    #[serde(
        serialize_with = "ser_nil_seq",
        deserialize_with = "de_nil_seq",
        default
    )]
    pub indexes: Vec<ObjectDdl>,
    #[serde(
        serialize_with = "ser_nil_seq",
        deserialize_with = "de_nil_seq",
        default
    )]
    pub constraints: Vec<ObjectDdl>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub enums: Vec<EnumShape>,
    /// Declared between `enums` and `sequences` to match Go's `Snapshot` field
    /// order exactly — the canonical JSON that [`hash`] digests is emitted in
    /// declaration order, so moving this field would make the two SDKs hash the
    /// same database differently.
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub extensions: Vec<ExtShape>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub sequences: Vec<SeqShape>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub functions: Vec<FuncShape>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub policies: Vec<PolicyShape>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub triggers: Vec<TriggerShape>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub materialized_views: Vec<MatViewShape>,
}

impl Snapshot {
    /// Whether this snapshot was written before
    /// [`TableShape::rls_forced`] was modelled, and therefore cannot be
    /// compared on it.
    ///
    /// The inspector populates the field on every table it returns, so a
    /// single `None` dates the whole document.
    pub fn predates_rls_force(&self) -> bool {
        self.tables.iter().any(|t| t.rls_forced.is_none())
    }

    /// A copy with `rls_forced` cleared on every table, which serialises
    /// byte-identically to a snapshot written before the field existed.
    ///
    /// This lets a caller holding an old-model baseline answer the only
    /// question that matters during the upgrade: did anything OTHER than the
    /// snapshot model change? Hashing this projection against the stored
    /// baseline hash answers it exactly — no heuristics, no version counter.
    pub fn without_rls_force(&self) -> Snapshot {
        let mut out = self.clone();
        for t in &mut out.tables {
            t.rls_forced = None;
        }
        out
    }
}

/// A PostgreSQL extension installed into the inspected schema.
///
/// An extension is scoped to a database but installed into one schema, and only
/// those installed into the schema being inspected are recorded — a `Snapshot`
/// describes one schema, for extensions as for everything else it carries. An
/// extension a schema depends on but does not own (the usual `pgcrypto` in
/// `public`) is provisioned by `LogicalDatabase.spec.extensions`, which is the
/// layer that owns database-scoped objects.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExtShape {
    pub name: String,
    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub schema: String,
    /// Mirrors `pg_extension.extversion` — the installed version, which
    /// `ALTER EXTENSION ... UPDATE TO` changes in place without touching the
    /// name or the schema. Without it that upgrade is invisible to drift: the
    /// extension's functions can change behaviour under a schema that reports
    /// itself unchanged.
    ///
    /// Empty means "not recorded" — a snapshot written before this field
    /// existed. `pg_extension.extversion` is NOT NULL, so a snapshot the
    /// current inspector produced always carries it. Skipping the empty value
    /// keeps a cleared version serialising byte-identically to those older
    /// snapshots, which is what lets the Go side's `WithoutExtVersion`
    /// projection hash equal to a legacy baseline.
    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub version: String,
}

/// A PostgreSQL enum type and its labels (ordered by `enumsortorder`).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnumShape {
    pub name: String,
    #[serde(
        serialize_with = "ser_nil_seq",
        deserialize_with = "de_nil_seq",
        default
    )]
    pub labels: Vec<String>,
}

/// A PostgreSQL sequence's properties.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SeqShape {
    pub name: String,
    pub data_type: String,
    pub increment_by: i64,
    pub min_value: i64,
    pub max_value: i64,
    pub start_value: i64,
}

/// A PostgreSQL function/procedure.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct FuncShape {
    pub name: String,
    pub args: String,
    pub returns: String,
    pub language: String,
    pub definition: String,
}

/// One table's column list (or a view's definition).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TableShape {
    pub name: String,
    /// `BASE TABLE`, `VIEW`, `FOREIGN`, …
    pub kind: String,
    #[serde(
        serialize_with = "ser_nil_seq",
        deserialize_with = "de_nil_seq",
        default
    )]
    pub columns: Vec<ColumnShape>,
    /// Populated for `kind == "VIEW"`.
    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub view_definition: String,
    /// `pg_class.relrowsecurity`.
    #[serde(skip_serializing_if = "is_false", default)]
    pub rls_enabled: bool,
    /// `pg_class.relforcerowsecurity` — whether RLS also applies to the
    /// table's OWNER.
    ///
    /// Separate from [`rls_enabled`](Self::rls_enabled), and usually the bit
    /// that matters: PostgreSQL exempts a table's owner from its own
    /// policies, so ENABLE without FORCE leaves the policies in place while
    /// enforcing none of them against an application that connects as the
    /// owning role.
    ///
    /// Captured because the snapshot hash is a digest of this struct: an
    /// un-modelled bit makes `ALTER TABLE … NO FORCE ROW LEVEL SECURITY`
    /// produce an identical hash, and therefore no drift event at all.
    ///
    /// `None` means the snapshot predates the field, not "not forced".
    /// Snapshots are persisted, and the stored baseline is rewritten only
    /// when an operator accepts drift, so after this field ships every
    /// baseline in the fleet is an old-model document until someone
    /// re-accepts it. Decoding a missing key as `false` would read every
    /// already-forced table as "FORCE was just added" and report it on every
    /// reconcile, forever. The inspector always populates it, so `None`
    /// occurs only for documents written before it existed.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub rls_forced: Option<bool>,
}

/// A row-level security policy from `pg_policies`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyShape {
    pub name: String,
    pub table: String,
    /// `ALL`/`SELECT`/`INSERT`/`UPDATE`/`DELETE`.
    pub command: String,
    pub permissive: bool,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub roles: Vec<String>,
    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub using: String,
    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub with_check: String,
}

/// A trigger binding from `pg_trigger`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TriggerShape {
    pub name: String,
    pub table: String,
    /// `BEFORE`/`AFTER`/`INSTEAD OF`.
    pub timing: String,
    /// `INSERT`, `UPDATE`, `DELETE`, `TRUNCATE`.
    #[serde(
        serialize_with = "ser_nil_seq",
        deserialize_with = "de_nil_seq",
        default
    )]
    pub events: Vec<String>,
    pub for_each_row: bool,
    pub function: String,
    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub when: String,
}

/// A materialized view from `pg_matviews`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct MatViewShape {
    pub name: String,
    pub definition: String,
}

/// One column. `information_schema` reports both `data_type` ("text") and
/// `udt_name` ("text"); both are recorded for forward-compat.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ColumnShape {
    pub name: String,
    pub ordinal: i64,
    pub data_type: String,
    pub udt_name: String,
    pub nullable: bool,
    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub default: String,

    /// `format_type(atttypid, atttypmod)` — the type with its modifiers intact:
    /// `character varying(64)`, `numeric(20,2)`, `geography(Point,4326)`.
    ///
    /// `information_schema.data_type` reports the type family without
    /// modifiers, so a snapshot built from `data_type` alone silently widens
    /// `varchar(64)` to unbounded varchar and collapses `geography(Point,4326)`
    /// to bare geography. Round-tripping such a snapshot through the differ
    /// authors DDL that drops length limits and PostGIS type/SRID constraints
    /// without saying so.
    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub formatted_type: String,

    /// The STORED generation expression, or `""` for an ordinary column.
    ///
    /// A generated column carries its expression in
    /// `information_schema.generation_expression`, never in `column_default`,
    /// so a snapshot that reads only the default records the column as
    /// ordinary. The differ then authors `ADD COLUMN` without
    /// `GENERATED … STORED`: the column exists, is silently always NULL, and
    /// nothing recomputes it.
    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub generated: String,

    /// `pg_attribute.attidentity`: `""` (none), `"a"` (GENERATED ALWAYS), or
    /// `"d"` (GENERATED BY DEFAULT).
    ///
    /// Without this a snapshot cannot distinguish a generated key from a plain
    /// NOT NULL column, so the differ authors `CREATE TABLE` without the
    /// identity clause. That applies cleanly and then every insert fails with
    /// `23502 null value in column "id"` — the migration looks correct until
    /// the first write.
    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub identity: String,
}

/// Generic name+definition pair for indexes and constraints — read straight
/// from `pg_indexes` / `pg_constraint` where the definition is canonical.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObjectDdl {
    pub name: String,
    pub table: String,
    /// index: `btree`/`hash`/…; constraint: `PRIMARY KEY`/`CHECK`/…
    #[serde(rename = "type")]
    pub r#type: String,
    pub definition: String,
}

/// Returns a deterministic SHA-256 hex over the snapshot's canonical JSON,
/// byte-compatible with the Go `drift.Hash`.
pub fn hash(s: &Snapshot) -> Result<String, serde_json::Error> {
    let json = marshal_snapshot(s)?;
    let digest = Sha256::digest(&json);
    Ok(hex::encode(digest))
}

/// Serialises a snapshot to JSON bytes byte-compatible with Go's
/// `json.Marshal` (see module docs). Used by [`hash`] and
/// [`snapshot_store::write_snapshot`].
pub(crate) fn marshal_snapshot(s: &Snapshot) -> Result<Vec<u8>, serde_json::Error> {
    let mut buf = Vec::new();
    let mut ser = serde_json::Serializer::with_formatter(&mut buf, GoFormatter);
    s.serialize(&mut ser)?;
    Ok(buf)
}

/// Turns `information_schema.columns` (`data_type`, `udt_name`) into a
/// SchemaDefinition-compatible type string. ARRAY → `<elem>[]`,
/// USER-DEFINED → the udt name, otherwise `data_type` verbatim.
pub fn resolve_column_type(data_type: &str, udt_name: &str) -> String {
    match data_type {
        "ARRAY" => {
            if let Some(stripped) = udt_name.strip_prefix('_') {
                format!("{stripped}[]")
            } else {
                format!("{udt_name}[]")
            }
        }
        "USER-DEFINED" => udt_name.to_string(),
        _ => data_type.to_string(),
    }
}

/// The modifier-preserving column-type resolver — the Rust twin of Go's
/// `drift.ResolveColumnTypeShape`.
///
/// Prefers [`ColumnShape::formatted_type`], which already carries length,
/// precision and PostGIS typmod, and falls back to the
/// `data_type`/`udt_name` pair for snapshots taken before that field existed.
///
/// Both sides must agree: `keystonectl` uses this at SchemaDefinition-render
/// time to emit `text[]` / `tenant_type` instead of the raw
/// `information_schema` labels, and the differ uses it at diff-comparison time
/// to match observed against declared types. Without the shared resolver a
/// SchemaDefinition that declares `character(64)` reads back `character` and
/// fires a type-drift warning on every reconcile.
pub fn resolve_column_type_shape(c: &ColumnShape) -> String {
    if c.formatted_type.is_empty() {
        return resolve_column_type(&c.data_type, &c.udt_name);
    }
    strip_type_schema(&c.formatted_type, &c.udt_name)
}

/// Removes a schema qualifier from a `format_type` result when the unqualified
/// remainder is the type's own `udt_name`.
///
/// `format_type` qualifies any type not on the current `search_path`, so a
/// user-defined type reads back as `keystone_dev_2c3a8f55f325.record_kind`.
/// The differ normalises a `sql://` desired schema by applying it to a scratch
/// schema whose name is content-hashed, so the qualifier differs between the
/// two sides of every diff — every enum column would report type drift on every
/// run, and none of it would be real. Only the qualifier is dropped; modifiers
/// such as `(Point,4326)` are on the other side of the name and are preserved.
fn strip_type_schema(formatted: &str, udt_name: &str) -> String {
    if udt_name.is_empty() {
        return formatted.to_string();
    }

    // Consider only the part before any modifier list: `a.b(Point,4326)` must
    // be split on the dot in `a.b`, never on one inside the parentheses.
    let head = match formatted.find('(') {
        Some(i) => &formatted[..i],
        None => formatted,
    };

    let Some(dot) = head.rfind('.') else {
        return formatted.to_string();
    };

    let bare = head[dot + 1..].trim_matches('"');
    if bare != udt_name {
        // Qualified, but not by its own name — leave it alone rather than
        // guessing.
        return formatted.to_string();
    }

    format!("{bare}{}", &formatted[head.len()..])
}

/// Renders `pg_attribute.attidentity` as the SQL fragment that recreates it,
/// or `""` when the column is not an identity column.
pub fn identity_clause(identity: &str) -> &'static str {
    match identity {
        "a" => "GENERATED ALWAYS AS IDENTITY",
        "d" => "GENERATED BY DEFAULT AS IDENTITY",
        _ => "",
    }
}

/// Maps PG `pg_constraint.contype` byte codes to human-readable strings.
pub fn constraint_type_name(b: u8) -> &'static str {
    match b {
        b'p' => "PRIMARY KEY",
        b'u' => "UNIQUE",
        b'f' => "FOREIGN KEY",
        b'c' => "CHECK",
        b'x' => "EXCLUDE",
        b't' => "TRIGGER",
        _ => "OTHER",
    }
}

/// Pulls the `WHEN (...)` clause out of a `CREATE TRIGGER` DDL string from
/// `pg_get_triggerdef`, with the surrounding parentheses stripped. Empty
/// when the trigger has no `WHEN`.
pub fn extract_trigger_when(def: &str) -> String {
    const NEEDLE: &str = " WHEN (";
    let idx = match index_case_insensitive(def, NEEDLE) {
        Some(i) => i,
        None => return String::new(),
    };
    let rest = &def[idx + NEEDLE.len()..];
    // Walk forward counting parens until the matching close.
    let mut depth = 1i32;
    for (i, c) in rest.char_indices() {
        match c {
            '(' => depth += 1,
            ')' => {
                depth -= 1;
                if depth == 0 {
                    return rest[..i].to_string();
                }
            }
            _ => {}
        }
    }
    String::new()
}

/// Returns the first index of `sub` in `s` ignoring case, or `None`. `sub`
/// must already be upper-case (the comparison upper-cases `s`'s ASCII
/// lowercase letters). Byte-for-byte port of the Go helper.
pub fn index_case_insensitive(s: &str, sub: &str) -> Option<usize> {
    let sb = s.as_bytes();
    let ub = sub.as_bytes();
    if ub.is_empty() {
        return Some(0);
    }
    if ub.len() > sb.len() {
        return None;
    }
    for i in 0..=(sb.len() - ub.len()) {
        let mut m = true;
        for (j, &want) in ub.iter().enumerate() {
            let mut a = sb[i + j];
            if a.is_ascii_lowercase() {
                a -= b'a' - b'A';
            }
            if a != want {
                m = false;
                break;
            }
        }
        if m {
            return Some(i);
        }
    }
    None
}

/// Serialises an empty slice as JSON `null` (matching Go's nil-slice
/// behaviour) and a non-empty slice as an array.
fn ser_nil_seq<S, T>(v: &[T], s: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
    T: Serialize,
{
    if v.is_empty() {
        s.serialize_none()
    } else {
        s.collect_seq(v)
    }
}

/// Deserialises `null` (or a missing field) and an array both into a `Vec`.
fn de_nil_seq<'de, D, T>(d: D) -> Result<Vec<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    Ok(Option::<Vec<T>>::deserialize(d)?.unwrap_or_default())
}

#[allow(clippy::trivially_copy_pass_by_ref)] // serde skip_serializing_if signature
fn is_false(b: &bool) -> bool {
    !*b
}

/// A `serde_json` formatter that reproduces Go's `encoding/json` string
/// escaping so the snapshot hash matches `drift.Hash` byte-for-byte.
struct GoFormatter;

impl serde_json::ser::Formatter for GoFormatter {
    fn write_string_fragment<W>(&mut self, writer: &mut W, fragment: &str) -> io::Result<()>
    where
        W: ?Sized + io::Write,
    {
        // serde's default formatter does not escape these, but Go does.
        let mut last = 0;
        for (i, c) in fragment.char_indices() {
            let esc: Option<&str> = match c {
                '<' => Some("\\u003c"),
                '>' => Some("\\u003e"),
                '&' => Some("\\u0026"),
                '\u{2028}' => Some("\\u2028"),
                '\u{2029}' => Some("\\u2029"),
                _ => None,
            };
            if let Some(e) = esc {
                writer.write_all(&fragment.as_bytes()[last..i])?;
                writer.write_all(e.as_bytes())?;
                last = i + c.len_utf8();
            }
        }
        writer.write_all(&fragment.as_bytes()[last..])
    }

    fn write_char_escape<W>(
        &mut self,
        writer: &mut W,
        char_escape: serde_json::ser::CharEscape,
    ) -> io::Result<()>
    where
        W: ?Sized + io::Write,
    {
        use serde_json::ser::CharEscape;
        // Go emits  /  for backspace / form-feed rather than the
        // \b / \f short forms serde uses; everything else matches.
        match char_escape {
            CharEscape::Backspace => writer.write_all(b"\\u0008"),
            CharEscape::FormFeed => writer.write_all(b"\\u000c"),
            other => serde_json::ser::CompactFormatter.write_char_escape(writer, other),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Golden vectors captured from the Go `drift` package (json.Marshal +
    // drift.Hash). These lock the Rust port to byte-for-byte compatibility.

    fn full_snapshot() -> Snapshot {
        Snapshot {
            schema: "shop".into(),
            tables: vec![
                TableShape {
                    name: "orders".into(),
                    kind: "BASE TABLE".into(),
                    columns: vec![
                        ColumnShape {
                            name: "id".into(),
                            ordinal: 1,
                            data_type: "bigint".into(),
                            udt_name: "int8".into(),
                            nullable: false,
                            default: String::new(),
                            ..Default::default()
                        },
                        ColumnShape {
                            name: "tags".into(),
                            ordinal: 2,
                            data_type: "ARRAY".into(),
                            udt_name: "_text".into(),
                            nullable: true,
                            default: String::new(),
                            ..Default::default()
                        },
                    ],
                    view_definition: String::new(),
                    rls_enabled: true,
                    rls_forced: None,
                },
                TableShape {
                    name: "order_view".into(),
                    kind: "VIEW".into(),
                    columns: Vec::new(),
                    view_definition: "SELECT id FROM orders WHERE qty > 0 AND price < 100;".into(),
                    rls_enabled: false,
                    rls_forced: None,
                },
            ],
            indexes: vec![ObjectDdl {
                name: "orders_pkey".into(),
                table: "orders".into(),
                r#type: "index".into(),
                definition: "CREATE UNIQUE INDEX orders_pkey ON shop.orders USING btree (id)".into(),
            }],
            constraints: vec![
                ObjectDdl {
                    name: "orders_qty_chk".into(),
                    table: "orders".into(),
                    r#type: "CHECK".into(),
                    definition: "CHECK ((qty > 0) AND (qty < 1000) AND (a & b))".into(),
                },
                ObjectDdl {
                    name: "orders_pkey".into(),
                    table: "orders".into(),
                    r#type: "PRIMARY KEY".into(),
                    definition: "PRIMARY KEY (id)".into(),
                },
            ],
            enums: vec![EnumShape {
                name: "status".into(),
                labels: vec!["new".into(), "paid".into(), "shipped".into()],
            }],
            // Left empty to keep this fixture identical to the Go one the
            // golden hash below was captured from. Non-empty extensions are
            // pinned separately by `hash_extensions_field_order_matches_go`.
            extensions: Vec::new(),
            sequences: vec![SeqShape {
                name: "orders_id_seq".into(),
                data_type: "bigint".into(),
                increment_by: 1,
                min_value: 1,
                max_value: 9223372036854775807,
                start_value: 1,
            }],
            functions: vec![FuncShape {
                name: "f".into(),
                args: "a integer".into(),
                returns: "integer".into(),
                language: "sql".into(),
                definition: "CREATE OR REPLACE FUNCTION shop.f(a integer)\n RETURNS integer\n LANGUAGE sql\nAS $function$ SELECT a & 1 WHERE a < 10 $function$\n".into(),
            }],
            policies: vec![PolicyShape {
                name: "p_sel".into(),
                table: "orders".into(),
                command: "SELECT".into(),
                permissive: true,
                roles: vec!["app_role".into()],
                using: "(owner = current_user)".into(),
                with_check: String::new(),
            }],
            triggers: vec![TriggerShape {
                name: "trg".into(),
                table: "orders".into(),
                timing: "BEFORE".into(),
                events: vec!["INSERT".into(), "UPDATE".into()],
                for_each_row: true,
                function: "f".into(),
                when: "new.qty > 0".into(),
            }],
            materialized_views: vec![MatViewShape {
                name: "mv".into(),
                definition: "SELECT count(*) AS c FROM shop.orders WHERE qty > 0;".into(),
            }],
        }
    }

    #[test]
    fn hash_extensions_field_order_matches_go() {
        // Golden captured from Go: `json.Marshal` + `drift.Hash` over the same
        // snapshot. Go emits struct fields in declaration order, so this pins
        // `extensions` to its slot between `enums` and `sequences` — move the
        // Rust field and the two SDKs hash the same database differently, which
        // reads as drift on every reconcile.
        let s = Snapshot {
            schema: "app".into(),
            enums: vec![EnumShape {
                name: "status".into(),
                labels: vec!["new".into()],
            }],
            extensions: vec![
                ExtShape {
                    name: "pgcrypto".into(),
                    schema: "public".into(),
                    ..Default::default()
                },
                ExtShape {
                    name: "uuid-ossp".into(),
                    schema: "app".into(),
                    ..Default::default()
                },
            ],
            sequences: vec![SeqShape {
                name: "s".into(),
                data_type: "bigint".into(),
                increment_by: 1,
                min_value: 1,
                max_value: 9223372036854775807,
                start_value: 1,
            }],
            ..Default::default()
        };
        let json = String::from_utf8(marshal_snapshot(&s).unwrap()).unwrap();
        assert_eq!(
            json,
            r#"{"schema":"app","tables":null,"indexes":null,"constraints":null,"enums":[{"name":"status","labels":["new"]}],"extensions":[{"name":"pgcrypto","schema":"public"},{"name":"uuid-ossp","schema":"app"}],"sequences":[{"name":"s","data_type":"bigint","increment_by":1,"min_value":1,"max_value":9223372036854775807,"start_value":1}]}"#
        );
        assert_eq!(
            hash(&s).unwrap(),
            "22d71f07255d6c2bb29c38134ca01ca3dbbc525d028938624bc65747caf102cb"
        );
    }

    #[test]
    fn hash_ext_version_field_order_matches_go() {
        // Same golden discipline as above, one level down: `version` sits after
        // `name` and `schema` inside `ExtShape`, and the two SDKs must agree on
        // that or a database inspected by the Rust side hashes differently from
        // the same database inspected by the Go side.
        //
        // The snapshot is byte-for-byte the one above with versions filled in,
        // so the pair also demonstrates the field is additive: drop the two
        // `version` values and this reproduces the legacy golden exactly, which
        // is precisely what `WithoutExtVersion` relies on.
        let s = Snapshot {
            schema: "app".into(),
            enums: vec![EnumShape {
                name: "status".into(),
                labels: vec!["new".into()],
            }],
            extensions: vec![
                ExtShape {
                    name: "pgcrypto".into(),
                    schema: "public".into(),
                    version: "1.3".into(),
                },
                ExtShape {
                    name: "uuid-ossp".into(),
                    schema: "app".into(),
                    version: "1.1".into(),
                },
            ],
            sequences: vec![SeqShape {
                name: "s".into(),
                data_type: "bigint".into(),
                increment_by: 1,
                min_value: 1,
                max_value: 9223372036854775807,
                start_value: 1,
            }],
            ..Default::default()
        };
        let json = String::from_utf8(marshal_snapshot(&s).unwrap()).unwrap();
        assert_eq!(
            json,
            r#"{"schema":"app","tables":null,"indexes":null,"constraints":null,"enums":[{"name":"status","labels":["new"]}],"extensions":[{"name":"pgcrypto","schema":"public","version":"1.3"},{"name":"uuid-ossp","schema":"app","version":"1.1"}],"sequences":[{"name":"s","data_type":"bigint","increment_by":1,"min_value":1,"max_value":9223372036854775807,"start_value":1}]}"#
        );
        assert_eq!(
            hash(&s).unwrap(),
            "31aada1bc4eb0dc1e3f4feea65c47cea868024f9213427df69de21f4eaa4c044"
        );
    }

    #[test]
    fn hash_empty_matches_go() {
        let s = Snapshot {
            schema: "public".into(),
            ..Default::default()
        };
        let json = String::from_utf8(marshal_snapshot(&s).unwrap()).unwrap();
        assert_eq!(
            json,
            r#"{"schema":"public","tables":null,"indexes":null,"constraints":null}"#
        );
        assert_eq!(
            hash(&s).unwrap(),
            "3ed0871459361db4acc8533b85c4dacd6ce89d4ea15ce64869f2bc887da92654"
        );
    }

    #[test]
    fn hash_tables_only_matches_go() {
        let s = Snapshot {
            schema: "app".into(),
            tables: vec![TableShape {
                name: "users".into(),
                kind: "BASE TABLE".into(),
                columns: vec![
                    ColumnShape {
                        name: "id".into(),
                        ordinal: 1,
                        data_type: "integer".into(),
                        udt_name: "int4".into(),
                        nullable: false,
                        default: String::new(),
                        ..Default::default()
                    },
                    ColumnShape {
                        name: "email".into(),
                        ordinal: 2,
                        data_type: "text".into(),
                        udt_name: "text".into(),
                        nullable: true,
                        default: "''::text".into(),
                        ..Default::default()
                    },
                ],
                view_definition: String::new(),
                rls_enabled: false,
                rls_forced: None,
            }],
            ..Default::default()
        };
        let json = String::from_utf8(marshal_snapshot(&s).unwrap()).unwrap();
        assert_eq!(
            json,
            r#"{"schema":"app","tables":[{"name":"users","kind":"BASE TABLE","columns":[{"name":"id","ordinal":1,"data_type":"integer","udt_name":"int4","nullable":false},{"name":"email","ordinal":2,"data_type":"text","udt_name":"text","nullable":true,"default":"''::text"}]}],"indexes":null,"constraints":null}"#
        );
        assert_eq!(
            hash(&s).unwrap(),
            "0a69b08f54881fcd4fa934a57ff03a6b32502b01bd42b58c7c97e630d5fd291f"
        );
    }

    /// `rls_forced` is three-state on the wire — `true`, `false`, and absent
    /// — and the absent case is load-bearing: it is how a snapshot written
    /// before the field existed is recognised. Go encodes a `*bool` that way
    /// natively; Rust has to be made to agree, or a baseline written by the
    /// operator would hash differently here and every schema would read as
    /// drifted. Expected values produced by the Go `drift.Hash` over the
    /// equivalent struct.
    #[test]
    fn hash_rls_forced_tristate_matches_go() {
        let col = || {
            vec![ColumnShape {
                name: "tenant_id".into(),
                ordinal: 1,
                data_type: "uuid".into(),
                udt_name: "uuid".into(),
                nullable: false,
                default: String::new(),
                ..Default::default()
            }]
        };
        let tbl = |name: &str, forced: Option<bool>| TableShape {
            name: name.into(),
            kind: "BASE TABLE".into(),
            columns: col(),
            view_definition: String::new(),
            rls_enabled: true,
            rls_forced: forced,
        };
        let s = Snapshot {
            schema: "app".into(),
            tables: vec![
                tbl("forced", Some(true)),
                tbl("unforced", Some(false)),
                tbl("legacy", None),
            ],
            ..Default::default()
        };

        let json = String::from_utf8(marshal_snapshot(&s).unwrap()).unwrap();
        assert_eq!(
            json,
            r#"{"schema":"app","tables":[{"name":"forced","kind":"BASE TABLE","columns":[{"name":"tenant_id","ordinal":1,"data_type":"uuid","udt_name":"uuid","nullable":false}],"rls_enabled":true,"rls_forced":true},{"name":"unforced","kind":"BASE TABLE","columns":[{"name":"tenant_id","ordinal":1,"data_type":"uuid","udt_name":"uuid","nullable":false}],"rls_enabled":true,"rls_forced":false},{"name":"legacy","kind":"BASE TABLE","columns":[{"name":"tenant_id","ordinal":1,"data_type":"uuid","udt_name":"uuid","nullable":false}],"rls_enabled":true}],"indexes":null,"constraints":null}"#
        );
        assert_eq!(
            hash(&s).unwrap(),
            "de80df9085acf1112e896d9aec485b539774e53aedf8e958ed9a8fca75238449"
        );
    }

    /// The projection used by the upgrade path must hash exactly like a
    /// document written before the field existed — that equality is the whole
    /// mechanism for telling "only the model changed" from a real change.
    #[test]
    fn without_rls_force_hashes_like_legacy() {
        let mk = |forced: Option<bool>| Snapshot {
            schema: "app".into(),
            tables: vec![TableShape {
                name: "messages".into(),
                kind: "BASE TABLE".into(),
                columns: Vec::new(),
                view_definition: String::new(),
                rls_enabled: true,
                rls_forced: forced,
            }],
            ..Default::default()
        };
        let observed = mk(Some(true));
        assert_eq!(
            hash(&observed.without_rls_force()).unwrap(),
            hash(&mk(None)).unwrap()
        );
        // And the receiver is untouched — the caller hashes it straight after
        // to write the new baseline.
        assert_eq!(observed.tables[0].rls_forced, Some(true));
        assert!(mk(None).predates_rls_force());
        assert!(!observed.predates_rls_force());
    }

    #[test]
    fn hash_full_with_html_matches_go() {
        let s = full_snapshot();
        let json = String::from_utf8(marshal_snapshot(&s).unwrap()).unwrap();
        // Go HTML-escapes <, >, & — so NO raw special char survives in the
        // output, and the "\uXXXX" escape bodies appear instead. (Avoids
        // typing literal backslashes in the needles.)
        assert!(
            !json.contains('>') && !json.contains('<') && !json.contains('&'),
            "special chars must be escaped: {json}"
        );
        assert!(
            json.contains("u003e") && json.contains("u003c") && json.contains("u0026"),
            "expected the \\u003e/\\u003c/\\u0026 escape bodies: {json}"
        );
        // The hash is over the exact bytes, so matching the Go golden hash is
        // itself a complete byte-fidelity check.
        assert_eq!(
            hash(&s).unwrap(),
            "6c6e006fb006722d210b74f06158f485ef7120ac6b81f58d41879f528720256f"
        );
    }

    #[test]
    fn snapshot_json_round_trips() {
        let s = full_snapshot();
        let json = marshal_snapshot(&s).unwrap();
        let back: Snapshot = serde_json::from_slice(&json).unwrap();
        assert_eq!(back, s);
    }

    #[test]
    fn resolve_column_type_vectors() {
        assert_eq!(resolve_column_type("ARRAY", "_text"), "text[]");
        assert_eq!(resolve_column_type("ARRAY", "text"), "text[]");
        assert_eq!(
            resolve_column_type("USER-DEFINED", "tenant_type"),
            "tenant_type"
        );
        assert_eq!(
            resolve_column_type("character varying", "varchar"),
            "character varying"
        );
        assert_eq!(
            resolve_column_type("timestamp with time zone", "timestamptz"),
            "timestamp with time zone"
        );
    }

    #[test]
    fn extract_trigger_when_vectors() {
        assert_eq!(
            extract_trigger_when(
                "CREATE TRIGGER trg BEFORE INSERT ON t FOR EACH ROW WHEN (new.qty > 0) EXECUTE FUNCTION f()"
            ),
            "new.qty > 0"
        );
        assert_eq!(
            extract_trigger_when(
                "CREATE TRIGGER trg AFTER UPDATE ON t FOR EACH ROW EXECUTE FUNCTION f()"
            ),
            ""
        );
        assert_eq!(
            extract_trigger_when(
                "CREATE TRIGGER trg BEFORE INSERT ON t FOR EACH ROW WHEN ((new.a > 0) AND (new.b < (1 + 2))) EXECUTE FUNCTION f()"
            ),
            "(new.a > 0) AND (new.b < (1 + 2))"
        );
    }

    #[test]
    fn constraint_type_name_vectors() {
        assert_eq!(constraint_type_name(b'p'), "PRIMARY KEY");
        assert_eq!(constraint_type_name(b'u'), "UNIQUE");
        assert_eq!(constraint_type_name(b'f'), "FOREIGN KEY");
        assert_eq!(constraint_type_name(b'c'), "CHECK");
        assert_eq!(constraint_type_name(b'x'), "EXCLUDE");
        assert_eq!(constraint_type_name(b't'), "TRIGGER");
        assert_eq!(constraint_type_name(b'z'), "OTHER");
    }

    /// Ports go/declarative/identity_typmod_test.go's
    /// `TestResolveColumnTypeShapePreservesModifiers`. `format_type` carries
    /// length, numeric precision and PostGIS typmod; `data_type` drops all
    /// three, so a snapshot resolved from it authors DDL that silently widens
    /// every bounded type.
    #[test]
    fn resolve_column_type_shape_preserves_modifiers() {
        let shape = |dt: &str, udt: &str, ft: &str| ColumnShape {
            data_type: dt.into(),
            udt_name: udt.into(),
            formatted_type: ft.into(),
            ..Default::default()
        };
        let cases: &[(ColumnShape, &str)] = &[
            (
                shape("character varying", "varchar", "character varying(64)"),
                "character varying(64)",
            ),
            (
                shape("numeric", "numeric", "numeric(20,2)"),
                "numeric(20,2)",
            ),
            (
                shape("USER-DEFINED", "geography", "geography(Point,4326)"),
                "geography(Point,4326)",
            ),
        ];
        for (c, want) in cases {
            assert_eq!(&resolve_column_type_shape(c), want, "shape: {c:?}");
        }
    }

    /// Snapshots taken before `formatted_type` existed must still resolve, or an
    /// upgrade would read every stored snapshot as total drift.
    #[test]
    fn resolve_column_type_shape_falls_back_for_older_snapshots() {
        let shape = |dt: &str, udt: &str| ColumnShape {
            data_type: dt.into(),
            udt_name: udt.into(),
            ..Default::default()
        };
        let cases: &[(ColumnShape, &str)] = &[
            (shape("ARRAY", "_text"), "text[]"),
            (shape("USER-DEFINED", "record_kind"), "record_kind"),
            (
                shape("timestamp with time zone", "timestamptz"),
                "timestamp with time zone",
            ),
        ];
        for (c, want) in cases {
            assert_eq!(&resolve_column_type_shape(c), want, "shape: {c:?}");
        }
    }

    /// The scratch schema the differ normalises a `sql://` desired source into
    /// is content-hash named, so `format_type` qualifies user-defined types with
    /// a name that differs between the two sides of every diff. Left unstripped,
    /// every enum column reports type drift on every run and none of it is real.
    #[test]
    fn resolve_column_type_shape_strips_scratch_schema_qualifier() {
        let shape = |udt: &str, ft: &str| ColumnShape {
            data_type: "USER-DEFINED".into(),
            udt_name: udt.into(),
            formatted_type: ft.into(),
            ..Default::default()
        };
        let cases: &[(ColumnShape, &str)] = &[
            (
                shape("record_kind", "keystone_dev_2c3a8f55f325.record_kind"),
                "record_kind",
            ),
            // The modifiers live on the other side of the name and survive.
            (
                shape("geography", "gis.geography(Point,4326)"),
                "geography(Point,4326)",
            ),
            // Qualified, but not by its own name — left alone rather than guessed at.
            (
                shape("record_kind", "other.something_else"),
                "other.something_else",
            ),
        ];
        for (c, want) in cases {
            assert_eq!(&resolve_column_type_shape(c), want, "shape: {c:?}");
        }
    }

    #[test]
    fn identity_clause_vectors() {
        assert_eq!(identity_clause("a"), "GENERATED ALWAYS AS IDENTITY");
        assert_eq!(identity_clause("d"), "GENERATED BY DEFAULT AS IDENTITY");
        assert_eq!(identity_clause(""), "");
        assert_eq!(identity_clause("x"), "");
    }
}
