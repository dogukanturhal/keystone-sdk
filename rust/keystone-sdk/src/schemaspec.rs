// SPDX-License-Identifier: Apache-2.0

//! Converts a [`crate::drift::Snapshot`] into a
//! [`crate::declarative::spec::SchemaDefinitionSpec`] — the inverse of the
//! differ.
//!
//! Ported from the Go `schemaspec` package. Pure: all parsing operates on
//! the catalog-derived DDL strings already captured in the Snapshot
//! (`pg_get_constraintdef`, `pg_get_indexdef`, `pg_get_functiondef`). The Go
//! `Options{SchemaRef, SelectorLabels}` is omitted — those reconciler-only
//! fields aren't modelled by the Rust spec (the differ ignores them).
//!
//! Diffing the result against an empty schema reproduces the inspected
//! schema as CREATE DDL — the basis for an adoption baseline.

use crate::declarative::spec::*;
use crate::drift::{resolve_column_type_shape, ObjectDdl, Snapshot};

/// Renders `pg_attribute.attidentity` as the `DesiredColumn.identity` keyword
/// the SchemaDefinition CRD carries (`ALWAYS` / `BY DEFAULT`), or `""` for an
/// ordinary column. Note this is the *spec* spelling; the SQL fragment the
/// differ emits is [`crate::drift::identity_clause`].
fn identity_keyword(attidentity: &str) -> &'static str {
    match attidentity {
        "a" => "ALWAYS",
        "d" => "BY DEFAULT",
        _ => "",
    }
}

/// Projects a [`Snapshot`] into a [`SchemaDefinitionSpec`]. Indexes that exist
/// only to back a PRIMARY KEY or UNIQUE constraint are dropped (implied by the
/// constraint).
pub fn from_snapshot(snap: &Snapshot) -> SchemaDefinitionSpec {
    let mut spec = SchemaDefinitionSpec::default();

    for x in &snap.extensions {
        let mut ext = DesiredExtension {
            name: x.name.clone(),
            ..Default::default()
        };
        // Only pin the schema when the extension deliberately lives somewhere
        // other than the schema being inspected. A `sql://` desired source is
        // normalised by applying it to a content-hash-named scratch schema, so
        // an extension created by that source reports the scratch name —
        // pinning it would write a throwaway identifier into the migration.
        if !x.schema.is_empty() && x.schema != snap.schema {
            ext.schema = x.schema.clone();
        }
        spec.extensions.push(ext);
    }

    // Index constraints by table for PK/FK/UNIQUE/CHECK extraction.
    let mut pk_by_table: std::collections::HashMap<&str, Vec<String>> = Default::default();
    // table → PK constraint name.
    let mut pk_name_by_table: std::collections::HashMap<&str, &str> = Default::default();
    // table → names of indexes that exist only to back a PRIMARY KEY or UNIQUE
    // constraint. Such an index is not an independent object (it cannot be
    // dropped on its own), so re-emitting it would duplicate the constraint it
    // belongs to.
    let mut constraint_index_names: std::collections::HashMap<
        &str,
        std::collections::HashSet<&str>,
    > = Default::default();
    let mut fk_by_table: std::collections::HashMap<&str, Vec<FkRecord>> = Default::default();
    let mut ck_by_table: std::collections::HashMap<&str, Vec<DesiredCheckConstraint>> =
        Default::default();
    let mut uq_by_table: std::collections::HashMap<&str, Vec<DesiredUniqueConstraint>> =
        Default::default();
    for c in &snap.constraints {
        match c.r#type.as_str() {
            "PRIMARY KEY" => {
                pk_by_table.insert(c.table.as_str(), parse_constraint_cols(&c.definition));
                // Recorded verbatim rather than only when it differs from
                // PostgreSQL's `<table>_pkey` default: reproducing that default
                // would mean re-deriving it, and PostgreSQL truncates it at 63
                // bytes, so an "is this the default?" test is a guess where the
                // catalog already holds the answer.
                pk_name_by_table.insert(c.table.as_str(), c.name.as_str());
                constraint_index_names
                    .entry(c.table.as_str())
                    .or_default()
                    .insert(c.name.as_str());
            }
            "UNIQUE" => {
                // Carried as a constraint, not folded into `indexes`:
                // PostgreSQL only accepts a PRIMARY KEY or UNIQUE constraint as
                // a foreign-key target, so demoting one to a unique index
                // round-trips the schema into a shape where existing FKs
                // referencing those columns can no longer be created.
                let cols = parse_constraint_cols(&c.definition);
                if cols.is_empty() {
                    continue;
                }
                uq_by_table
                    .entry(c.table.as_str())
                    .or_default()
                    .push(DesiredUniqueConstraint {
                        name: c.name.clone(),
                        columns: cols,
                        nulls_not_distinct: has_nulls_not_distinct(&c.definition),
                    });
                constraint_index_names
                    .entry(c.table.as_str())
                    .or_default()
                    .insert(c.name.as_str());
            }
            "FOREIGN KEY" => {
                let fk = parse_fk_constraint(&c.name, &c.definition);
                if !fk.name.is_empty() {
                    fk_by_table.entry(c.table.as_str()).or_default().push(fk);
                }
            }
            "CHECK" => {
                // Without this the desired spec carries no CHECK constraints at
                // all, so the differ sees every existing one as removed and
                // authors a bare DROP CONSTRAINT with no matching ADD —
                // silently deleting data-integrity rules — while never creating
                // the ones a desired schema declares.
                let expr = parse_check_expression(&c.definition);
                if !expr.is_empty() {
                    ck_by_table
                        .entry(c.table.as_str())
                        .or_default()
                        .push(DesiredCheckConstraint {
                            name: c.name.clone(),
                            definition: expr,
                        });
                }
            }
            _ => {}
        }
    }

    // Index indexes by table.
    let mut idx_by_table: std::collections::HashMap<&str, Vec<&ObjectDdl>> = Default::default();
    for idx in &snap.indexes {
        idx_by_table
            .entry(idx.table.as_str())
            .or_default()
            .push(idx);
    }

    // Tables (BASE TABLE only).
    for t in &snap.tables {
        if t.kind == "VIEW" {
            continue;
        }
        let mut dt = DesiredTable {
            name: t.name.clone(),
            check_constraints: ck_by_table
                .get(t.name.as_str())
                .cloned()
                .unwrap_or_default(),
            unique_constraints: uq_by_table
                .get(t.name.as_str())
                .cloned()
                .unwrap_or_default(),
            primary_key_name: pk_name_by_table
                .get(t.name.as_str())
                .map(|s| s.to_string())
                .unwrap_or_default(),
            ..Default::default()
        };
        let empty: Vec<String> = Vec::new();
        let pk = pk_by_table.get(t.name.as_str()).unwrap_or(&empty);
        let pk_set: std::collections::HashSet<&str> = pk.iter().map(|s| s.as_str()).collect();

        for c in &t.columns {
            let mut dc = DesiredColumn {
                name: c.name.clone(),
                r#type: resolve_column_type_shape(c),
                identity: identity_keyword(&c.identity).to_string(),
                generated: c.generated.clone(),
                nullable: c.nullable,
                default: c.default.clone(),
                ..Default::default()
            };
            if pk_set.contains(c.name.as_str()) && pk.len() == 1 {
                dc.primary_key = true;
            }
            dt.columns.push(dc);
        }

        if pk.len() > 1 {
            dt.primary_key = pk.clone();
        }

        // Indexes, minus those PostgreSQL creates to back a PRIMARY KEY or
        // UNIQUE constraint. Such an index is not an independent object — it
        // cannot be dropped separately, and re-emitting it produces a CREATE
        // UNIQUE INDEX alongside (or instead of) the constraint it belongs to.
        //
        // Matched by name, which is exact: PostgreSQL always names a
        // constraint's backing index after the constraint, including when
        // ADD CONSTRAINT … USING INDEX renames an existing one. The previous
        // `_pkey` suffix test was a guess at PostgreSQL's default constraint
        // name, so it missed every explicitly-named PK — which is what ORMs
        // generate (EF Core emits `PK_Todos`) — and would have wrongly dropped
        // a hand-written index called `*_pkey`.
        let backing = constraint_index_names.get(t.name.as_str());
        if let Some(idxs) = idx_by_table.get(t.name.as_str()) {
            for idx in idxs {
                if backing.is_some_and(|s| s.contains(idx.name.as_str())) {
                    continue;
                }
                let di = parse_index_ddl(idx);
                if !di.name.is_empty() {
                    dt.indexes.push(di);
                }
            }
        }

        if let Some(fks) = fk_by_table.get(t.name.as_str()) {
            for fk in fks {
                dt.foreign_keys.push(DesiredForeignKey {
                    name: fk.name.clone(),
                    columns: fk.columns.clone(),
                    references_table: fk.ref_table.clone(),
                    references_columns: fk.ref_columns.clone(),
                    on_delete: fk.on_delete.clone(),
                });
            }
        }

        spec.tables.push(dt);
    }

    // Enums.
    for e in &snap.enums {
        spec.enums.push(DesiredEnum {
            name: e.name.clone(),
            values: e.labels.clone(),
        });
    }

    // Sequences.
    for s in &snap.sequences {
        spec.sequences.push(DesiredSequence {
            name: s.name.clone(),
            data_type: s.data_type.clone(),
            increment_by: s.increment_by,
            min_value: s.min_value,
            max_value: s.max_value,
            start_with: s.start_value,
            ..Default::default()
        });
    }

    // Views.
    for t in &snap.tables {
        if t.kind != "VIEW" {
            continue;
        }
        spec.views.push(DesiredView {
            name: t.name.clone(),
            query: t.view_definition.trim().to_string(),
            replace: true,
        });
    }

    // Functions.
    for f in &snap.functions {
        spec.functions.push(DesiredFunction {
            name: f.name.clone(),
            args: f.args.clone(),
            returns: f.returns.clone(),
            language: f.language.clone(),
            body: extract_function_body(&f.definition),
            replace: true,
        });
    }

    // RLS flag per table.
    let rls: std::collections::HashSet<&str> = snap
        .tables
        .iter()
        .filter(|t| t.rls_enabled)
        .map(|t| t.name.as_str())
        .collect();
    for dt in &mut spec.tables {
        if rls.contains(dt.name.as_str()) {
            dt.enable_rls = true;
        }
    }

    // Policies.
    for p in &snap.policies {
        spec.policies.push(DesiredPolicy {
            name: p.name.clone(),
            table: p.table.clone(),
            command: p.command.clone(),
            permissive: p.permissive,
            roles: p.roles.clone(),
            using: p.using.clone(),
            with_check: p.with_check.clone(),
        });
    }

    // Triggers.
    for tr in &snap.triggers {
        spec.triggers.push(DesiredTrigger {
            name: tr.name.clone(),
            table: tr.table.clone(),
            timing: tr.timing.clone(),
            events: tr.events.clone(),
            for_each_row: tr.for_each_row,
            function: tr.function.clone(),
            when: tr.when.clone(),
        });
    }

    // Materialized views.
    for mv in &snap.materialized_views {
        spec.materialized_views.push(DesiredMaterializedView {
            name: mv.name.clone(),
            query: mv.definition.trim().to_string(),
            with_data: true,
            ..Default::default()
        });
    }

    spec
}

/// A parsed FK constraint.
#[derive(Debug, Default)]
struct FkRecord {
    name: String,
    columns: Vec<String>,
    ref_table: String,
    ref_columns: Vec<String>,
    on_delete: String,
}

fn parse_constraint_cols(def: &str) -> Vec<String> {
    let open = def.find('(');
    // Last `)`, not the first: a UNIQUE constraint over an expression, or one
    // whose column list is followed by `DEFERRABLE`, closes an inner paren
    // first.
    let close = def.rfind(')');
    match (open, close) {
        (Some(o), Some(c)) if c > o => split_quoted_ident_list(&def[o + 1..c]),
        _ => Vec::new(),
    }
}

/// Splits a PostgreSQL identifier list on commas and unquotes each element.
///
/// `pg_get_constraintdef` quotes any identifier that is not a bare lowercase
/// word, so a table created by an ORM comes back as `PRIMARY KEY ("Id")`.
/// Carrying the quotes through would be wrong twice over: the name no longer
/// matches the column in `tables[].columns`, so the PK silently vanishes from
/// the desired state and the schema round-trips without one; and re-quoting on
/// emit produces `"""Id"""`. A missing PK is not cosmetic — foreign keys can
/// only reference a PRIMARY KEY or UNIQUE *constraint*, and logical replication
/// needs a replica identity.
///
/// Splitting is quote-aware because a quoted identifier may legally contain a
/// comma — `PRIMARY KEY ("a,b", c)` is two columns, not three. Inside quotes,
/// `""` is an escaped double quote.
fn split_quoted_ident_list(inner: &str) -> Vec<String> {
    let b = inner.as_bytes();
    let mut cols: Vec<String> = Vec::new();
    let mut cur = String::new();
    let mut in_quotes = false;
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'"' => {
                if in_quotes && i + 1 < b.len() && b[i + 1] == b'"' {
                    cur.push('"'); // escaped quote inside the identifier
                    i += 2;
                    continue;
                }
                in_quotes = !in_quotes;
            }
            b',' if !in_quotes => {
                let s = cur.trim();
                if !s.is_empty() {
                    cols.push(s.to_string());
                }
                cur.clear();
            }
            c => cur.push(c as char),
        }
        i += 1;
    }
    let s = cur.trim();
    if !s.is_empty() {
        cols.push(s.to_string());
    }
    cols
}

/// Removes the surrounding double quotes PostgreSQL adds when an identifier is
/// not a bare lowercase word, collapsing the doubled `""` escape back to a
/// single quote character.
fn unquote_ident(s: &str) -> String {
    let s = s.trim();
    let b = s.as_bytes();
    if b.len() < 2 || b[0] != b'"' || b[b.len() - 1] != b'"' {
        return s.to_string();
    }
    s[1..s.len() - 1].replace("\"\"", "\"")
}

/// Reports whether a UNIQUE constraint definition carries the NULLS NOT
/// DISTINCT modifier (PostgreSQL 15+).
///
/// `pg_get_constraintdef` renders it between the keyword and the column list —
/// `UNIQUE NULLS NOT DISTINCT (c)` — so it must be read off the prefix before
/// [`parse_constraint_cols`] takes the parenthesised part. The default (NULLS
/// DISTINCT) lets a nullable unique column hold unlimited NULL rows, so losing
/// this flag silently widens what the table accepts.
fn has_nulls_not_distinct(def: &str) -> bool {
    let head = match def.find('(') {
        Some(i) => &def[..i],
        None => def,
    };
    head.to_ascii_uppercase().contains("NULLS NOT DISTINCT")
}

/// Extracts the predicate from a CHECK constraint definition.
///
/// `pg_get_constraintdef` returns `CHECK ((quantity > 0))` — the keyword, then
/// the expression already wrapped in its own parentheses, optionally followed by
/// NOT VALID. One layer of parentheses is removed so the renderer's own
/// `CHECK (%s)` reproduces the original text rather than nesting further.
///
/// Returns `""` when the input is not a CHECK definition, so a caller cannot
/// accidentally emit a malformed constraint from an unexpected shape.
fn parse_check_expression(def: &str) -> String {
    let mut s = def.trim();

    // A trailing NOT VALID is a property of the constraint, not the predicate.
    const NV: &str = " NOT VALID";
    if let Some(idx) = s.to_ascii_uppercase().rfind(NV) {
        if idx == s.len() - NV.len() {
            s = s[..idx].trim();
        }
    }

    const KW: &str = "CHECK";
    if s.len() < KW.len() || !s[..KW.len()].eq_ignore_ascii_case(KW) {
        return String::new();
    }
    s = s[KW.len()..].trim();

    // Strip exactly one balanced outer paren pair.
    let b = s.as_bytes();
    if b.len() < 2 || b[0] != b'(' || b[b.len() - 1] != b')' {
        return String::new();
    }
    let mut depth = 0i32;
    for (i, c) in s.char_indices() {
        match c {
            '(' => depth += 1,
            ')' => {
                depth -= 1;
                // The opening paren closes before the end: the outer pair does
                // not wrap the whole expression, so removing it would change
                // the meaning.
                if depth == 0 && i != s.len() - 1 {
                    return s.to_string();
                }
            }
            _ => {}
        }
    }
    s[1..s.len() - 1].trim().to_string()
}

/// Extracts FK details from `pg_get_constraintdef` output, e.g.
/// `FOREIGN KEY (col) REFERENCES target(tcol) ON DELETE CASCADE`.
fn parse_fk_constraint(name: &str, def: &str) -> FkRecord {
    let mut rec = FkRecord {
        name: name.to_string(),
        on_delete: "NO ACTION".to_string(),
        ..Default::default()
    };
    let upper = def.to_ascii_uppercase();

    let fk_idx = match upper.find("FOREIGN KEY") {
        Some(i) => i,
        None => return FkRecord::default(),
    };
    let rest = &def[fk_idx + "FOREIGN KEY".len()..];
    let open = rest.find('(');
    let close = rest.find(')');
    let (open, close) = match (open, close) {
        (Some(o), Some(c)) => (o, c),
        _ => return FkRecord::default(),
    };
    rec.columns = split_quoted_ident_list(&rest[open + 1..close]);

    let ref_idx = match upper.find("REFERENCES ") {
        Some(i) => i,
        None => return FkRecord::default(),
    };
    let ref_rest = &def[ref_idx + "REFERENCES ".len()..];
    let ref_paren = match ref_rest.find('(') {
        Some(i) => i,
        None => return FkRecord::default(),
    };
    rec.ref_table = ref_rest[..ref_paren].trim().to_string();
    // Strip the schema prefix, then unquote — in that order, because the
    // separating dot sits outside the quotes (`app."Tenants"`).
    if let Some(dot) = rec.ref_table.rfind('.') {
        rec.ref_table = rec.ref_table[dot + 1..].to_string();
    }
    rec.ref_table = unquote_ident(&rec.ref_table);
    if let Some(ref_close_rel) = ref_rest[ref_paren..].find(')') {
        rec.ref_columns =
            split_quoted_ident_list(&ref_rest[ref_paren + 1..ref_paren + ref_close_rel]);
    }

    if let Some(idx) = upper.find("ON DELETE ") {
        let mut action = def[idx + "ON DELETE ".len()..].trim().to_string();
        for kw in [" ON ", " DEFERRABLE", " NOT "] {
            if let Some(ki) = action.to_ascii_uppercase().find(kw) {
                action = action[..ki].to_string();
            }
        }
        let action = action.trim();
        if !action.is_empty() {
            rec.on_delete = action.to_ascii_uppercase();
        }
    }
    rec
}

/// Finds the first `(` and the matching `)`, accounting for nesting.
/// Returns `(-1, -1)` if no `(`, or `(open, -1)` if unmatched.
fn matched_parens(s: &str) -> (isize, isize) {
    let b = s.as_bytes();
    let open = match s.find('(') {
        Some(i) => i,
        None => return (-1, -1),
    };
    let mut depth = 0i32;
    let mut i = open;
    while i < b.len() {
        match b[i] {
            b'(' => depth += 1,
            b')' => {
                depth -= 1;
                if depth == 0 {
                    return (open as isize, i as isize);
                }
            }
            _ => {}
        }
        i += 1;
    }
    (open as isize, -1)
}

/// Splits on commas not inside parentheses.
fn split_top_level_commas(s: &str) -> Vec<&str> {
    let b = s.as_bytes();
    let mut out = Vec::new();
    let mut depth = 0i32;
    let mut start = 0usize;
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'(' => depth += 1,
            b')' => {
                if depth > 0 {
                    depth -= 1;
                }
            }
            b',' if depth == 0 => {
                out.push(&s[start..i]);
                start = i + 1;
            }
            _ => {}
        }
        i += 1;
    }
    if start < b.len() {
        out.push(&s[start..]);
    }
    out
}

/// Extracts a [`DesiredIndex`] from a `pg_indexes` DDL string. Empty `name`
/// signals a parse failure (matching the Go zero-value sentinel).
fn parse_index_ddl(idx: &ObjectDdl) -> DesiredIndex {
    let mut di = DesiredIndex {
        name: idx.name.clone(),
        ..Default::default()
    };
    let def = idx.definition.as_str();
    let upper = def.to_ascii_uppercase();

    di.unique = upper.contains("UNIQUE INDEX");

    // Method.
    if let Some(using_idx) = upper.find(" USING ") {
        let rest = &def[using_idx + " USING ".len()..];
        let mut paren_idx = rest.find(' ').map(|i| i as isize).unwrap_or(-1);
        if let Some(p) = rest.find('(') {
            if paren_idx < 0 || (p as isize) < paren_idx {
                paren_idx = p as isize;
            }
        }
        if paren_idx > 0 {
            di.method = rest[..paren_idx as usize].trim().to_string();
        }
    }
    if di.method.is_empty() {
        di.method = "btree".to_string();
    }

    // WHERE clause.
    let mut body_end = def.len();
    if let Some(where_idx) = upper.find(" WHERE ") {
        di.where_ = def[where_idx + " WHERE ".len()..].trim().to_string();
        body_end = where_idx;
    }

    // NULLS NOT DISTINCT.
    let body0 = &def[..body_end];
    if let Some(nnd_idx) = body0.to_ascii_uppercase().find(" NULLS NOT DISTINCT") {
        di.nulls_not_distinct = true;
        body_end = nnd_idx;
    }

    // INCLUDE.
    let mut body = def[..body_end].to_string();
    if let Some(inc_idx) = body.to_ascii_uppercase().find(" INCLUDE ") {
        let inc_str = &body[inc_idx + " INCLUDE ".len()..];
        let (open, close) = matched_parens(inc_str);
        if open >= 0 && close > open {
            for c in split_top_level_commas(&inc_str[open as usize + 1..close as usize]) {
                let c = c.trim();
                if !c.is_empty() {
                    di.include.push(c.to_string());
                }
            }
        }
        body = body[..inc_idx].to_string();
    }

    // Main column list.
    let using_idx = match body.to_ascii_uppercase().find(" USING ") {
        Some(i) => i,
        None => return DesiredIndex::default(),
    };
    let rest = &body[using_idx..];
    let (open, close) = matched_parens(rest);
    if open < 0 || close <= open {
        return DesiredIndex::default();
    }
    let col_str = &rest[open as usize + 1..close as usize];

    // Expression-index shape: the inner content is one balanced paren pair.
    let trimmed = col_str.trim();
    if trimmed.starts_with('(') {
        let (eo, ec) = matched_parens(trimmed);
        if eo == 0 && ec == (trimmed.len() as isize - 1) {
            di.expression = trimmed[1..ec as usize].to_string();
            return di;
        }
    }

    let parts = split_top_level_commas(col_str);
    let mut has_modifiers = false;
    let mut parsed: Vec<DesiredIndexColumn> = Vec::new();
    let mut simple: Vec<String> = Vec::new();
    for p in parts {
        let entry = p.trim();
        let (refc, is_expr) = parse_column_ref_entry(entry);
        if refc.name.is_empty() && refc.expression.is_empty() {
            continue;
        }
        if is_expr
            || !refc.direction.is_empty()
            || !refc.nulls.is_empty()
            || !refc.op_class.is_empty()
        {
            has_modifiers = true;
        }
        if !refc.name.is_empty() {
            simple.push(refc.name.clone());
        }
        parsed.push(refc);
    }
    if has_modifiers {
        di.column_refs = parsed;
    } else {
        di.columns = simple;
    }

    if di.columns.is_empty() && di.column_refs.is_empty() {
        return DesiredIndex::default();
    }
    di
}

/// Parses one column-list entry into a [`DesiredIndexColumn`]. Returns the
/// entry and `is_expr=true` when the body is a SQL expression.
fn parse_column_ref_entry(s: &str) -> (DesiredIndexColumn, bool) {
    if s.is_empty() {
        return (DesiredIndexColumn::default(), false);
    }
    let (body, modifiers) = split_body_and_modifiers(s);
    if body.is_empty() {
        return (DesiredIndexColumn::default(), false);
    }
    let mut mods = parse_column_modifiers(modifiers);

    if is_expression_body(body) {
        let mut body = body;
        if body.starts_with('(') {
            let (eo, ec) = matched_parens(body);
            if eo == 0 && ec == (body.len() as isize - 1) {
                body = &body[1..ec as usize];
            }
        }
        mods.expression = body.to_string();
        return (mods, true);
    }

    mods.name = body.trim_matches('"').to_string();
    (mods, false)
}

/// Cuts an entry into its body (column/expression) and modifier suffix.
fn split_body_and_modifiers(s: &str) -> (&str, &str) {
    let b = s.as_bytes();
    let mut depth = 0i32;
    let mut body_end: isize = -1;
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'(' => depth += 1,
            b')' => {
                if depth > 0 {
                    depth -= 1;
                }
            }
            b' ' | b'\t' if depth == 0 && i > 0 => {
                body_end = i as isize;
            }
            _ => {}
        }
        if body_end >= 0 {
            break;
        }
        i += 1;
    }
    if body_end < 0 {
        return (s, "");
    }
    (&s[..body_end as usize], s[body_end as usize..].trim())
}

/// Extracts opclass / direction / nulls from the modifier-suffix tokens.
fn parse_column_modifiers(s: &str) -> DesiredIndexColumn {
    let mut mods = DesiredIndexColumn::default();
    if s.is_empty() {
        return mods;
    }
    let tokens: Vec<&str> = s.split_whitespace().collect();
    let mut i = 0;
    while i < tokens.len() {
        let t = tokens[i].to_ascii_uppercase();
        match t.as_str() {
            "ASC" => mods.direction = "asc".to_string(),
            "DESC" => mods.direction = "desc".to_string(),
            "NULLS" => {
                if i + 1 < tokens.len() {
                    match tokens[i + 1].to_ascii_uppercase().as_str() {
                        "FIRST" => mods.nulls = "first".to_string(),
                        "LAST" => mods.nulls = "last".to_string(),
                        _ => {}
                    }
                    i += 1;
                }
            }
            _ => {
                let candidate = tokens[i].trim_matches('"');
                if mods.op_class.is_empty() && !candidate.is_empty() {
                    mods.op_class = candidate.to_string();
                }
            }
        }
        i += 1;
    }
    mods
}

fn is_expression_body(s: &str) -> bool {
    s.contains("::") || s.contains('(')
}

/// Pulls the body from a `pg_get_functiondef` output, looking for `$$`/
/// `$fn$`/`$function$`/`$body$` delimiters.
fn extract_function_body(def: &str) -> String {
    for delim in ["$$", "$fn$", "$function$", "$body$"] {
        if let Some(first) = def.find(delim) {
            let after = first + delim.len();
            if let Some(second) = def[after..].find(delim) {
                return def[after..after + second].to_string();
            }
        }
    }
    def.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::drift::{ColumnShape, TableShape};

    #[test]
    fn parse_constraint_and_fk() {
        assert_eq!(parse_constraint_cols("PRIMARY KEY (a, b)"), vec!["a", "b"]);
        let fk = parse_fk_constraint(
            "fk1",
            "FOREIGN KEY (user_id) REFERENCES app.users(id) ON DELETE CASCADE",
        );
        assert_eq!(fk.name, "fk1");
        assert_eq!(fk.columns, vec!["user_id"]);
        assert_eq!(fk.ref_table, "users");
        assert_eq!(fk.ref_columns, vec!["id"]);
        assert_eq!(fk.on_delete, "CASCADE");
    }

    #[test]
    fn parse_simple_index() {
        let idx = ObjectDdl {
            name: "idx_email".into(),
            table: "users".into(),
            r#type: "index".into(),
            definition: "CREATE UNIQUE INDEX idx_email ON app.users USING btree (email)".into(),
        };
        let di = parse_index_ddl(&idx);
        assert_eq!(di.name, "idx_email");
        assert!(di.unique);
        assert_eq!(di.method, "btree");
        assert_eq!(di.columns, vec!["email"]);
        assert!(di.column_refs.is_empty());
    }

    #[test]
    fn parse_index_with_modifiers_and_where() {
        let idx = ObjectDdl {
            name: "idx_x".into(),
            table: "t".into(),
            r#type: "index".into(),
            definition:
                "CREATE INDEX idx_x ON app.t USING btree (a DESC, b) WHERE (deleted_at IS NULL)"
                    .into(),
        };
        let di = parse_index_ddl(&idx);
        assert_eq!(di.where_, "(deleted_at IS NULL)");
        assert!(!di.column_refs.is_empty(), "DESC modifier → column_refs");
        assert_eq!(di.column_refs[0].name, "a");
        assert_eq!(di.column_refs[0].direction, "desc");
        assert_eq!(di.column_refs[1].name, "b");
    }

    fn idx(def: &str) -> DesiredIndex {
        parse_index_ddl(&ObjectDdl {
            name: "n".into(),
            table: "t".into(),
            r#type: "index".into(),
            definition: def.into(),
        })
    }

    #[test]
    fn parse_index_golden_shapes() {
        // Single function-call column → per-column expression (NOT top-level).
        let di = idx("CREATE INDEX idx_lower ON app.t USING btree (lower(email))");
        assert!(di.expression.is_empty());
        assert_eq!(di.column_refs.len(), 1);
        assert_eq!(di.column_refs[0].expression, "lower(email)");

        // Double-paren wrapped expression → top-level Expression (inner unwrapped).
        let di = idx("CREATE INDEX idx_dbl ON app.t USING btree ((a + b))");
        assert_eq!(di.expression, "a + b");
        assert!(di.column_refs.is_empty() && di.columns.is_empty());

        // INCLUDE / covering.
        let di = idx("CREATE INDEX idx_inc ON app.t USING btree (a) INCLUDE (b, c)");
        assert_eq!(di.columns, vec!["a"]);
        assert_eq!(di.include, vec!["b", "c"]);

        // Per-column opclass.
        let di = idx("CREATE INDEX idx_op ON app.t USING btree (name varchar_pattern_ops)");
        assert_eq!(di.column_refs.len(), 1);
        assert_eq!(di.column_refs[0].name, "name");
        assert_eq!(di.column_refs[0].op_class, "varchar_pattern_ops");

        // NULLS NOT DISTINCT (unique).
        let di = idx("CREATE UNIQUE INDEX idx_nnd ON app.t USING btree (a) NULLS NOT DISTINCT");
        assert!(di.unique && di.nulls_not_distinct);
        assert_eq!(di.columns, vec!["a"]);

        // Non-btree method.
        let di = idx("CREATE INDEX idx_gin ON app.t USING gin (tags)");
        assert_eq!(di.method, "gin");
        assert_eq!(di.columns, vec!["tags"]);
    }

    #[test]
    fn extract_function_body_cases() {
        assert_eq!(
            extract_function_body(
                "CREATE FUNCTION f() RETURNS int LANGUAGE sql AS $function$ SELECT 1 $function$"
            ),
            " SELECT 1 "
        );
        assert_eq!(
            extract_function_body("no delimiters here"),
            "no delimiters here"
        );
    }

    #[test]
    fn from_snapshot_roundtrips_table() {
        let snap = Snapshot {
            schema: "app".into(),
            tables: vec![TableShape {
                name: "users".into(),
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
                ..Default::default()
            }],
            constraints: vec![ObjectDdl {
                name: "users_pkey".into(),
                table: "users".into(),
                r#type: "PRIMARY KEY".into(),
                definition: "PRIMARY KEY (id)".into(),
            }],
            ..Default::default()
        };
        let spec = from_snapshot(&snap);
        assert_eq!(spec.tables.len(), 1);
        let t = &spec.tables[0];
        assert_eq!(t.name, "users");
        assert!(t.columns[0].primary_key, "single-col PK → inline");
        assert_eq!(t.columns[1].r#type, "text[]", "ARRAY resolved");
        assert!(
            t.primary_key.is_empty(),
            "single-col PK not also table-level"
        );
        assert_eq!(t.primary_key_name, "users_pkey", "PK name carried verbatim");
    }

    #[test]
    fn split_quoted_ident_list_unquotes_and_respects_quoted_commas() {
        // A quoted identifier may legally contain a comma.
        assert_eq!(split_quoted_ident_list(r#""a,b", c"#), vec!["a,b", "c"]);
        // `""` is an escaped double quote inside the identifier.
        assert_eq!(
            split_quoted_ident_list(r#""He said ""hi""""#),
            vec![r#"He said "hi""#]
        );
        assert_eq!(split_quoted_ident_list(""), Vec::<String>::new());
    }

    #[test]
    fn parse_constraint_cols_unquotes_orm_identifiers() {
        // EF Core and friends quote every identifier. Carrying the quotes
        // through means the name matches no column, so the PK silently
        // vanishes from the desired state and the schema round-trips without
        // one.
        assert_eq!(
            parse_constraint_cols(r#"PRIMARY KEY ("TenantId", "Id")"#),
            vec!["TenantId", "Id"]
        );
        // Last `)`, not the first: DEFERRABLE follows the column list.
        assert_eq!(
            parse_constraint_cols("UNIQUE (a, b) DEFERRABLE INITIALLY DEFERRED"),
            vec!["a", "b"]
        );
    }

    #[test]
    fn parse_fk_unquotes_table_and_columns() {
        let fk = parse_fk_constraint(
            "FK_Todos_Tenants_TenantId",
            r#"FOREIGN KEY ("TenantId") REFERENCES app."Tenants"("Id") ON DELETE CASCADE"#,
        );
        assert_eq!(fk.columns, vec!["TenantId"]);
        // Schema prefix stripped before unquoting — the dot sits outside the
        // quotes in `app."Tenants"`.
        assert_eq!(fk.ref_table, "Tenants");
        assert_eq!(fk.ref_columns, vec!["Id"]);
    }

    #[test]
    fn has_nulls_not_distinct_reads_the_prefix() {
        assert!(has_nulls_not_distinct("UNIQUE NULLS NOT DISTINCT (c)"));
        assert!(!has_nulls_not_distinct("UNIQUE (c)"));
        // The modifier is rendered before the column list, so a column
        // literally named `nulls not distinct` must not trip the test.
        assert!(!has_nulls_not_distinct(r#"UNIQUE ("nulls not distinct")"#));
    }

    #[test]
    fn parse_check_expression_cases() {
        // Exactly one paren layer is removed: the renderer's own `CHECK (%s)`
        // then reproduces the original text rather than nesting further.
        assert_eq!(
            parse_check_expression("CHECK ((quantity > 0))"),
            "(quantity > 0)"
        );
        // Trailing NOT VALID is a property of the constraint, not the predicate.
        assert_eq!(
            parse_check_expression("CHECK ((quantity > 0)) NOT VALID"),
            "(quantity > 0)"
        );
        // The outer pair does not wrap the whole expression, so removing it
        // would change the meaning — returned untouched.
        assert_eq!(parse_check_expression("CHECK ((a) OR (b))"), "(a) OR (b)");
        // Not a CHECK definition → "", so no malformed constraint is emitted.
        assert_eq!(parse_check_expression("UNIQUE (a)"), "");
        assert_eq!(parse_check_expression("CHECK"), "");
    }

    #[test]
    fn from_snapshot_projects_constraints_and_filters_backing_indexes() {
        let snap = Snapshot {
            schema: "app".into(),
            extensions: vec![
                // Same schema as the one inspected → not pinned. A sql://
                // source is normalised through a content-hash-named scratch
                // schema, so pinning would write a throwaway identifier.
                crate::drift::ExtShape {
                    name: "pgcrypto".into(),
                    schema: "app".into(),
                    ..Default::default()
                },
                crate::drift::ExtShape {
                    name: "hstore".into(),
                    schema: "public".into(),
                    ..Default::default()
                },
            ],
            tables: vec![TableShape {
                name: "users".into(),
                kind: "BASE TABLE".into(),
                columns: vec![
                    ColumnShape {
                        name: "id".into(),
                        ordinal: 1,
                        data_type: "uuid".into(),
                        udt_name: "uuid".into(),
                        nullable: false,
                        ..Default::default()
                    },
                    ColumnShape {
                        name: "email".into(),
                        ordinal: 2,
                        data_type: "text".into(),
                        udt_name: "text".into(),
                        nullable: true,
                        ..Default::default()
                    },
                ],
                ..Default::default()
            }],
            constraints: vec![
                ObjectDdl {
                    name: "PK_users".into(),
                    table: "users".into(),
                    r#type: "PRIMARY KEY".into(),
                    definition: "PRIMARY KEY (id)".into(),
                },
                ObjectDdl {
                    name: "users_email_key".into(),
                    table: "users".into(),
                    r#type: "UNIQUE".into(),
                    definition: "UNIQUE NULLS NOT DISTINCT (email)".into(),
                },
                ObjectDdl {
                    name: "users_email_len".into(),
                    table: "users".into(),
                    r#type: "CHECK".into(),
                    definition: "CHECK ((length(email) > 3))".into(),
                },
            ],
            indexes: vec![
                // Backs PK_users — not an independent object.
                ObjectDdl {
                    name: "PK_users".into(),
                    table: "users".into(),
                    r#type: "index".into(),
                    definition: "CREATE UNIQUE INDEX \"PK_users\" ON app.users USING btree (id)"
                        .into(),
                },
                // Backs users_email_key — likewise.
                ObjectDdl {
                    name: "users_email_key".into(),
                    table: "users".into(),
                    r#type: "index".into(),
                    definition:
                        "CREATE UNIQUE INDEX users_email_key ON app.users USING btree (email)"
                            .into(),
                },
                // A hand-written index that merely ends in _pkey: the old
                // suffix filter would have dropped this.
                ObjectDdl {
                    name: "lookup_pkey".into(),
                    table: "users".into(),
                    r#type: "index".into(),
                    definition: "CREATE INDEX lookup_pkey ON app.users USING btree (email)".into(),
                },
            ],
            ..Default::default()
        };
        let spec = from_snapshot(&snap);

        assert_eq!(spec.extensions.len(), 2);
        assert_eq!(spec.extensions[0].name, "pgcrypto");
        assert_eq!(spec.extensions[0].schema, "", "inspected schema not pinned");
        assert_eq!(spec.extensions[1].schema, "public");

        let t = &spec.tables[0];
        assert_eq!(t.primary_key_name, "PK_users");
        assert_eq!(t.unique_constraints.len(), 1);
        assert_eq!(t.unique_constraints[0].columns, vec!["email"]);
        assert!(t.unique_constraints[0].nulls_not_distinct);
        assert_eq!(t.check_constraints.len(), 1);
        assert_eq!(t.check_constraints[0].definition, "(length(email) > 3)");

        let names: Vec<&str> = t.indexes.iter().map(|i| i.name.as_str()).collect();
        assert_eq!(
            names,
            vec!["lookup_pkey"],
            "only constraint-backed indexes are filtered"
        );
    }
}
