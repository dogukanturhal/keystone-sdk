// SPDX-License-Identifier: Apache-2.0

//! Phase 9.6 — cross-bundle breaking change detection. Ported from
//! `rules_crossbundle.go`. Flags destructive ops in this bundle that would
//! break objects referenced by other pending bundles' SQL.

use std::collections::{HashMap, HashSet};
use std::sync::LazyLock;

use regex::Regex;

use super::{finding, line_of_offset, Analyzer, FileBody, Finding, LintLevel, Migration};

/// Simplified live-schema state, populated from `drift::Snapshot` by the
/// reconciler. (The cross-bundle rule only checks for its *presence*; the
/// fields mirror the Go type for API completeness.)
#[derive(Debug, Clone, Default)]
pub struct SchemaObjectSet {
    /// Table name → set of column names.
    pub tables: HashMap<String, HashSet<String>>,
    /// Index names that exist in the schema.
    pub indexes: HashSet<String>,
    /// Constraint names that exist.
    pub constraints: HashSet<String>,
}

macro_rules! re {
    ($name:ident, $pat:expr) => {
        static $name: LazyLock<Regex> = LazyLock::new(|| Regex::new($pat).expect($pat));
    };
}

re!(
    RE_TABLE_REF,
    r"(?i)\b(?:FROM|JOIN|INTO|UPDATE|TABLE|REFERENCES)\s+(?:(?:[a-z_][a-z0-9_]*)\.)?([a-z_][a-z0-9_]*)"
);
re!(
    RE_COLUMN_REF,
    r"(?i)\bALTER\s+TABLE\s+(?:(?:[a-z_][a-z0-9_]*)\.)?([a-z_][a-z0-9_]*)\s+(?:ADD|ALTER|DROP)\s+(?:COLUMN\s+)?(?:IF\s+(?:NOT\s+)?EXISTS\s+)?([a-z_][a-z0-9_]*)"
);
re!(
    RE_INDEX_REF,
    r"(?i)\b(?:CREATE|DROP)\s+(?:UNIQUE\s+)?INDEX\s+(?:CONCURRENTLY\s+)?(?:IF\s+(?:NOT\s+)?EXISTS\s+)?(?:(?:[a-z_][a-z0-9_]*)\.)?([a-z_][a-z0-9_]*)"
);
re!(
    RE_CB_DROP_TABLE,
    r"(?i)\bDROP\s+TABLE\s+(?:IF\s+EXISTS\s+)?(?:(?:[a-z_][a-z0-9_]*)\.)?([a-z_][a-z0-9_]*)"
);
re!(
    RE_CB_DROP_COLUMN,
    r"(?i)\bALTER\s+TABLE\s+(?:(?:[a-z_][a-z0-9_]*)\.)?([a-z_][a-z0-9_]*)\s+DROP\s+(?:COLUMN\s+)?(?:IF\s+EXISTS\s+)?([a-z_][a-z0-9_]*)"
);
re!(
    RE_CB_RENAME_COLUMN,
    r"(?i)\bALTER\s+TABLE\s+(?:(?:[a-z_][a-z0-9_]*)\.)?([a-z_][a-z0-9_]*)\s+RENAME\s+(?:COLUMN\s+)?([a-z_][a-z0-9_]*)\s+TO\s+([a-z_][a-z0-9_]*)"
);
re!(
    RE_CB_DROP_INDEX,
    r"(?i)\bDROP\s+INDEX\s+(?:CONCURRENTLY\s+)?(?:IF\s+EXISTS\s+)?(?:(?:[a-z_][a-z0-9_]*)\.)?([a-z_][a-z0-9_]*)"
);

const RULE: &str = "cross-bundle-breaking-change";

/// cross-bundle-breaking-change
pub struct CrossBundleBreakDetector;
impl Analyzer for CrossBundleBreakDetector {
    fn id(&self) -> &'static str {
        RULE
    }
    fn description(&self) -> &'static str {
        "detect destructive operations that would break other pending bundles"
    }
    fn check(&self, m: &Migration) -> Vec<Finding> {
        if m.schema_objects.is_none() || m.pending_bundle_sql.is_empty() {
            return Vec::new();
        }
        let refs = extract_references(&m.pending_bundle_sql);
        let mut findings = Vec::new();
        for f in &m.files {
            findings.extend(check_drop_table(f, &refs));
            findings.extend(check_drop_column(f, &refs));
            findings.extend(check_rename_column(f, &refs));
            findings.extend(check_drop_index(f, &refs));
        }
        findings
    }
}

/// What objects pending bundles' SQL references.
#[derive(Default)]
struct PendingReferences {
    table_refs: HashSet<String>,
    /// "table.column" keys.
    column_refs: HashSet<String>,
    index_refs: HashSet<String>,
}

fn extract_references(pending_sql: &[FileBody]) -> PendingReferences {
    let mut refs = PendingReferences::default();
    for f in pending_sql {
        for caps in RE_TABLE_REF.captures_iter(&f.body) {
            refs.table_refs
                .insert(caps.get(1).unwrap().as_str().to_lowercase());
        }
        for caps in RE_COLUMN_REF.captures_iter(&f.body) {
            let table = caps.get(1).unwrap().as_str().to_lowercase();
            let col = caps.get(2).unwrap().as_str().to_lowercase();
            refs.column_refs.insert(format!("{table}.{col}"));
            refs.table_refs.insert(table);
        }
        for caps in RE_INDEX_REF.captures_iter(&f.body) {
            refs.index_refs
                .insert(caps.get(1).unwrap().as_str().to_lowercase());
        }
    }
    refs
}

fn check_drop_table(f: &FileBody, refs: &PendingReferences) -> Vec<Finding> {
    let mut out = Vec::new();
    for caps in RE_CB_DROP_TABLE.captures_iter(&f.body) {
        let whole = caps.get(0).unwrap().start();
        let table = caps.get(1).unwrap().as_str().to_lowercase();
        if refs.table_refs.contains(&table) {
            out.push(finding(
                RULE,
                LintLevel::Error,
                &f.name,
                line_of_offset(&f.body, whole),
                format!(
                    "DROP TABLE {table} would break a pending bundle that references this table"
                ),
            ));
        }
    }
    out
}

fn check_drop_column(f: &FileBody, refs: &PendingReferences) -> Vec<Finding> {
    let mut out = Vec::new();
    for caps in RE_CB_DROP_COLUMN.captures_iter(&f.body) {
        let whole = caps.get(0).unwrap().start();
        let table = caps.get(1).unwrap().as_str().to_lowercase();
        let col = caps.get(2).unwrap().as_str().to_lowercase();
        if refs.column_refs.contains(&format!("{table}.{col}")) {
            out.push(finding(
                RULE,
                LintLevel::Error,
                &f.name,
                line_of_offset(&f.body, whole),
                format!(
                    "DROP COLUMN {table}.{col} would break a pending bundle that references this column"
                ),
            ));
        }
    }
    out
}

fn check_rename_column(f: &FileBody, refs: &PendingReferences) -> Vec<Finding> {
    let mut out = Vec::new();
    for caps in RE_CB_RENAME_COLUMN.captures_iter(&f.body) {
        let whole = caps.get(0).unwrap().start();
        let table = caps.get(1).unwrap().as_str().to_lowercase();
        let old_col = caps.get(2).unwrap().as_str().to_lowercase();
        if refs.column_refs.contains(&format!("{table}.{old_col}")) {
            let new_col = caps.get(3).unwrap().as_str().to_lowercase();
            out.push(finding(
                RULE,
                LintLevel::Error,
                &f.name,
                line_of_offset(&f.body, whole),
                format!(
                    "RENAME COLUMN {table}.{old_col} TO {new_col} would break a pending bundle that references the old name"
                ),
            ));
        }
    }
    out
}

fn check_drop_index(f: &FileBody, refs: &PendingReferences) -> Vec<Finding> {
    let mut out = Vec::new();
    for caps in RE_CB_DROP_INDEX.captures_iter(&f.body) {
        let whole = caps.get(0).unwrap().start();
        let idx = caps.get(1).unwrap().as_str().to_lowercase();
        if refs.index_refs.contains(&idx) {
            out.push(finding(
                RULE,
                LintLevel::Error,
                &f.name,
                line_of_offset(&f.body, whole),
                format!("DROP INDEX {idx} would break a pending bundle that references this index"),
            ));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::super::{FileBody, Migration};
    use super::*;

    #[test]
    fn no_schema_objects_means_silent() {
        let m = Migration {
            files: vec![FileBody {
                name: "001.sql".into(),
                body: "DROP TABLE t;".into(),
            }],
            pending_bundle_sql: vec![FileBody {
                name: "p.sql".into(),
                body: "SELECT * FROM t;".into(),
            }],
            schema_objects: None,
            ..Default::default()
        };
        assert_eq!(CrossBundleBreakDetector.check(&m).len(), 0);
    }

    #[test]
    fn drop_table_referenced_by_pending() {
        let m = Migration {
            files: vec![FileBody {
                name: "001.sql".into(),
                body: "DROP TABLE orders;".into(),
            }],
            pending_bundle_sql: vec![FileBody {
                name: "p.sql".into(),
                body: "SELECT * FROM orders;".into(),
            }],
            schema_objects: Some(SchemaObjectSet::default()),
            ..Default::default()
        };
        let f = CrossBundleBreakDetector.check(&m);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].rule, "cross-bundle-breaking-change");
        assert!(f[0].message.contains("DROP TABLE orders"));
    }

    #[test]
    fn drop_column_referenced_by_pending() {
        let m = Migration {
            files: vec![FileBody {
                name: "001.sql".into(),
                body: "ALTER TABLE orders DROP COLUMN total;".into(),
            }],
            pending_bundle_sql: vec![FileBody {
                name: "p.sql".into(),
                body: "ALTER TABLE orders ALTER COLUMN total TYPE bigint;".into(),
            }],
            schema_objects: Some(SchemaObjectSet::default()),
            ..Default::default()
        };
        let f = CrossBundleBreakDetector.check(&m);
        assert_eq!(f.len(), 1);
        assert!(f[0].message.contains("DROP COLUMN orders.total"));
    }
}
