// SPDX-License-Identifier: Apache-2.0

//! Cross-migration analyzer (Phase A4) + the shared `line_of_offset`.
//! Ported from `rules_cross.go`. Walks a bundle's SQL files in apply order
//! and tracks `{table → column set}` created earlier in the SAME bundle,
//! flagging destructive ops against that bundle-local state.

use std::collections::{HashMap, HashSet};
use std::sync::LazyLock;

use regex::Regex;

use super::{finding, Analyzer, Finding, LintLevel, Migration};

macro_rules! re {
    ($name:ident, $pat:expr) => {
        static $name: LazyLock<Regex> = LazyLock::new(|| Regex::new($pat).expect($pat));
    };
}

re!(
    RE_CREATE_TABLE_X4,
    r"(?is)\bCREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?(?:(?:[a-z_][a-z0-9_]*)\.)?([a-z_][a-z0-9_]*)\s*\(([^;]*?)\)\s*;"
);
re!(
    RE_ALTER_TABLE_ADD,
    r"(?i)\bALTER\s+TABLE\s+(?:(?:[a-z_][a-z0-9_]*)\.)?([a-z_][a-z0-9_]*)\s+ADD\s+(?:COLUMN\s+)?(?:IF\s+NOT\s+EXISTS\s+)?([a-z_][a-z0-9_]*)"
);
re!(
    RE_ALTER_TABLE_DROP,
    r"(?i)\bALTER\s+TABLE\s+(?:(?:[a-z_][a-z0-9_]*)\.)?([a-z_][a-z0-9_]*)\s+DROP\s+(?:COLUMN\s+)?(?:IF\s+EXISTS\s+)?([a-z_][a-z0-9_]*)"
);
re!(
    RE_ALTER_TABLE_RENAME_COL,
    r"(?i)\bALTER\s+TABLE\s+(?:(?:[a-z_][a-z0-9_]*)\.)?([a-z_][a-z0-9_]*)\s+RENAME\s+(?:COLUMN\s+)?([a-z_][a-z0-9_]*)\s+TO\s+([a-z_][a-z0-9_]*)"
);
re!(
    RE_ALTER_TABLE_ALTER_TYPE,
    r"(?i)\bALTER\s+TABLE\s+(?:(?:[a-z_][a-z0-9_]*)\.)?([a-z_][a-z0-9_]*)\s+ALTER\s+(?:COLUMN\s+)?([a-z_][a-z0-9_]*)\s+(?:SET\s+DATA\s+)?TYPE\b"
);
re!(
    RE_DROP_TABLE_X4,
    r"(?i)\bDROP\s+TABLE\s+(?:IF\s+EXISTS\s+)?(?:(?:[a-z_][a-z0-9_]*)\.)?([a-z_][a-z0-9_]*)"
);
// NOTE: intentionally NOT case-insensitive — matches the Go quirk where
// only lowercase column declarations (`col type`) are harvested.
re!(RE_COLUMN_IDENT, r"(?m)^\s*([a-z_][a-z0-9_]*)\s+[a-z]");

/// `ALTER TABLE t <verb> …` does not always name a column. `COLUMN` is optional
/// in PostgreSQL, so the regexes above make it optional too — which means the
/// identifier they capture after `ADD`/`DROP`/`RENAME` is whatever word came
/// next, including the keyword introducing a table-level subcommand.
///
/// Left unfiltered that turns the ordinary CHECK-widening idiom
///
/// ```sql
/// ALTER TABLE t DROP CONSTRAINT IF EXISTS t_status_check;
/// ALTER TABLE t ADD  CONSTRAINT t_status_check CHECK (...);
/// ```
///
/// into a self-inflicted error finding: the ADD registers a phantom column
/// named `constraint`, and the DROP then reports "removes a column the same
/// bundle introduced". Every widening of an enumerated CHECK trips it.
///
/// Keyed by verb rather than pooled, so the skip is as narrow as possible.
/// These are reserved words in PostgreSQL, so a real column of the same name
/// could only be written quoted — and a quoted identifier does not match the
/// unquoted `[a-z_]` capture in the first place.
fn is_subcommand_keyword(verb: &str, ident: &str) -> bool {
    match verb {
        // ADD CONSTRAINT / PRIMARY KEY / UNIQUE / FOREIGN KEY / CHECK / EXCLUDE
        "add" => matches!(
            ident,
            "constraint" | "primary" | "unique" | "foreign" | "check" | "exclude"
        ),
        // DROP CONSTRAINT is the only table-level DROP that is not a column;
        // DROP DEFAULT / NOT NULL are reachable only via ALTER COLUMN, which
        // these regexes do not match.
        "drop" | "rename" => ident == "constraint",
        _ => false,
    }
}

/// Returns the 1-based line number for a byte offset in `body`.
pub(crate) fn line_of_offset(body: &str, off: usize) -> i32 {
    let off = off.min(body.len());
    1 + body[..off].matches('\n').count() as i32
}

/// cross-migration-breaking-change
pub struct BreakingChangeDetector;
impl Analyzer for BreakingChangeDetector {
    fn id(&self) -> &'static str {
        "cross-migration-breaking-change"
    }
    fn description(&self) -> &'static str {
        "flag DROP/RENAME/ALTER COLUMN TYPE against objects created earlier in the same bundle"
    }
    fn check(&self, m: &Migration) -> Vec<Finding> {
        let mut tables: HashMap<String, HashSet<String>> = HashMap::new();
        let mut out: Vec<Finding> = Vec::new();

        for f in &m.files {
            // 1) CREATE TABLE — harvest the column list.
            for caps in RE_CREATE_TABLE_X4.captures_iter(&f.body) {
                let table = caps.get(1).unwrap().as_str().to_lowercase();
                let cols = parse_column_list(caps.get(2).unwrap().as_str());
                let set = tables.entry(table).or_default();
                for c in cols {
                    set.insert(c);
                }
            }

            // 2) ALTER TABLE ADD COLUMN — extend the column set.
            for caps in RE_ALTER_TABLE_ADD.captures_iter(&f.body) {
                let table = caps.get(1).unwrap().as_str().to_lowercase();
                let col = caps.get(2).unwrap().as_str().to_lowercase();
                if is_subcommand_keyword("add", &col) {
                    continue;
                }
                if let Some(set) = tables.get_mut(&table) {
                    set.insert(col);
                }
            }

            // 3) ALTER TABLE DROP COLUMN — destructive against bundle-local state.
            for caps in RE_ALTER_TABLE_DROP.captures_iter(&f.body) {
                let whole = caps.get(0).unwrap().start();
                let table = caps.get(1).unwrap().as_str().to_lowercase();
                let col = caps.get(2).unwrap().as_str().to_lowercase();
                if is_subcommand_keyword("drop", &col) {
                    continue;
                }
                if tables.get(&table).is_some_and(|s| s.contains(&col)) {
                    out.push(finding(
                        self.id(),
                        LintLevel::Error,
                        &f.name,
                        line_of_offset(&f.body, whole),
                        format!(
                            "ALTER TABLE {table} DROP COLUMN {col} \
                             removes a column the same bundle introduced — \
                             split into two bundles with a deprecation window or use pgroll-expand-contract"
                        ),
                    ));
                }
            }

            // 4) ALTER TABLE RENAME COLUMN — always a client break.
            for caps in RE_ALTER_TABLE_RENAME_COL.captures_iter(&f.body) {
                let whole = caps.get(0).unwrap().start();
                let table = caps.get(1).unwrap().as_str().to_lowercase();
                let old_col = caps.get(2).unwrap().as_str().to_lowercase();
                let new_col = caps.get(3).unwrap().as_str().to_lowercase();
                if is_subcommand_keyword("rename", &old_col) {
                    continue;
                }
                if let Some(set) = tables.get_mut(&table) {
                    if set.contains(&old_col) {
                        out.push(finding(
                            self.id(),
                            LintLevel::Error,
                            &f.name,
                            line_of_offset(&f.body, whole),
                            format!(
                                "ALTER TABLE {table} RENAME COLUMN {old_col} TO {new_col} \
                                 breaks clients reading the old name — use add-new-column + backfill + drop-old-column across two bundles"
                            ),
                        ));
                        // Track the rename so later drops of new_col fire too.
                        set.remove(&old_col);
                        set.insert(new_col);
                    }
                }
            }

            // 5) ALTER TABLE ALTER COLUMN TYPE — a rewrite under the hood.
            for caps in RE_ALTER_TABLE_ALTER_TYPE.captures_iter(&f.body) {
                let whole = caps.get(0).unwrap().start();
                let table = caps.get(1).unwrap().as_str().to_lowercase();
                let col = caps.get(2).unwrap().as_str().to_lowercase();
                if tables.get(&table).is_some_and(|s| s.contains(&col)) {
                    out.push(finding(
                        self.id(),
                        LintLevel::Error,
                        &f.name,
                        line_of_offset(&f.body, whole),
                        format!(
                            "ALTER TABLE {table} ALTER COLUMN {col} TYPE … \
                             is a full-table rewrite against a column the same bundle introduced — \
                             get the type right in the CREATE TABLE, or split into an expand/contract pair"
                        ),
                    ));
                }
            }

            // 6) DROP TABLE that the same bundle CREATEd.
            for caps in RE_DROP_TABLE_X4.captures_iter(&f.body) {
                let whole = caps.get(0).unwrap().start();
                let table = caps.get(1).unwrap().as_str().to_lowercase();
                if tables.contains_key(&table) {
                    out.push(finding(
                        self.id(),
                        LintLevel::Error,
                        &f.name,
                        line_of_offset(&f.body, whole),
                        format!(
                            "DROP TABLE {table} removes a table the same bundle CREATEd — \
                             delete the CREATE TABLE and ship a clean bundle instead of creating-then-dropping"
                        ),
                    ));
                    tables.remove(&table);
                }
            }
        }

        out
    }
}

/// Extracts column names from a `CREATE TABLE (...)` body — split on
/// depth-0 commas, skip constraint-only segments, take the first lowercase
/// identifier of each.
fn parse_column_list(body: &str) -> Vec<String> {
    let mut out = Vec::new();
    for seg in split_comma_depth0(body) {
        let seg = seg.trim();
        let upper = seg.to_uppercase();
        if upper.starts_with("PRIMARY KEY")
            || upper.starts_with("UNIQUE")
            || upper.starts_with("CHECK")
            || upper.starts_with("FOREIGN KEY")
            || upper.starts_with("CONSTRAINT")
        {
            continue;
        }
        let with_nl = format!("{seg}\n");
        if let Some(caps) = RE_COLUMN_IDENT.captures(&with_nl) {
            out.push(caps.get(1).unwrap().as_str().to_lowercase());
        }
    }
    out
}

/// Splits `s` on commas outside any parentheses.
fn split_comma_depth0(s: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let mut depth = 0i32;
    let mut start = 0usize;
    for (i, c) in s.char_indices() {
        match c {
            '(' => depth += 1,
            ')' => depth -= 1,
            ',' if depth == 0 => {
                out.push(&s[start..i]);
                start = i + 1;
            }
            _ => {}
        }
    }
    if start < s.len() {
        out.push(&s[start..]);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::super::{FileBody, Migration};
    use super::*;

    fn mig_files(files: &[(&str, &str)]) -> Migration {
        Migration {
            files: files
                .iter()
                .map(|(n, b)| FileBody {
                    name: (*n).into(),
                    body: (*b).into(),
                })
                .collect(),
            ..Default::default()
        }
    }

    #[test]
    fn line_of_offset_counts_newlines() {
        assert_eq!(line_of_offset("a\nb\nc", 0), 1);
        assert_eq!(line_of_offset("a\nb\nc", 2), 2);
        assert_eq!(line_of_offset("a\nb\nc", 100), 3);
    }

    #[test]
    fn drop_column_created_in_same_bundle() {
        let m = mig_files(&[(
            "001.sql",
            "CREATE TABLE t (id int, email text);\nALTER TABLE t DROP COLUMN email;",
        )]);
        let f = BreakingChangeDetector.check(&m);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].rule, "cross-migration-breaking-change");
        assert!(f[0].message.contains("DROP COLUMN email"));
    }

    #[test]
    fn drop_column_not_created_here_is_silent() {
        // email is not created in this bundle → nothing tracked → no finding.
        let m = mig_files(&[("001.sql", "ALTER TABLE t DROP COLUMN email;")]);
        assert_eq!(BreakingChangeDetector.check(&m).len(), 0);
    }

    #[test]
    fn widening_a_check_constraint_is_not_a_column_drop() {
        // The standard way to widen an enumerated CHECK: drop the old
        // constraint, re-add it with the larger value set. Neither statement
        // touches a column, so neither may be reported — but with `COLUMN`
        // optional in the regexes, the ADD used to register a phantom column
        // named `constraint` that the DROP then "removed".
        let m = mig_files(&[(
            "0056_pop3_scope.up.sql",
            "ALTER TABLE app_passwords DROP CONSTRAINT IF EXISTS app_passwords_scope_check;\n\
             ALTER TABLE app_passwords ADD CONSTRAINT app_passwords_scope_check\n\
                 CHECK (scope IS NULL OR scope IN ('smtp', 'imap', 'pop3'));",
        )]);
        assert_eq!(BreakingChangeDetector.check(&m), Vec::new());

        // Same, in the order the DO-block form emits them, and with the table
        // created in the same bundle so the column set is actually populated.
        let m2 = mig_files(&[(
            "001.sql",
            "CREATE TABLE quarantine (id uuid, status text);\n\
             ALTER TABLE quarantine ADD CONSTRAINT quarantine_status_check\n\
                 CHECK (status IN ('held','released'));\n\
             ALTER TABLE quarantine DROP CONSTRAINT quarantine_status_check;",
        )]);
        assert_eq!(BreakingChangeDetector.check(&m2), Vec::new());
    }

    #[test]
    fn other_table_level_add_subcommands_are_not_columns() {
        let m = mig_files(&[(
            "001.sql",
            "CREATE TABLE t (a text, b text);\n\
             ALTER TABLE t ADD PRIMARY KEY (a);\n\
             ALTER TABLE t ADD UNIQUE (b);\n\
             ALTER TABLE t ADD FOREIGN KEY (a) REFERENCES u (id);\n\
             ALTER TABLE t ADD CHECK (a <> '');\n\
             ALTER TABLE t ADD EXCLUDE USING gist (a WITH =);",
        )]);
        assert_eq!(BreakingChangeDetector.check(&m), Vec::new());
    }

    #[test]
    fn renaming_a_constraint_is_not_a_column_rename() {
        let m = mig_files(&[(
            "001.sql",
            "CREATE TABLE t (id int);\n\
             ALTER TABLE t RENAME CONSTRAINT t_old_check TO t_new_check;",
        )]);
        assert_eq!(BreakingChangeDetector.check(&m), Vec::new());
    }

    #[test]
    fn a_real_column_drop_still_fires_beside_constraint_traffic() {
        // The guard must be narrow: constraint churn in the same file may not
        // mask the column drop sitting next to it.
        let m = mig_files(&[(
            "001.sql",
            "CREATE TABLE t (id int, email text);\n\
             ALTER TABLE t DROP CONSTRAINT IF EXISTS t_email_check;\n\
             ALTER TABLE t DROP COLUMN email;",
        )]);
        let f = BreakingChangeDetector.check(&m);
        assert_eq!(f.len(), 1);
        assert!(f[0].message.contains("DROP COLUMN email"));
    }

    #[test]
    fn rename_in_same_file_then_cross_file_drop() {
        // Within ONE file the analyzer processes all DROP COLUMNs (section 3)
        // BEFORE all RENAMEs (section 4), so a DROP of the not-yet-renamed
        // name doesn't fire — only the rename does (1 finding). Matches the
        // Go section ordering exactly.
        let m = mig_files(&[(
            "001.sql",
            "CREATE TABLE t (id int, a text);\nALTER TABLE t RENAME COLUMN a TO b;\nALTER TABLE t DROP COLUMN b;",
        )]);
        let f = BreakingChangeDetector.check(&m);
        assert_eq!(f.len(), 1);
        assert!(f[0].message.contains("RENAME COLUMN a TO b"));

        // The rename-tracking IS visible across files: a later file dropping
        // the renamed column `b` fires (set now holds `b`).
        let m2 = mig_files(&[
            (
                "001.sql",
                "CREATE TABLE t (id int, a text);\nALTER TABLE t RENAME COLUMN a TO b;",
            ),
            ("002.sql", "ALTER TABLE t DROP COLUMN b;"),
        ]);
        let f2 = BreakingChangeDetector.check(&m2);
        assert_eq!(f2.len(), 2);
    }

    #[test]
    fn create_then_drop_table() {
        let m = mig_files(&[("001.sql", "CREATE TABLE t (id int);\nDROP TABLE t;")]);
        let f = BreakingChangeDetector.check(&m);
        assert_eq!(f.len(), 1);
        assert!(f[0].message.contains("DROP TABLE t"));
    }

    #[test]
    fn cross_file_tracking() {
        let m = mig_files(&[
            ("001.sql", "CREATE TABLE t (id int, x text);"),
            ("002.sql", "ALTER TABLE t DROP COLUMN x;"),
        ]);
        assert_eq!(BreakingChangeDetector.check(&m).len(), 1);
    }
}
