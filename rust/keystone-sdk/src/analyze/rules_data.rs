// SPDX-License-Identifier: Apache-2.0

//! Phase A2 — data-dependent operation safety. Ported from `rules_data.go`.

use std::sync::LazyLock;

use regex::Regex;

use super::{finding, line_of_offset, stmt_verb_is, Analyzer, Finding, LintLevel, Migration};

macro_rules! re {
    ($name:ident, $pat:expr) => {
        static $name: LazyLock<Regex> = LazyLock::new(|| Regex::new($pat).expect($pat));
    };
}

re!(RE_UPDATE_STMT, r"(?is)\bUPDATE\s+[^;]*;");
re!(RE_HAS_WHERE, r"(?i)\bWHERE\b");
re!(RE_DELETE_STMT, r"(?is)\bDELETE\s+FROM\s+[^;]*;");
re!(
    RE_INSERT_SELECT,
    r"(?is)\bINSERT\s+INTO\s+\w+(?:\s*\([^)]*\))?\s*SELECT\s+[^;]*?\bFROM\s+\w+[^;]*;"
);
re!(
    RE_INSERT_VALUES,
    r"(?is)\bINSERT\s+INTO\s+\w+[^;]*?\bVALUES\b[^;]*;"
);
re!(RE_VALUES_TUPLE, r"\)\s*,\s*\(");
re!(
    RE_DISABLE_TRIGGERS_ALL,
    r"(?i)\bDISABLE\s+TRIGGER\s+(ALL|USER)\b"
);

/// no-update-without-where
pub struct NoUpdateWithoutWhere;
impl Analyzer for NoUpdateWithoutWhere {
    fn id(&self) -> &'static str {
        "no-update-without-where"
    }
    fn description(&self) -> &'static str {
        "UPDATE without WHERE rewrites every row"
    }
    fn check(&self, m: &Migration) -> Vec<Finding> {
        let mut out = Vec::new();
        for f in &m.files {
            for mat in RE_UPDATE_STMT.find_iter(&f.body) {
                if !stmt_verb_is(&f.body, mat.start(), "UPDATE") {
                    continue;
                }
                let stmt = &f.body[mat.start()..mat.end()];
                if RE_HAS_WHERE.is_match(stmt) {
                    continue;
                }
                out.push(finding(
                    self.id(),
                    LintLevel::Error,
                    &f.name,
                    line_of_offset(&f.body, mat.start()),
                    "UPDATE without WHERE rewrites every row. Add a WHERE clause, or \
                     if you truly intend to update everything, annotate with \
                     `-- update-all:` on the line above and break into a batched migration.",
                ));
            }
        }
        out
    }
}

/// no-delete-without-where
pub struct NoDeleteWithoutWhere;
impl Analyzer for NoDeleteWithoutWhere {
    fn id(&self) -> &'static str {
        "no-delete-without-where"
    }
    fn description(&self) -> &'static str {
        "DELETE without WHERE removes every row"
    }
    fn check(&self, m: &Migration) -> Vec<Finding> {
        let mut out = Vec::new();
        for f in &m.files {
            for mat in RE_DELETE_STMT.find_iter(&f.body) {
                if !stmt_verb_is(&f.body, mat.start(), "DELETE") {
                    continue;
                }
                let stmt = &f.body[mat.start()..mat.end()];
                if RE_HAS_WHERE.is_match(stmt) {
                    continue;
                }
                out.push(finding(
                    self.id(),
                    LintLevel::Error,
                    &f.name,
                    line_of_offset(&f.body, mat.start()),
                    "DELETE without WHERE removes every row and generates row-level \
                     triggers for each. Add a WHERE clause; if the intent is to empty the table, \
                     consider TRUNCATE (after no-truncate review) or a policy-override annotation.",
                ));
            }
        }
        out
    }
}

/// no-insert-select-without-where
pub struct NoInsertSelectWithoutWhere;
impl Analyzer for NoInsertSelectWithoutWhere {
    fn id(&self) -> &'static str {
        "no-insert-select-without-where"
    }
    fn description(&self) -> &'static str {
        "INSERT … SELECT without WHERE copies the entire source table inside a migration"
    }
    fn check(&self, m: &Migration) -> Vec<Finding> {
        let mut out = Vec::new();
        for f in &m.files {
            for mat in RE_INSERT_SELECT.find_iter(&f.body) {
                let stmt = &f.body[mat.start()..mat.end()];
                if RE_HAS_WHERE.is_match(stmt) {
                    continue;
                }
                out.push(finding(
                    self.id(),
                    LintLevel::Warning,
                    &f.name,
                    line_of_offset(&f.body, mat.start()),
                    "INSERT INTO … SELECT without WHERE copies every row from the source, \
                     pinning the migration for the scan's duration. Prefer batched COPY \
                     outside the migration, or paginate with SELECT … WHERE id > $cursor LIMIT N.",
                ));
            }
        }
        out
    }
}

/// no-large-values-list (default cap 1000 row tuples)
pub struct NoLargeValuesList;
impl Analyzer for NoLargeValuesList {
    fn id(&self) -> &'static str {
        "no-large-values-list"
    }
    fn description(&self) -> &'static str {
        "VALUES lists > 1000 rows should use COPY"
    }
    fn check(&self, m: &Migration) -> Vec<Finding> {
        const CAP: usize = 1000;
        let mut out = Vec::new();
        for f in &m.files {
            for mat in RE_INSERT_VALUES.find_iter(&f.body) {
                let stmt = &f.body[mat.start()..mat.end()];
                // Rows = comma-separated tuple boundaries + 1.
                let tuples = RE_VALUES_TUPLE.find_iter(stmt).count() + 1;
                if tuples <= CAP {
                    continue;
                }
                out.push(finding(
                    self.id(),
                    LintLevel::Notice,
                    &f.name,
                    line_of_offset(&f.body, mat.start()),
                    format!(
                        "INSERT VALUES with {tuples} row tuples (>{CAP}). \
                         Large VALUES lists parse slowly and hold the table lock for the duration. \
                         Use COPY for bulk loads, or split across batches."
                    ),
                ));
            }
        }
        out
    }
}

/// no-disable-triggers-all
pub struct NoDisableTriggersAll;
impl Analyzer for NoDisableTriggersAll {
    fn id(&self) -> &'static str {
        "no-disable-triggers-all"
    }
    fn description(&self) -> &'static str {
        "DISABLE TRIGGER ALL bypasses FK / CHECK / audit triggers"
    }
    fn check(&self, m: &Migration) -> Vec<Finding> {
        let mut out = Vec::new();
        for f in &m.files {
            for (i, line) in f.body.split('\n').enumerate() {
                if !RE_DISABLE_TRIGGERS_ALL.is_match(line) {
                    continue;
                }
                out.push(finding(
                    self.id(),
                    LintLevel::Error,
                    &f.name,
                    (i + 1) as i32,
                    "DISABLE TRIGGER ALL/USER bypasses every trigger including FK and audit. \
                     Inserts can create orphan rows. If you need a bulk load path, \
                     use a CHECK NOT VALID + VALIDATE CONSTRAINT pattern instead.",
                ));
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::super::{FileBody, Migration};
    use super::*;

    fn mig(body: &str) -> Migration {
        Migration {
            files: vec![FileBody {
                name: "001.sql".into(),
                body: body.into(),
            }],
            ..Default::default()
        }
    }

    #[test]
    fn update_without_where() {
        assert_eq!(
            NoUpdateWithoutWhere
                .check(&mig("UPDATE t SET a = 1;"))
                .len(),
            1
        );
        assert_eq!(
            NoUpdateWithoutWhere
                .check(&mig("UPDATE t SET a = 1 WHERE id = 2;"))
                .len(),
            0
        );
        // GRANT ... UPDATE ... must NOT fire.
        assert_eq!(
            NoUpdateWithoutWhere
                .check(&mig("GRANT UPDATE ON t TO app;"))
                .len(),
            0
        );
    }

    #[test]
    fn delete_without_where() {
        assert_eq!(NoDeleteWithoutWhere.check(&mig("DELETE FROM t;")).len(), 1);
        assert_eq!(
            NoDeleteWithoutWhere
                .check(&mig("DELETE FROM t WHERE id = 1;"))
                .len(),
            0
        );
    }

    #[test]
    fn insert_select_and_values() {
        assert_eq!(
            NoInsertSelectWithoutWhere
                .check(&mig("INSERT INTO t SELECT * FROM src;"))
                .len(),
            1
        );
        assert_eq!(
            NoInsertSelectWithoutWhere
                .check(&mig("INSERT INTO t SELECT * FROM src WHERE x;"))
                .len(),
            0
        );
        // 1001 tuples → fires; small list → not.
        let tuples = vec!["(1)"; 1001].join(",");
        let big = format!("INSERT INTO t VALUES {tuples};");
        assert_eq!(NoLargeValuesList.check(&mig(&big)).len(), 1);
        assert_eq!(
            NoLargeValuesList
                .check(&mig("INSERT INTO t VALUES (1),(2),(3);"))
                .len(),
            0
        );
    }

    #[test]
    fn disable_triggers() {
        assert_eq!(
            NoDisableTriggersAll
                .check(&mig("ALTER TABLE t DISABLE TRIGGER ALL;"))
                .len(),
            1
        );
    }
}
