// SPDX-License-Identifier: Apache-2.0

//! Phase A2 — lock-heavy operations. Ported from `rules_locks.go`.

use std::sync::LazyLock;

use regex::Regex;

use super::{finding, line_of_offset, statement_matches, Analyzer, Finding, LintLevel, Migration};

macro_rules! re {
    ($name:ident, $pat:expr) => {
        static $name: LazyLock<Regex> = LazyLock::new(|| Regex::new($pat).expect($pat));
    };
}

re!(
    RE_ADD_FOREIGN_KEY,
    r"(?i)\bALTER\s+TABLE\b[^;]*\bADD\s+(?:CONSTRAINT\s+\w+\s+)?FOREIGN\s+KEY\b"
);
re!(RE_NOT_VALID, r"(?i)\bNOT\s+VALID\b");
re!(
    RE_ADD_CHECK,
    r"(?i)\bALTER\s+TABLE\b[^;]*\bADD\s+(?:CONSTRAINT\s+\w+\s+)?CHECK\s*\("
);
re!(
    RE_ADD_UNIQUE_CONSTRAINT,
    r"(?i)\bALTER\s+TABLE\b[^;]*\bADD\s+(?:CONSTRAINT\s+\w+\s+)?UNIQUE\s*\("
);
re!(RE_USING_INDEX, r"(?i)\bUSING\s+INDEX\b");
re!(
    RE_SET_NOT_NULL,
    r"(?i)\bALTER\s+COLUMN\s+\w+\s+SET\s+NOT\s+NULL\b"
);
re!(
    RE_CHECK_IS_NOT_NULL,
    r"(?i)\bCHECK\s*\(\s*\w+\s+IS\s+NOT\s+NULL\s*\)\s*NOT\s+VALID\b"
);
re!(RE_VACUUM_FULL, r"(?i)\bVACUUM\s+FULL\b");
re!(RE_CLUSTER, r"(?i)^\s*CLUSTER\b|\bCLUSTER\s+\w+\s+USING\b");
re!(
    RE_REINDEX,
    r"(?i)\bREINDEX\s+(TABLE|INDEX|SCHEMA|DATABASE|SYSTEM)\b"
);
re!(
    RE_REINDEX_CONCURRENTLY,
    r"(?i)\bREINDEX\s+(TABLE|INDEX|SCHEMA|DATABASE|SYSTEM)\s+CONCURRENTLY\b"
);
re!(RE_DROP_INDEX, r"(?i)\bDROP\s+INDEX\b");
re!(
    RE_DROP_INDEX_CONCURRENTLY,
    r"(?i)\bDROP\s+INDEX\s+CONCURRENTLY\b"
);
re!(RE_LOCK_TABLE, r"(?i)\bLOCK\s+TABLE\b");

/// Shared shape for the "file-level scan + guard regex" rules: emit one
/// finding per match of `re` unless `guard` matches anywhere in the file.
fn file_scan_guarded(
    m: &Migration,
    re: &Regex,
    guard: &Regex,
    rule: &str,
    sev: LintLevel,
    msg: &str,
) -> Vec<Finding> {
    let mut out = Vec::new();
    for f in &m.files {
        let locs: Vec<usize> = re.find_iter(&f.body).map(|mat| mat.start()).collect();
        if locs.is_empty() {
            continue;
        }
        if guard.is_match(&f.body) {
            continue;
        }
        for start in locs {
            out.push(finding(
                rule,
                sev,
                &f.name,
                line_of_offset(&f.body, start),
                msg,
            ));
        }
    }
    out
}

/// no-add-fk-without-not-valid
pub struct NoAddFkWithoutNotValid;
impl Analyzer for NoAddFkWithoutNotValid {
    fn id(&self) -> &'static str {
        "no-add-fk-without-not-valid"
    }
    fn description(&self) -> &'static str {
        "ALTER TABLE ADD FOREIGN KEY without NOT VALID scans every row under a lock"
    }
    fn check(&self, m: &Migration) -> Vec<Finding> {
        file_scan_guarded(
            m,
            &RE_ADD_FOREIGN_KEY,
            &RE_NOT_VALID,
            self.id(),
            LintLevel::Warning,
            "ALTER TABLE ADD FOREIGN KEY without NOT VALID scans every row \
             under ShareRowExclusive. Two-step: ADD CONSTRAINT … FOREIGN KEY … NOT VALID; \
             then VALIDATE CONSTRAINT (RowExclusive, concurrent-safe).",
        )
    }
}

/// no-add-check-without-not-valid
pub struct NoAddCheckWithoutNotValid;
impl Analyzer for NoAddCheckWithoutNotValid {
    fn id(&self) -> &'static str {
        "no-add-check-without-not-valid"
    }
    fn description(&self) -> &'static str {
        "ALTER TABLE ADD CHECK without NOT VALID scans every row under a lock"
    }
    fn check(&self, m: &Migration) -> Vec<Finding> {
        file_scan_guarded(
            m,
            &RE_ADD_CHECK,
            &RE_NOT_VALID,
            self.id(),
            LintLevel::Warning,
            "ALTER TABLE ADD CHECK without NOT VALID validates every row synchronously. \
             Two-step: ADD CONSTRAINT … CHECK (…) NOT VALID; then VALIDATE CONSTRAINT.",
        )
    }
}

/// no-unique-constraint-direct
pub struct NoUniqueConstraintDirect;
impl Analyzer for NoUniqueConstraintDirect {
    fn id(&self) -> &'static str {
        "no-unique-constraint-direct"
    }
    fn description(&self) -> &'static str {
        "ALTER TABLE ADD CONSTRAINT … UNIQUE without USING INDEX locks writes during build"
    }
    fn check(&self, m: &Migration) -> Vec<Finding> {
        file_scan_guarded(
            m,
            &RE_ADD_UNIQUE_CONSTRAINT,
            &RE_USING_INDEX,
            self.id(),
            LintLevel::Warning,
            "Direct ADD UNIQUE builds the backing index under AccessExclusive. \
             Two-step: CREATE UNIQUE INDEX CONCURRENTLY idx ON t(col); \
             ALTER TABLE t ADD CONSTRAINT c UNIQUE USING INDEX idx;",
        )
    }
}

/// no-set-not-null-direct
pub struct NoSetNotNullDirect;
impl Analyzer for NoSetNotNullDirect {
    fn id(&self) -> &'static str {
        "no-set-not-null-direct"
    }
    fn description(&self) -> &'static str {
        "ALTER COLUMN SET NOT NULL scans every row under AccessExclusive"
    }
    fn check(&self, m: &Migration) -> Vec<Finding> {
        file_scan_guarded(
            m,
            &RE_SET_NOT_NULL,
            &RE_CHECK_IS_NOT_NULL,
            self.id(),
            LintLevel::Warning,
            "ALTER COLUMN SET NOT NULL scans every row under AccessExclusive. \
             On PG 12+: ADD CHECK (col IS NOT NULL) NOT VALID; VALIDATE CONSTRAINT; \
             SET NOT NULL (now instant because the CHECK is proven).",
        )
    }
}

/// no-vacuum-full
pub struct NoVacuumFull;
impl Analyzer for NoVacuumFull {
    fn id(&self) -> &'static str {
        "no-vacuum-full"
    }
    fn description(&self) -> &'static str {
        "VACUUM FULL rewrites the table under AccessExclusive; use pg_repack instead"
    }
    fn check(&self, m: &Migration) -> Vec<Finding> {
        statement_matches(
            m,
            &RE_VACUUM_FULL,
            LintLevel::Error,
            self.id(),
            "VACUUM FULL takes AccessExclusive for the rewrite's duration. \
             For live tables use pg_repack (online equivalent); for one-offs schedule a maintenance window.",
        )
    }
}

/// no-cluster
pub struct NoCluster;
impl Analyzer for NoCluster {
    fn id(&self) -> &'static str {
        "no-cluster"
    }
    fn description(&self) -> &'static str {
        "CLUSTER rewrites the table under AccessExclusive"
    }
    fn check(&self, m: &Migration) -> Vec<Finding> {
        let mut out = Vec::new();
        for f in &m.files {
            for (i, line) in f.body.split('\n').enumerate() {
                if RE_CLUSTER.is_match(line) {
                    out.push(finding(
                        self.id(),
                        LintLevel::Error,
                        &f.name,
                        (i + 1) as i32,
                        "CLUSTER rewrites the table under AccessExclusive. \
                         Use pg_repack for online equivalent; reserve CLUSTER for maintenance windows.",
                    ));
                }
            }
        }
        out
    }
}

/// no-reindex-without-concurrently
pub struct NoReindexWithoutConcurrently;
impl Analyzer for NoReindexWithoutConcurrently {
    fn id(&self) -> &'static str {
        "no-reindex-without-concurrently"
    }
    fn description(&self) -> &'static str {
        "REINDEX without CONCURRENTLY blocks writes for the rebuild"
    }
    fn check(&self, m: &Migration) -> Vec<Finding> {
        let mut out = Vec::new();
        for f in &m.files {
            for (i, line) in f.body.split('\n').enumerate() {
                if !RE_REINDEX.is_match(line) {
                    continue;
                }
                if RE_REINDEX_CONCURRENTLY.is_match(line) {
                    continue;
                }
                out.push(finding(
                    self.id(),
                    LintLevel::Warning,
                    &f.name,
                    (i + 1) as i32,
                    "REINDEX without CONCURRENTLY takes an exclusive lock for the rebuild's duration. \
                     Use REINDEX ... CONCURRENTLY on PG 12+ for an online rebuild.",
                ));
            }
        }
        out
    }
}

/// no-drop-index-without-concurrently
pub struct NoDropIndexWithoutConcurrently;
impl Analyzer for NoDropIndexWithoutConcurrently {
    fn id(&self) -> &'static str {
        "no-drop-index-without-concurrently"
    }
    fn description(&self) -> &'static str {
        "DROP INDEX without CONCURRENTLY takes AccessExclusive on the parent table"
    }
    fn check(&self, m: &Migration) -> Vec<Finding> {
        let mut out = Vec::new();
        for f in &m.files {
            for (i, line) in f.body.split('\n').enumerate() {
                if !RE_DROP_INDEX.is_match(line) {
                    continue;
                }
                if RE_DROP_INDEX_CONCURRENTLY.is_match(line) {
                    continue;
                }
                out.push(finding(
                    self.id(),
                    LintLevel::Warning,
                    &f.name,
                    (i + 1) as i32,
                    "DROP INDEX without CONCURRENTLY takes AccessExclusive on the parent. \
                     Use DROP INDEX CONCURRENTLY to drop without blocking concurrent writes.",
                ));
            }
        }
        out
    }
}

/// no-lock-table-explicit
pub struct NoLockTableExplicit;
impl Analyzer for NoLockTableExplicit {
    fn id(&self) -> &'static str {
        "no-lock-table-explicit"
    }
    fn description(&self) -> &'static str {
        "LOCK TABLE is rarely the right answer; prefer transactional semantics"
    }
    fn check(&self, m: &Migration) -> Vec<Finding> {
        statement_matches(
            m,
            &RE_LOCK_TABLE,
            LintLevel::Warning,
            self.id(),
            "Explicit LOCK TABLE is almost always a workaround. \
             PostgreSQL's transaction machinery acquires the minimum lock; \
             if you truly need an exclusive lock, consider restructuring the migration.",
        )
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
    fn add_fk_not_valid_guard() {
        assert_eq!(
            NoAddFkWithoutNotValid
                .check(&mig(
                    "ALTER TABLE t ADD CONSTRAINT fk FOREIGN KEY (a) REFERENCES p(id);"
                ))
                .len(),
            1
        );
        assert_eq!(
            NoAddFkWithoutNotValid
                .check(&mig(
                    "ALTER TABLE t ADD CONSTRAINT fk FOREIGN KEY (a) REFERENCES p(id) NOT VALID;"
                ))
                .len(),
            0
        );
    }

    #[test]
    fn unique_constraint_using_index_guard() {
        assert_eq!(
            NoUniqueConstraintDirect
                .check(&mig("ALTER TABLE t ADD CONSTRAINT u UNIQUE (a);"))
                .len(),
            1
        );
        assert_eq!(
            NoUniqueConstraintDirect
                .check(&mig(
                    "ALTER TABLE t ADD CONSTRAINT u UNIQUE USING INDEX ix;"
                ))
                .len(),
            0
        );
    }

    #[test]
    fn set_not_null_and_vacuum_cluster() {
        assert_eq!(
            NoSetNotNullDirect
                .check(&mig("ALTER TABLE t ALTER COLUMN a SET NOT NULL;"))
                .len(),
            1
        );
        assert_eq!(NoVacuumFull.check(&mig("VACUUM FULL t;")).len(), 1);
        assert_eq!(NoCluster.check(&mig("CLUSTER t USING ix;")).len(), 1);
    }

    #[test]
    fn reindex_and_drop_index_concurrently() {
        assert_eq!(
            NoReindexWithoutConcurrently
                .check(&mig("REINDEX TABLE t;"))
                .len(),
            1
        );
        assert_eq!(
            NoReindexWithoutConcurrently
                .check(&mig("REINDEX TABLE CONCURRENTLY t;"))
                .len(),
            0
        );
        assert_eq!(
            NoDropIndexWithoutConcurrently
                .check(&mig("DROP INDEX ix;"))
                .len(),
            1
        );
        assert_eq!(
            NoDropIndexWithoutConcurrently
                .check(&mig("DROP INDEX CONCURRENTLY ix;"))
                .len(),
            0
        );
    }
}
