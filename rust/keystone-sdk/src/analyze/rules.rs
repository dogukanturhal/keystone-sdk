// SPDX-License-Identifier: Apache-2.0

//! Phase 11.2 base pack — structural safety. Ported from `rules.go`.

use std::sync::LazyLock;

use regex::Regex;

use super::{
    finding, line_of_offset, statement_matches, stmt_verb_is, Analyzer, Finding, LintLevel,
    Migration,
};

macro_rules! re {
    ($name:ident, $pat:expr) => {
        static $name: LazyLock<Regex> = LazyLock::new(|| Regex::new($pat).expect($pat));
    };
}

re!(RE_DROP_TABLE, r"(?i)\bDROP\s+TABLE\b");
re!(
    RE_DROP_COLUMN,
    r"(?i)\bALTER\s+TABLE\b[^;]*\bDROP\s+COLUMN\b"
);
re!(
    RE_CREATE_INDEX_CONCURRENTLY,
    r"(?i)\bCREATE\s+(UNIQUE\s+)?INDEX\s+CONCURRENTLY\b"
);
re!(RE_CREATE_INDEX, r"(?i)\bCREATE\s+(UNIQUE\s+)?INDEX\b");
re!(RE_CREATE_TABLE, r"(?i)\bCREATE\s+TABLE\b");
re!(RE_PRIMARY_KEY, r"(?i)\bPRIMARY\s+KEY\b");
re!(
    RE_ALTER_COLUMN_TYPE,
    r"(?i)\bALTER\s+COLUMN\s+\w+\s+TYPE\b|\bALTER\s+COLUMN\s+\w+\s+SET\s+DATA\s+TYPE\b"
);
re!(
    RE_ADD_COLUMN_NOT_NULL_NO_DEFAULT,
    r"(?i)\bADD\s+COLUMN\s+\w+\s+[A-Za-z]+[^;]*\bNOT\s+NULL\b"
);
re!(RE_HAS_DEFAULT, r"(?i)\bDEFAULT\s+\S+");
re!(RE_TRUNCATE, r"(?i)\bTRUNCATE\b");
re!(RE_GRANT_ALL, r"(?i)\bGRANT\s+ALL\b");
re!(
    RE_DDL,
    r"(?i)\b(ALTER|CREATE|DROP)\s+(TABLE|INDEX|CONSTRAINT)\b"
);
re!(
    RE_STATEMENT_TIMEOUT,
    r"(?i)\bSET\s+(LOCAL\s+)?statement_timeout\b"
);
re!(
    RE_BEGIN_STATEMENT,
    r"(?im)^\s*BEGIN\s*(?:TRANSACTION|WORK)?\s*;"
);
re!(RE_DO_BLOCK, r"(?is)\bDO\s+\$\w*\$.*?\$\w*\$\s*;");

/// no-drop-table
pub struct NoDropTable;
impl Analyzer for NoDropTable {
    fn id(&self) -> &'static str {
        "no-drop-table"
    }
    fn description(&self) -> &'static str {
        "refuse DROP TABLE; use soft-delete or retention policy"
    }
    fn check(&self, m: &Migration) -> Vec<Finding> {
        statement_matches(
            m,
            &RE_DROP_TABLE,
            LintLevel::Error,
            self.id(),
            "DROP TABLE removes data irrecoverably; use a soft-delete column or \
             schedule via a separate destructive-migration workflow with operator sign-off",
        )
    }
}

/// no-drop-column
pub struct NoDropColumn;
impl Analyzer for NoDropColumn {
    fn id(&self) -> &'static str {
        "no-drop-column"
    }
    fn description(&self) -> &'static str {
        "prefer pgroll-expand-contract drop_column over ALTER TABLE DROP COLUMN"
    }
    fn check(&self, m: &Migration) -> Vec<Finding> {
        statement_matches(
            m,
            &RE_DROP_COLUMN,
            LintLevel::Error,
            self.id(),
            "ALTER TABLE DROP COLUMN is data-destructive and takes AccessExclusive lock. \
             Use strategy=pgroll-expand-contract with kind=drop_column for the two-phase safe drop",
        )
    }
}

/// prefer-concurrent-index-creation
pub struct PreferConcurrentIndexCreation;
impl Analyzer for PreferConcurrentIndexCreation {
    fn id(&self) -> &'static str {
        "prefer-concurrent-index-creation"
    }
    fn description(&self) -> &'static str {
        "CREATE INDEX takes ShareLock for the duration; add CONCURRENTLY for zero-downtime"
    }
    fn check(&self, m: &Migration) -> Vec<Finding> {
        let mut out = Vec::new();
        for f in &m.files {
            for (i, line) in f.body.split('\n').enumerate() {
                if RE_CREATE_INDEX.is_match(line) && !RE_CREATE_INDEX_CONCURRENTLY.is_match(line) {
                    out.push(finding(
                        self.id(),
                        LintLevel::Warning,
                        &f.name,
                        (i + 1) as i32,
                        "CREATE INDEX without CONCURRENTLY locks writes for the scan. \
                         Add CONCURRENTLY unless the table is empty or the migration is in a maintenance window.",
                    ));
                }
            }
        }
        out
    }
}

/// require-primary-key
pub struct RequirePrimaryKey;
impl Analyzer for RequirePrimaryKey {
    fn id(&self) -> &'static str {
        "require-primary-key"
    }
    fn description(&self) -> &'static str {
        "every CREATE TABLE must declare a PRIMARY KEY"
    }
    fn check(&self, m: &Migration) -> Vec<Finding> {
        let mut out = Vec::new();
        for f in &m.files {
            if RE_CREATE_TABLE.is_match(&f.body) && !RE_PRIMARY_KEY.is_match(&f.body) {
                out.push(finding(
                    self.id(),
                    LintLevel::Warning,
                    &f.name,
                    0,
                    "file contains CREATE TABLE but no PRIMARY KEY clause detected. \
                     Tables without a PK can't be replicated by logical replication or migrated via pgroll.",
                ));
            }
        }
        out
    }
}

/// no-alter-column-type-in-place
pub struct NoAlterColumnTypeInPlace;
impl Analyzer for NoAlterColumnTypeInPlace {
    fn id(&self) -> &'static str {
        "no-alter-column-type-in-place"
    }
    fn description(&self) -> &'static str {
        "ALTER COLUMN ... TYPE rewrites the table; use pgroll alter_column_type"
    }
    fn check(&self, m: &Migration) -> Vec<Finding> {
        statement_matches(
            m,
            &RE_ALTER_COLUMN_TYPE,
            LintLevel::Error,
            self.id(),
            "ALTER COLUMN TYPE rewrites the table and takes AccessExclusive lock. \
             Use strategy=pgroll-expand-contract with kind=alter_column_type for zero-downtime type changes",
        )
    }
}

/// no-add-required-field-without-default
pub struct NoAddRequiredFieldWithoutDefault;
impl Analyzer for NoAddRequiredFieldWithoutDefault {
    fn id(&self) -> &'static str {
        "no-add-required-field-without-default"
    }
    fn description(&self) -> &'static str {
        "ADD COLUMN NOT NULL without DEFAULT rewrites every row; add default or allow NULL"
    }
    fn check(&self, m: &Migration) -> Vec<Finding> {
        let mut out = Vec::new();
        for f in &m.files {
            for (i, line) in f.body.split('\n').enumerate() {
                if RE_ADD_COLUMN_NOT_NULL_NO_DEFAULT.is_match(line)
                    && !RE_HAS_DEFAULT.is_match(line)
                {
                    out.push(finding(
                        self.id(),
                        LintLevel::Error,
                        &f.name,
                        (i + 1) as i32,
                        "ADD COLUMN ... NOT NULL without DEFAULT forces a full-table rewrite. \
                         Either add a DEFAULT (PG 11+ instant add) or use kind=add_column with nullable=true + enforceNotNullInContract",
                    ));
                }
            }
        }
        out
    }
}

/// no-truncate
pub struct NoTruncate;
impl Analyzer for NoTruncate {
    fn id(&self) -> &'static str {
        "no-truncate"
    }
    fn description(&self) -> &'static str {
        "TRUNCATE is data-destructive and bypasses DELETE triggers"
    }
    fn check(&self, m: &Migration) -> Vec<Finding> {
        // Gate: only fire when the containing statement IS a TRUNCATE (avoids
        // matching the privilege name in GRANT ... TRUNCATE ...).
        let mut out = Vec::new();
        for f in &m.files {
            for mat in RE_TRUNCATE.find_iter(&f.body) {
                if !stmt_verb_is(&f.body, mat.start(), "TRUNCATE") {
                    continue;
                }
                out.push(finding(
                    self.id(),
                    LintLevel::Error,
                    &f.name,
                    line_of_offset(&f.body, mat.start()),
                    "TRUNCATE removes all rows irrecoverably and bypasses ON DELETE triggers. \
                     Use DELETE if you need row-level side effects, or policy-override=true if truly intended",
                ));
            }
        }
        out
    }
}

/// no-grant-all
pub struct NoGrantAll;
impl Analyzer for NoGrantAll {
    fn id(&self) -> &'static str {
        "no-grant-all"
    }
    fn description(&self) -> &'static str {
        "GRANT ALL is a privilege-escalation footgun; enumerate the privileges you actually need"
    }
    fn check(&self, m: &Migration) -> Vec<Finding> {
        statement_matches(
            m,
            &RE_GRANT_ALL,
            LintLevel::Warning,
            self.id(),
            "GRANT ALL includes future privileges added by PG upgrades. \
             Prefer an explicit privilege list: GRANT SELECT, INSERT, UPDATE, DELETE ...",
        )
    }
}

/// require-statement-timeout-on-ddl
pub struct RequireStatementTimeoutOnDdl;
impl Analyzer for RequireStatementTimeoutOnDdl {
    fn id(&self) -> &'static str {
        "require-statement-timeout-on-ddl"
    }
    fn description(&self) -> &'static str {
        "bare ALTER TABLE without statement_timeout can block forever on lock contention"
    }
    fn check(&self, m: &Migration) -> Vec<Finding> {
        let mut out = Vec::new();
        for f in &m.files {
            if RE_DDL.is_match(&f.body) && !RE_STATEMENT_TIMEOUT.is_match(&f.body) {
                out.push(finding(
                    self.id(),
                    LintLevel::Notice,
                    &f.name,
                    0,
                    "DDL migration without SET LOCAL statement_timeout. \
                     Keystone's runner sets a 30s default at pool level, but explicit SET in the migration \
                     makes the behaviour visible to reviewers.",
                ));
            }
        }
        out
    }
}

/// no-transaction-around-concurrent-index
pub struct NoTransactionAroundConcurrentIndex;
impl Analyzer for NoTransactionAroundConcurrentIndex {
    fn id(&self) -> &'static str {
        "no-transaction-around-concurrent-index"
    }
    fn description(&self) -> &'static str {
        "CREATE INDEX CONCURRENTLY cannot run inside a transaction block"
    }
    fn check(&self, m: &Migration) -> Vec<Finding> {
        let mut out = Vec::new();
        for f in &m.files {
            // Strip DO blocks before checking for transaction-control BEGIN.
            let body_no_do = RE_DO_BLOCK.replace_all(&f.body, "");
            if RE_CREATE_INDEX_CONCURRENTLY.is_match(&body_no_do)
                && RE_BEGIN_STATEMENT.is_match(&body_no_do)
            {
                out.push(finding(
                    self.id(),
                    LintLevel::Error,
                    &f.name,
                    0,
                    "CREATE INDEX CONCURRENTLY cannot run inside a transaction. \
                     Move the CONCURRENTLY statement into its own file (Keystone's runner applies each file in its own tx).",
                ));
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::super::{by_rule, Migration};
    use super::*;

    fn mig(body: &str) -> Migration {
        Migration {
            files: vec![super::super::FileBody {
                name: "001.sql".into(),
                body: body.into(),
            }],
            ..Default::default()
        }
    }

    #[test]
    fn no_drop_table_fires() {
        assert_eq!(NoDropTable.check(&mig("DROP TABLE users;")).len(), 1);
        assert_eq!(NoDropTable.check(&mig("SELECT 1;")).len(), 0);
    }

    #[test]
    fn no_truncate_gated_by_verb() {
        // GRANT ... TRUNCATE must NOT fire (privilege name, not the verb).
        let f = NoTruncate.check(&mig("GRANT TRUNCATE ON t TO app;"));
        assert_eq!(f.len(), 0);
        // Real TRUNCATE fires.
        let f = NoTruncate.check(&mig("TRUNCATE t;"));
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].severity, LintLevel::Error);
    }

    #[test]
    fn prefer_concurrent_index_skips_concurrently() {
        assert_eq!(
            PreferConcurrentIndexCreation
                .check(&mig("CREATE INDEX i ON t (c);"))
                .len(),
            1
        );
        assert_eq!(
            PreferConcurrentIndexCreation
                .check(&mig("CREATE INDEX CONCURRENTLY i ON t (c);"))
                .len(),
            0
        );
    }

    #[test]
    fn require_primary_key_whole_file() {
        assert_eq!(
            RequirePrimaryKey
                .check(&mig("CREATE TABLE t (id int);"))
                .len(),
            1
        );
        assert_eq!(
            RequirePrimaryKey
                .check(&mig("CREATE TABLE t (id int PRIMARY KEY);"))
                .len(),
            0
        );
    }

    #[test]
    fn add_required_field_without_default() {
        let f = NoAddRequiredFieldWithoutDefault
            .check(&mig("ALTER TABLE t ADD COLUMN c int NOT NULL;"));
        assert_eq!(f.len(), 1);
        let f = NoAddRequiredFieldWithoutDefault
            .check(&mig("ALTER TABLE t ADD COLUMN c int NOT NULL DEFAULT 0;"));
        assert_eq!(f.len(), 0);
    }

    #[test]
    fn no_tx_around_concurrent_index_ignores_do_block() {
        // Explicit BEGIN; + CONCURRENTLY → fires.
        let f = NoTransactionAroundConcurrentIndex.check(&mig(
            "BEGIN;\nCREATE INDEX CONCURRENTLY i ON t (c);\nCOMMIT;",
        ));
        assert_eq!(f.len(), 1);
        // PL/pgSQL BEGIN inside a DO block must NOT trip it.
        let f = NoTransactionAroundConcurrentIndex.check(&mig(
            "DO $$ BEGIN PERFORM 1; END $$;\nCREATE INDEX CONCURRENTLY i ON t (c);",
        ));
        assert_eq!(f.len(), 0);
    }

    #[test]
    fn registry_smoke_counts() {
        // A migration that trips several rules at once.
        let m = mig("DROP TABLE old;\nCREATE INDEX i ON t (c);");
        let findings = NoDropTable.check(&m);
        let found = by_rule(&findings);
        assert_eq!(found.get("no-drop-table"), Some(&1));
    }
}
