// SPDX-License-Identifier: Apache-2.0

//! Phase A2 — transaction / session-state safety. Ported from `rules_tx.go`.

use std::sync::LazyLock;

use regex::Regex;

use super::{finding, statement_matches, Analyzer, Finding, LintLevel, Migration};

macro_rules! re {
    ($name:ident, $pat:expr) => {
        static $name: LazyLock<Regex> = LazyLock::new(|| Regex::new($pat).expect($pat));
    };
}

re!(RE_COMMIT, r"(?i)^\s*COMMIT\s*;?\s*(--.*)?$");
re!(RE_ROLLBACK, r"(?i)^\s*ROLLBACK\s*;?\s*(--.*)?$");
re!(
    RE_SESSION_REPLICATION_ROLE,
    r"(?i)\bSET\s+(SESSION\s+|LOCAL\s+)?session_replication_role\b"
);
re!(
    RE_SET_CONSTRAINTS_DEFERRED,
    r"(?i)\bSET\s+CONSTRAINTS\s+ALL\s+DEFERRED\b"
);

/// no-commit-in-migration
pub struct NoCommitInMigration;
impl Analyzer for NoCommitInMigration {
    fn id(&self) -> &'static str {
        "no-commit-in-migration"
    }
    fn description(&self) -> &'static str {
        "COMMIT inside a migration breaks the runner's rollback invariant"
    }
    fn check(&self, m: &Migration) -> Vec<Finding> {
        let mut out = Vec::new();
        for f in &m.files {
            for (i, line) in f.body.split('\n').enumerate() {
                if !RE_COMMIT.is_match(line) {
                    continue;
                }
                out.push(finding(
                    self.id(),
                    LintLevel::Error,
                    &f.name,
                    (i + 1) as i32,
                    "COMMIT inside the migration body splits it into multiple physical \
                     transactions. The runner wraps each file in its own transaction; \
                     an author-supplied COMMIT makes partial failures non-rollbackable.",
                ));
            }
        }
        out
    }
}

/// no-rollback-in-migration
pub struct NoRollbackInMigration;
impl Analyzer for NoRollbackInMigration {
    fn id(&self) -> &'static str {
        "no-rollback-in-migration"
    }
    fn description(&self) -> &'static str {
        "ROLLBACK inside a migration is almost always a leftover debug statement"
    }
    fn check(&self, m: &Migration) -> Vec<Finding> {
        let mut out = Vec::new();
        for f in &m.files {
            for (i, line) in f.body.split('\n').enumerate() {
                if !RE_ROLLBACK.is_match(line) {
                    continue;
                }
                out.push(finding(
                    self.id(),
                    LintLevel::Error,
                    &f.name,
                    (i + 1) as i32,
                    "ROLLBACK inside the migration body is a debug remnant. The runner \
                     rolls back automatically when a statement errors; explicit ROLLBACK \
                     discards work the author apparently meant to commit.",
                ));
            }
        }
        out
    }
}

/// no-set-session-replication-role
pub struct NoSetSessionReplicationRole;
impl Analyzer for NoSetSessionReplicationRole {
    fn id(&self) -> &'static str {
        "no-set-session-replication-role"
    }
    fn description(&self) -> &'static str {
        "SET session_replication_role bypasses FK and user triggers"
    }
    fn check(&self, m: &Migration) -> Vec<Finding> {
        statement_matches(
            m,
            &RE_SESSION_REPLICATION_ROLE,
            LintLevel::Error,
            self.id(),
            "SET session_replication_role silences every user-defined trigger, \
             including FK enforcement. Orphan rows planted this way survive the migration \
             and break every downstream invariant. Use CHECK NOT VALID + VALIDATE CONSTRAINT \
             if you need a deferred constraint check instead.",
        )
    }
}

/// no-set-constraints-deferred
pub struct NoSetConstraintsDeferred;
impl Analyzer for NoSetConstraintsDeferred {
    fn id(&self) -> &'static str {
        "no-set-constraints-deferred"
    }
    fn description(&self) -> &'static str {
        "SET CONSTRAINTS ALL DEFERRED delays every FK/CHECK validation to COMMIT"
    }
    fn check(&self, m: &Migration) -> Vec<Finding> {
        statement_matches(
            m,
            &RE_SET_CONSTRAINTS_DEFERRED,
            LintLevel::Warning,
            self.id(),
            "SET CONSTRAINTS ALL DEFERRED postpones every FK/CHECK to COMMIT. \
             For circular inserts, defer only the specific constraint: \
             `SET CONSTRAINTS <name> DEFERRED`. Wholesale deferral hides errors \
             that should fire immediately and makes debugging harder.",
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
    fn commit_and_rollback() {
        assert_eq!(NoCommitInMigration.check(&mig("COMMIT;")).len(), 1);
        assert_eq!(NoCommitInMigration.check(&mig("  commit")).len(), 1);
        // COMMIT PREPARED is a 2PC variant — must NOT match.
        assert_eq!(
            NoCommitInMigration
                .check(&mig("COMMIT PREPARED 'x';"))
                .len(),
            0
        );
        assert_eq!(NoRollbackInMigration.check(&mig("ROLLBACK;")).len(), 1);
    }

    #[test]
    fn session_replication_role_and_constraints() {
        assert_eq!(
            NoSetSessionReplicationRole
                .check(&mig("SET session_replication_role = replica;"))
                .len(),
            1
        );
        assert_eq!(
            NoSetConstraintsDeferred
                .check(&mig("SET CONSTRAINTS ALL DEFERRED;"))
                .len(),
            1
        );
    }
}
