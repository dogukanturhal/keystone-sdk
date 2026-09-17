// SPDX-License-Identifier: Apache-2.0

//! Phase 9.3 — rollback safety. Ported from `rules_rollback.go`.

use super::{finding, Analyzer, Finding, LintLevel, Migration};

/// require-down-migration
pub struct RequireDownMigration;
impl Analyzer for RequireDownMigration {
    fn id(&self) -> &'static str {
        "require-down-migration"
    }
    fn description(&self) -> &'static str {
        "warn when a versioned migration has no down source for rollback"
    }
    fn check(&self, m: &Migration) -> Vec<Finding> {
        // Only applies to the versioned strategy.
        if !m.strategy.is_empty() && m.strategy != "versioned" {
            return Vec::new();
        }
        // Skip operation-based bundles (no SQL files).
        if m.files.is_empty() {
            return Vec::new();
        }
        if m.has_down_source {
            return Vec::new();
        }
        vec![finding(
            self.id(),
            LintLevel::Warning,
            "",
            0,
            "no down source configured; if this migration fails, automatic rollback \
             is not possible — only forward-fix. Add spec.downSource with *.down.sql files \
             to enable rollback capability",
        )]
    }
}

#[cfg(test)]
mod tests {
    use super::super::{FileBody, Migration};
    use super::*;

    fn mig() -> Migration {
        Migration {
            files: vec![FileBody {
                name: "001.sql".into(),
                body: "CREATE TABLE t (id int);".into(),
            }],
            ..Default::default()
        }
    }

    #[test]
    fn fires_without_down_source() {
        assert_eq!(RequireDownMigration.check(&mig()).len(), 1);
    }

    #[test]
    fn silent_with_down_source() {
        let mut m = mig();
        m.has_down_source = true;
        assert_eq!(RequireDownMigration.check(&m).len(), 0);
    }

    #[test]
    fn skips_non_versioned_strategy() {
        let mut m = mig();
        m.strategy = "pgroll-expand-contract".into();
        assert_eq!(RequireDownMigration.check(&m).len(), 0);
    }

    #[test]
    fn skips_operation_based() {
        let mut m = mig();
        m.files.clear();
        assert_eq!(RequireDownMigration.check(&m).len(), 0);
    }
}
