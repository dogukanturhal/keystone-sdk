// SPDX-License-Identifier: Apache-2.0

//! Phase A2 — backward compatibility. Ported from `rules_compat.go`.

use std::sync::LazyLock;

use regex::Regex;

use super::{statement_matches, Analyzer, Finding, LintLevel, Migration};

macro_rules! re {
    ($name:ident, $pat:expr) => {
        static $name: LazyLock<Regex> = LazyLock::new(|| Regex::new($pat).expect($pat));
    };
}

re!(
    RE_RENAME_COLUMN,
    r"(?i)\bALTER\s+TABLE\b[^;]*\bRENAME\s+COLUMN\b"
);
re!(
    RE_RENAME_CONSTRAINT,
    r"(?i)\bALTER\s+TABLE\b[^;]*\bRENAME\s+CONSTRAINT\b"
);
re!(RE_DROP_VIEW, r"(?i)\bDROP\s+(MATERIALIZED\s+)?VIEW\b");
re!(RE_DROP_FUNCTION, r"(?i)\bDROP\s+(FUNCTION|PROCEDURE)\b");
re!(RE_DROP_SEQUENCE, r"(?i)\bDROP\s+SEQUENCE\b");

/// no-rename-column
pub struct NoRenameColumn;
impl Analyzer for NoRenameColumn {
    fn id(&self) -> &'static str {
        "no-rename-column"
    }
    fn description(&self) -> &'static str {
        "ALTER TABLE RENAME COLUMN is synchronously visible; clients using the old name error"
    }
    fn check(&self, m: &Migration) -> Vec<Finding> {
        statement_matches(
            m,
            &RE_RENAME_COLUMN,
            LintLevel::Error,
            self.id(),
            "RENAME COLUMN is atomic and synchronously visible. Every client \
             still referencing the old column name fails. Stage instead: \
             ADD new column → dual-write trigger → backfill → deploy readers → \
             deploy writers → DROP old column.",
        )
    }
}

/// no-rename-constraint
pub struct NoRenameConstraint;
impl Analyzer for NoRenameConstraint {
    fn id(&self) -> &'static str {
        "no-rename-constraint"
    }
    fn description(&self) -> &'static str {
        "ALTER TABLE RENAME CONSTRAINT breaks any tooling keyed on the old name"
    }
    fn check(&self, m: &Migration) -> Vec<Finding> {
        statement_matches(
            m,
            &RE_RENAME_CONSTRAINT,
            LintLevel::Warning,
            self.id(),
            "RENAME CONSTRAINT invalidates any diff tool, dashboard, or \
             migration history keyed on the old constraint name. If a rename \
             is truly necessary, drop and re-add under the new name with the same definition.",
        )
    }
}

/// no-drop-view
pub struct NoDropView;
impl Analyzer for NoDropView {
    fn id(&self) -> &'static str {
        "no-drop-view"
    }
    fn description(&self) -> &'static str {
        "DROP VIEW breaks every caller; prefer CREATE OR REPLACE + deprecation"
    }
    fn check(&self, m: &Migration) -> Vec<Finding> {
        statement_matches(
            m,
            &RE_DROP_VIEW,
            LintLevel::Warning,
            self.id(),
            "DROP VIEW breaks every query that uses the view. \
             Prefer CREATE OR REPLACE VIEW for compatible shape changes, \
             or run a deprecation cycle: rename → new-name view → readers migrate → drop.",
        )
    }
}

/// no-drop-function
pub struct NoDropFunction;
impl Analyzer for NoDropFunction {
    fn id(&self) -> &'static str {
        "no-drop-function"
    }
    fn description(&self) -> &'static str {
        "DROP FUNCTION breaks triggers, views, and RLS policies that reference it"
    }
    fn check(&self, m: &Migration) -> Vec<Finding> {
        statement_matches(
            m,
            &RE_DROP_FUNCTION,
            LintLevel::Warning,
            self.id(),
            "DROP FUNCTION/PROCEDURE breaks everything that calls it — triggers, \
             views, RLS policies, application code. Use CREATE OR REPLACE for \
             in-place updates; DROP only during maintenance windows with full dependency review.",
        )
    }
}

/// no-drop-sequence
pub struct NoDropSequence;
impl Analyzer for NoDropSequence {
    fn id(&self) -> &'static str {
        "no-drop-sequence"
    }
    fn description(&self) -> &'static str {
        "DROP SEQUENCE breaks DEFAULT nextval() and IDENTITY ownership"
    }
    fn check(&self, m: &Migration) -> Vec<Finding> {
        statement_matches(
            m,
            &RE_DROP_SEQUENCE,
            LintLevel::Warning,
            self.id(),
            "DROP SEQUENCE breaks every DEFAULT nextval() expression that references it, \
             including columns converted from SERIAL. If you're migrating to \
             GENERATED AS IDENTITY, the drop happens automatically when the column changes — \
             explicit DROP SEQUENCE is usually unintended.",
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
    fn compat_rules() {
        assert_eq!(
            NoRenameColumn
                .check(&mig("ALTER TABLE t RENAME COLUMN a TO b;"))
                .len(),
            1
        );
        assert_eq!(
            NoRenameConstraint
                .check(&mig("ALTER TABLE t RENAME CONSTRAINT c TO d;"))
                .len(),
            1
        );
        assert_eq!(NoDropView.check(&mig("DROP VIEW v;")).len(), 1);
        assert_eq!(NoDropView.check(&mig("DROP MATERIALIZED VIEW v;")).len(), 1);
        assert_eq!(NoDropFunction.check(&mig("DROP FUNCTION f();")).len(), 1);
        assert_eq!(NoDropSequence.check(&mig("DROP SEQUENCE s;")).len(), 1);
    }
}
