// SPDX-License-Identifier: Apache-2.0

//! Keystone's native lint analyzer framework.
//!
//! Ported from the Go `analyze` package. Each rule implements [`Analyzer`];
//! the [`Registry`] runs every registered analyzer against a [`Migration`]
//! and aggregates [`Finding`]s. Rules are native regex matchers (Keystone's
//! lint is explicitly NOT squawk/eugene) — the port reproduces every rule's
//! ID, severity, regexes, and message text verbatim for wire-compatibility.
//!
//! [`default_registry`] returns the full 53-rule pack in the same order as
//! the Go `DefaultRegistry`.

mod helpers;
mod rules;
mod rules_compat;
mod rules_cross;
mod rules_crossbundle;
mod rules_data;
mod rules_extended;
mod rules_locks;
mod rules_naming;
mod rules_rollback;
mod rules_stmtverb;
mod rules_tx;
mod rules_types;

pub use rules_crossbundle::SchemaObjectSet;

/// Severity of a [`Finding`] (mirrors `keystonev1alpha1.LintLevel`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LintLevel {
    Error,
    Warning,
    Notice,
}

impl LintLevel {
    /// The wire string (`error`/`warning`/`notice`).
    pub fn as_str(&self) -> &'static str {
        match self {
            LintLevel::Error => "error",
            LintLevel::Warning => "warning",
            LintLevel::Notice => "notice",
        }
    }
}

impl std::fmt::Display for LintLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A filename paired with its SQL content.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FileBody {
    pub name: String,
    pub body: String,
}

/// The lightweight view the analyzer framework consumes.
///
/// Mirrors the Go `Migration`. `operations` (declarative ops) is omitted —
/// no native rule reads it, and the SDK `lint` entry point never sets it.
#[derive(Debug, Clone, Default)]
pub struct Migration {
    /// Identify the source for finding provenance.
    pub bundle_name: String,
    pub version: String,
    /// The ordered list of SQL files (name + body).
    pub files: Vec<FileBody>,
    /// The schema the bundle targets (for finding context).
    pub target_schema: String,
    /// True when the bundle has a downSource configured.
    pub has_down_source: bool,
    /// The bundle's apply strategy.
    pub strategy: String,
    /// Objects currently live in the target schema (from `drift::Snapshot`),
    /// used by cross-bundle breaking-change detection.
    pub schema_objects: Option<SchemaObjectSet>,
    /// SQL content of other bundles Pending/Running against the same schema.
    pub pending_bundle_sql: Vec<FileBody>,
}

/// One lint observation produced by an analyzer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    /// The analyzer's stable rule identifier.
    pub rule: String,
    pub severity: LintLevel,
    /// Locate the finding in the source. `file` empty / `line` 0 when the
    /// finding is bundle-wide (not statement-specific).
    pub file: String,
    pub line: i32,
    pub column: i32,
    pub message: String,
}

/// A single lint rule. Stateless and concurrency-safe.
pub trait Analyzer: Send + Sync {
    /// The stable rule identifier.
    fn id(&self) -> &'static str;
    /// A short (<256 char) human explanation.
    fn description(&self) -> &'static str;
    /// Runs the rule over the migration and returns findings. The native
    /// rules never fail (the Go signature returns a always-nil error), so
    /// this returns `Vec<Finding>` directly.
    fn check(&self, m: &Migration) -> Vec<Finding>;
}

/// A collection of analyzers.
#[derive(Default)]
pub struct Registry {
    analyzers: Vec<Box<dyn Analyzer>>,
}

impl Registry {
    /// Returns an empty registry.
    pub fn new() -> Self {
        Registry::default()
    }

    /// Adds an analyzer.
    pub fn register(&mut self, a: Box<dyn Analyzer>) {
        self.analyzers.push(a);
    }

    /// Invokes every analyzer and returns the aggregated findings, in
    /// registration order (matching the Go `Registry.Run`).
    pub fn run(&self, m: &Migration) -> Vec<Finding> {
        let mut findings = Vec::new();
        for a in &self.analyzers {
            findings.extend(a.check(m));
        }
        findings
    }

    /// The number of registered analyzers.
    pub fn len(&self) -> usize {
        self.analyzers.len()
    }

    /// Whether the registry has no analyzers.
    pub fn is_empty(&self) -> bool {
        self.analyzers.is_empty()
    }
}

/// Returns a registry populated with the full 53-rule analyzer pack, in the
/// same order as the Go `DefaultRegistry`.
pub fn default_registry() -> Registry {
    let mut r = Registry::new();
    let all: Vec<Box<dyn Analyzer>> = vec![
        // Phase 11.2 base pack — structural safety
        Box::new(rules::NoDropTable),
        Box::new(rules::NoDropColumn),
        Box::new(rules::PreferConcurrentIndexCreation),
        Box::new(rules::RequirePrimaryKey),
        Box::new(rules::NoAlterColumnTypeInPlace),
        Box::new(rules::NoAddRequiredFieldWithoutDefault),
        Box::new(rules::NoTruncate),
        Box::new(rules::NoGrantAll),
        Box::new(rules::RequireStatementTimeoutOnDdl),
        Box::new(rules::NoTransactionAroundConcurrentIndex),
        // Phase 11.3 extended pack
        Box::new(rules_extended::NoSerial),
        Box::new(rules_extended::RequireTimestamptz),
        Box::new(rules_extended::NoReservedIdentifier),
        Box::new(rules_extended::MaxMigrationSize),
        Box::new(rules_extended::NoCascadeDelete),
        Box::new(rules_extended::RequireIndexOnFk),
        Box::new(rules_extended::NoAlterColumnSetStorage),
        Box::new(rules_extended::NoExplicitPublicSchema),
        Box::new(rules_extended::RequireMigrationComment),
        Box::new(rules_extended::NoAlterTableRename),
        // Phase A4 cross-migration
        Box::new(rules_cross::BreakingChangeDetector),
        // Phase A2 — lock-heavy operations
        Box::new(rules_locks::NoAddFkWithoutNotValid),
        Box::new(rules_locks::NoAddCheckWithoutNotValid),
        Box::new(rules_locks::NoUniqueConstraintDirect),
        Box::new(rules_locks::NoSetNotNullDirect),
        Box::new(rules_locks::NoVacuumFull),
        Box::new(rules_locks::NoCluster),
        Box::new(rules_locks::NoReindexWithoutConcurrently),
        Box::new(rules_locks::NoDropIndexWithoutConcurrently),
        Box::new(rules_locks::NoLockTableExplicit),
        // Phase A2 — backward compatibility
        Box::new(rules_compat::NoRenameColumn),
        Box::new(rules_compat::NoRenameConstraint),
        Box::new(rules_compat::NoDropView),
        Box::new(rules_compat::NoDropFunction),
        Box::new(rules_compat::NoDropSequence),
        // Phase A2 — DML safety
        Box::new(rules_data::NoUpdateWithoutWhere),
        Box::new(rules_data::NoDeleteWithoutWhere),
        Box::new(rules_data::NoInsertSelectWithoutWhere),
        Box::new(rules_data::NoLargeValuesList),
        Box::new(rules_data::NoDisableTriggersAll),
        // Phase A2 — transaction / session safety
        Box::new(rules_tx::NoCommitInMigration),
        Box::new(rules_tx::NoRollbackInMigration),
        Box::new(rules_tx::NoSetSessionReplicationRole),
        Box::new(rules_tx::NoSetConstraintsDeferred),
        // Phase A2 — PG type conventions
        Box::new(rules_types::NoVarcharWithoutLimit),
        Box::new(rules_types::PreferJsonbOverJson),
        Box::new(rules_types::NoNumericWithoutPrecision),
        Box::new(rules_types::RequireIfNotExistsOnCreateTable),
        Box::new(rules_types::NoUuidGenerateV1),
        // Phase A2 — identifier hygiene
        Box::new(rules_naming::MaxIdentifierLength),
        Box::new(rules_naming::NoPgPrefixIdentifier),
        // Phase 9.3 — rollback safety
        Box::new(rules_rollback::RequireDownMigration),
        // Phase 9.6 — cross-bundle breaking change detection
        Box::new(rules_crossbundle::CrossBundleBreakDetector),
    ];
    for a in all {
        r.register(a);
    }
    r
}

/// Builds a [`Finding`] convenience helper used across rule modules.
pub(crate) fn finding(
    rule: &str,
    severity: LintLevel,
    file: &str,
    line: i32,
    message: impl Into<String>,
) -> Finding {
    Finding {
        rule: rule.to_string(),
        severity,
        file: file.to_string(),
        line,
        column: 0,
        message: message.into(),
    }
}

/// Groups findings by rule ID — handy in tests.
#[cfg(test)]
pub(crate) fn by_rule(findings: &[Finding]) -> std::collections::BTreeMap<&str, usize> {
    let mut m: std::collections::BTreeMap<&str, usize> = std::collections::BTreeMap::new();
    for f in findings {
        *m.entry(f.rule.as_str()).or_default() += 1;
    }
    m
}

// Re-export the shared helpers for the rule submodules.
pub(crate) use helpers::statement_matches;
pub(crate) use rules_cross::line_of_offset;
pub(crate) use rules_stmtverb::stmt_verb_is;

#[cfg(test)]
mod tests {
    use super::*;

    // Captured from the Go `DefaultRegistry()` — exact order.
    const GOLDEN_IDS: &[&str] = &[
        "no-drop-table",
        "no-drop-column",
        "prefer-concurrent-index-creation",
        "require-primary-key",
        "no-alter-column-type-in-place",
        "no-add-required-field-without-default",
        "no-truncate",
        "no-grant-all",
        "require-statement-timeout-on-ddl",
        "no-transaction-around-concurrent-index",
        "no-serial",
        "require-timestamptz",
        "no-reserved-identifier",
        "max-migration-size",
        "no-cascade-delete-on-fk",
        "require-index-on-fk",
        "no-alter-column-set-storage",
        "no-explicit-public-schema",
        "require-migration-comment",
        "no-alter-table-rename",
        "cross-migration-breaking-change",
        "no-add-fk-without-not-valid",
        "no-add-check-without-not-valid",
        "no-unique-constraint-direct",
        "no-set-not-null-direct",
        "no-vacuum-full",
        "no-cluster",
        "no-reindex-without-concurrently",
        "no-drop-index-without-concurrently",
        "no-lock-table-explicit",
        "no-rename-column",
        "no-rename-constraint",
        "no-drop-view",
        "no-drop-function",
        "no-drop-sequence",
        "no-update-without-where",
        "no-delete-without-where",
        "no-insert-select-without-where",
        "no-large-values-list",
        "no-disable-triggers-all",
        "no-commit-in-migration",
        "no-rollback-in-migration",
        "no-set-session-replication-role",
        "no-set-constraints-deferred",
        "no-varchar-without-limit",
        "prefer-jsonb-over-json",
        "no-numeric-without-precision",
        "require-if-not-exists-on-create-table",
        "no-uuid-generate-v1",
        "max-identifier-length",
        "no-pg-prefix-identifier",
        "require-down-migration",
        "cross-bundle-breaking-change",
    ];

    // The stress migration the Go golden was generated against.
    const STRESS_BODY: &str = r#"-- migration: stress test
CREATE TABLE users (id int);
DROP TABLE legacy;
ALTER TABLE users ADD COLUMN c int NOT NULL;
CREATE INDEX idx_u ON users (c);
TRUNCATE other;
GRANT ALL ON users TO app;
UPDATE users SET c = 1;
DELETE FROM users;
ALTER TABLE users RENAME COLUMN c TO d;
SELECT * FROM public.t;
ts TIMESTAMP;
id BIGSERIAL;
amount NUMERIC;
note VARCHAR;
payload json;
DEFAULT uuid_generate_v1();
VACUUM FULL users;
ALTER TABLE users ADD CONSTRAINT fk FOREIGN KEY (d) REFERENCES p(id);
COMMIT;
"#;

    // Golden findings (rule|severity|file|line|message), exact bytes from the
    // Go `DefaultRegistry().Run` over STRESS_BODY (TargetSchema=tenant_1).
    const GOLDEN_FINDINGS: &str = r#"no-drop-table|error|001_init.up.sql|3|DROP TABLE removes data irrecoverably; use a soft-delete column or schedule via a separate destructive-migration workflow with operator sign-off
prefer-concurrent-index-creation|warning|001_init.up.sql|5|CREATE INDEX without CONCURRENTLY locks writes for the scan. Add CONCURRENTLY unless the table is empty or the migration is in a maintenance window.
require-primary-key|warning|001_init.up.sql|0|file contains CREATE TABLE but no PRIMARY KEY clause detected. Tables without a PK can't be replicated by logical replication or migrated via pgroll.
no-add-required-field-without-default|error|001_init.up.sql|4|ADD COLUMN ... NOT NULL without DEFAULT forces a full-table rewrite. Either add a DEFAULT (PG 11+ instant add) or use kind=add_column with nullable=true + enforceNotNullInContract
no-truncate|error|001_init.up.sql|6|TRUNCATE removes all rows irrecoverably and bypasses ON DELETE triggers. Use DELETE if you need row-level side effects, or policy-override=true if truly intended
no-grant-all|warning|001_init.up.sql|7|GRANT ALL includes future privileges added by PG upgrades. Prefer an explicit privilege list: GRANT SELECT, INSERT, UPDATE, DELETE ...
require-statement-timeout-on-ddl|notice|001_init.up.sql|0|DDL migration without SET LOCAL statement_timeout. Keystone's runner sets a 30s default at pool level, but explicit SET in the migration makes the behaviour visible to reviewers.
no-serial|warning|001_init.up.sql|13|SERIAL/BIGSERIAL/SMALLSERIAL are PostgreSQL pseudo-types backed by a sequence + default. Use GENERATED BY DEFAULT AS IDENTITY (SQL-standard, cleaner ownership semantics on CREATE/DROP)
require-timestamptz|warning|001_init.up.sql|12|TIMESTAMP (without time zone) stores the local clock with no offset. Use TIMESTAMPTZ (alias for TIMESTAMP WITH TIME ZONE) unless you have a specific reason to store naive local time
require-index-on-fk|warning|001_init.up.sql|0|FOREIGN KEY on column d has no detected index. Without one, DELETE on the parent table does a full scan of this table per parent row. Add CREATE INDEX on the FK column.
no-explicit-public-schema|warning|001_init.up.sql|11|hardcoded 'public.table' prefix. Keystone's runner sets search_path=<target_schema>, so unqualified names resolve per-tenant. Explicit 'public' prefix routes writes to the wrong schema in multi-tenant rollouts.
cross-migration-breaking-change|error|001_init.up.sql|10|ALTER TABLE users RENAME COLUMN c TO d breaks clients reading the old name — use add-new-column + backfill + drop-old-column across two bundles
no-add-fk-without-not-valid|warning|001_init.up.sql|19|ALTER TABLE ADD FOREIGN KEY without NOT VALID scans every row under ShareRowExclusive. Two-step: ADD CONSTRAINT … FOREIGN KEY … NOT VALID; then VALIDATE CONSTRAINT (RowExclusive, concurrent-safe).
no-vacuum-full|error|001_init.up.sql|18|VACUUM FULL takes AccessExclusive for the rewrite's duration. For live tables use pg_repack (online equivalent); for one-offs schedule a maintenance window.
no-rename-column|error|001_init.up.sql|10|RENAME COLUMN is atomic and synchronously visible. Every client still referencing the old column name fails. Stage instead: ADD new column → dual-write trigger → backfill → deploy readers → deploy writers → DROP old column.
no-update-without-where|error|001_init.up.sql|8|UPDATE without WHERE rewrites every row. Add a WHERE clause, or if you truly intend to update everything, annotate with `-- update-all:` on the line above and break into a batched migration.
no-delete-without-where|error|001_init.up.sql|9|DELETE without WHERE removes every row and generates row-level triggers for each. Add a WHERE clause; if the intent is to empty the table, consider TRUNCATE (after no-truncate review) or a policy-override annotation.
no-commit-in-migration|error|001_init.up.sql|20|COMMIT inside the migration body splits it into multiple physical transactions. The runner wraps each file in its own transaction; an author-supplied COMMIT makes partial failures non-rollbackable.
no-varchar-without-limit|notice|001_init.up.sql|15|unbounded VARCHAR / CHARACTER VARYING has no advantage over TEXT. Use TEXT when the length is unbounded, VARCHAR(N) when it isn't.
prefer-jsonb-over-json|notice|001_init.up.sql|16|column typed as JSON. JSONB is binary-decomposed, indexable (GIN / path-ops), and parses once at INSERT. JSON preserves whitespace + key order — useful only for strict byte-round-trip.
no-numeric-without-precision|notice|001_init.up.sql|14|unbounded NUMERIC / DECIMAL stores arbitrary-precision digits — slow, heavy, and usually wrong. Declare the intended range: NUMERIC(12, 2) for money, NUMERIC(5, 4) for probabilities, etc.
require-if-not-exists-on-create-table|notice|001_init.up.sql|2|CREATE TABLE without IF NOT EXISTS. Retries after partial failure re-run the whole file — add IF NOT EXISTS to make creation idempotent.
no-uuid-generate-v1|warning|001_init.up.sql|17|uuid_generate_v1 / v1mc encode host MAC address + timestamp, leaking both in every row's identifier. On PG 13+, gen_random_uuid() produces v4 UUIDs with no leakage and no extension required.
require-down-migration|warning||0|no down source configured; if this migration fails, automatic rollback is not possible — only forward-fix. Add spec.downSource with *.down.sql files to enable rollback capability"#;

    #[test]
    fn default_registry_ids_match_go_order() {
        let r = default_registry();
        let ids: Vec<&str> = r.analyzers.iter().map(|a| a.id()).collect();
        assert_eq!(ids, GOLDEN_IDS.to_vec());
        assert_eq!(r.len(), 53);
    }

    #[test]
    fn lint_levels_render() {
        assert_eq!(LintLevel::Error.as_str(), "error");
        assert_eq!(LintLevel::Warning.as_str(), "warning");
        assert_eq!(LintLevel::Notice.as_str(), "notice");
    }

    #[test]
    fn lint_golden_matches_go() {
        let m = Migration {
            bundle_name: "stress".into(),
            version: "001".into(),
            target_schema: "tenant_1".into(),
            files: vec![FileBody {
                name: "001_init.up.sql".into(),
                body: STRESS_BODY.into(),
            }],
            ..Default::default()
        };
        let got = default_registry().run(&m);
        let got_lines: Vec<String> = got
            .iter()
            .map(|f| {
                format!(
                    "{}|{}|{}|{}|{}",
                    f.rule, f.severity, f.file, f.line, f.message
                )
            })
            .collect();
        let want_lines: Vec<&str> = GOLDEN_FINDINGS.split('\n').collect();
        assert_eq!(
            got_lines.len(),
            want_lines.len(),
            "finding count mismatch:\nGOT:\n{}",
            got_lines.join("\n")
        );
        for (i, (g, w)) in got_lines.iter().zip(want_lines.iter()).enumerate() {
            assert_eq!(g, w, "finding {i} mismatch");
        }
    }
}
