// SPDX-License-Identifier: AGPL-3.0-or-later

package analyze

import (
	"context"
	"regexp"
	"strings"

	keystonev1alpha1 "github.com/dogukanturhal/keystone/api/v1alpha1"
)

// Phase 11.2 analyzers. Each one is 10-30 LOC — intentionally simple so
// reviewers can audit them easily. Complex rules that need SQL parsing
// (e.g. matching column in ALTER context) are deferred to Phase 11.3
// where we introduce a minimal SQL tokenizer.

// statementMatches returns a finding per file whose content matches re.
func statementMatches(m *Migration, re *regexp.Regexp, sev keystonev1alpha1.LintLevel, rule, msg string) []Finding {
	var out []Finding
	for _, f := range m.Files {
		for i, line := range strings.Split(f.Body, "\n") {
			if re.MatchString(line) {
				out = append(out, Finding{
					Rule:     rule,
					Severity: sev,
					File:     f.Name,
					Line:     int32(i + 1),
					Message:  msg,
				})
			}
		}
	}
	return out
}

// -- Rule: no-drop-table ------------------------------------------------

type NoDropTable struct{}

func (NoDropTable) ID() string { return "no-drop-table" }
func (NoDropTable) Description() string {
	return "refuse DROP TABLE; use soft-delete or retention policy"
}

var reDropTable = regexp.MustCompile(`(?i)\bDROP\s+TABLE\b`)

func (a *NoDropTable) Check(_ context.Context, m *Migration) ([]Finding, error) {
	return statementMatches(m, reDropTable, keystonev1alpha1.LintLevelError,
		a.ID(),
		"DROP TABLE removes data irrecoverably; use a soft-delete column or "+
			"schedule via a separate destructive-migration workflow with operator sign-off"), nil
}

// -- Rule: no-drop-column -----------------------------------------------

type NoDropColumn struct{}

func (NoDropColumn) ID() string { return "no-drop-column" }
func (NoDropColumn) Description() string {
	return "prefer pgroll-expand-contract drop_column over ALTER TABLE DROP COLUMN"
}

var reDropColumn = regexp.MustCompile(`(?i)\bALTER\s+TABLE\b[^;]*\bDROP\s+COLUMN\b`)

func (a *NoDropColumn) Check(_ context.Context, m *Migration) ([]Finding, error) {
	return statementMatches(m, reDropColumn, keystonev1alpha1.LintLevelError,
		a.ID(),
		"ALTER TABLE DROP COLUMN is data-destructive and takes AccessExclusive lock. "+
			"Use strategy=pgroll-expand-contract with kind=drop_column for the two-phase safe drop"), nil
}

// -- Rule: prefer-concurrent-index-creation -----------------------------

type PreferConcurrentIndexCreation struct{}

func (PreferConcurrentIndexCreation) ID() string { return "prefer-concurrent-index-creation" }
func (PreferConcurrentIndexCreation) Description() string {
	return "CREATE INDEX takes ShareLock for the duration; add CONCURRENTLY for zero-downtime"
}

var reCreateIndexConcurrently = regexp.MustCompile(`(?i)\bCREATE\s+(UNIQUE\s+)?INDEX\s+CONCURRENTLY\b`)
var reCreateIndex = regexp.MustCompile(`(?i)\bCREATE\s+(UNIQUE\s+)?INDEX\b`)

func (a *PreferConcurrentIndexCreation) Check(_ context.Context, m *Migration) ([]Finding, error) {
	var out []Finding
	for _, f := range m.Files {
		for i, line := range strings.Split(f.Body, "\n") {
			if reCreateIndex.MatchString(line) && !reCreateIndexConcurrently.MatchString(line) {
				out = append(out, Finding{
					Rule:     a.ID(),
					Severity: keystonev1alpha1.LintLevelWarning,
					File:     f.Name,
					Line:     int32(i + 1),
					Message: "CREATE INDEX without CONCURRENTLY locks writes for the scan. " +
						"Add CONCURRENTLY unless the table is empty or the migration is in a maintenance window.",
				})
			}
		}
	}
	return out, nil
}

// -- Rule: require-primary-key ------------------------------------------

type RequirePrimaryKey struct{}

func (RequirePrimaryKey) ID() string { return "require-primary-key" }
func (RequirePrimaryKey) Description() string {
	return "every CREATE TABLE must declare a PRIMARY KEY"
}

var reCreateTable = regexp.MustCompile(`(?i)\bCREATE\s+TABLE\b`)
var rePrimaryKey = regexp.MustCompile(`(?i)\bPRIMARY\s+KEY\b`)

func (a *RequirePrimaryKey) Check(_ context.Context, m *Migration) ([]Finding, error) {
	var out []Finding
	for _, f := range m.Files {
		// Crude: CREATE TABLE without PRIMARY KEY somewhere in the
		// same file. False negatives (multi-stmt files) and positives
		// (comments) are tolerated — this is a warning, not a block.
		if reCreateTable.MatchString(f.Body) && !rePrimaryKey.MatchString(f.Body) {
			out = append(out, Finding{
				Rule:     a.ID(),
				Severity: keystonev1alpha1.LintLevelWarning,
				File:     f.Name,
				Message: "file contains CREATE TABLE but no PRIMARY KEY clause detected. " +
					"Tables without a PK can't be replicated by logical replication or migrated via pgroll.",
			})
		}
	}
	return out, nil
}

// -- Rule: no-alter-column-type-in-place --------------------------------

type NoAlterColumnTypeInPlace struct{}

func (NoAlterColumnTypeInPlace) ID() string { return "no-alter-column-type-in-place" }
func (NoAlterColumnTypeInPlace) Description() string {
	return "ALTER COLUMN ... TYPE rewrites the table; use pgroll alter_column_type"
}

var reAlterColumnType = regexp.MustCompile(`(?i)\bALTER\s+COLUMN\s+\w+\s+TYPE\b|\bALTER\s+COLUMN\s+\w+\s+SET\s+DATA\s+TYPE\b`)

func (a *NoAlterColumnTypeInPlace) Check(_ context.Context, m *Migration) ([]Finding, error) {
	return statementMatches(m, reAlterColumnType, keystonev1alpha1.LintLevelError,
		a.ID(),
		"ALTER COLUMN TYPE rewrites the table and takes AccessExclusive lock. "+
			"Use strategy=pgroll-expand-contract with kind=alter_column_type for zero-downtime type changes"), nil
}

// -- Rule: no-add-required-field-without-default ------------------------

type NoAddRequiredFieldWithoutDefault struct{}

func (NoAddRequiredFieldWithoutDefault) ID() string { return "no-add-required-field-without-default" }
func (NoAddRequiredFieldWithoutDefault) Description() string {
	return "ADD COLUMN NOT NULL without DEFAULT rewrites every row; add default or allow NULL"
}

var reAddColumnNotNullNoDefault = regexp.MustCompile(`(?i)\bADD\s+COLUMN\s+\w+\s+[A-Za-z]+[^;]*\bNOT\s+NULL\b`)
var reHasDefault = regexp.MustCompile(`(?i)\bDEFAULT\s+\S+`)

func (a *NoAddRequiredFieldWithoutDefault) Check(_ context.Context, m *Migration) ([]Finding, error) {
	var out []Finding
	for _, f := range m.Files {
		for i, line := range strings.Split(f.Body, "\n") {
			if reAddColumnNotNullNoDefault.MatchString(line) && !reHasDefault.MatchString(line) {
				out = append(out, Finding{
					Rule:     a.ID(),
					Severity: keystonev1alpha1.LintLevelError,
					File:     f.Name,
					Line:     int32(i + 1),
					Message: "ADD COLUMN ... NOT NULL without DEFAULT forces a full-table rewrite. " +
						"Either add a DEFAULT (PG 11+ instant add) or use kind=add_column with nullable=true + enforceNotNullInContract",
				})
			}
		}
	}
	return out, nil
}

// -- Rule: no-truncate --------------------------------------------------

type NoTruncate struct{}

func (NoTruncate) ID() string { return "no-truncate" }
func (NoTruncate) Description() string {
	return "TRUNCATE is data-destructive and bypasses DELETE triggers"
}

var reTruncate = regexp.MustCompile(`(?i)\bTRUNCATE\b`)

func (a *NoTruncate) Check(_ context.Context, m *Migration) ([]Finding, error) {
	// Gate: only fire when the containing statement IS a TRUNCATE. The
	// raw `\bTRUNCATE\b` match would otherwise trip on a privilege name
	// in `GRANT SELECT, INSERT, UPDATE, DELETE, TRUNCATE ON TABLE …`
	// (verified live 2026-05-12 on example-service migration 234).
	var out []Finding
	for _, f := range m.Files {
		for _, loc := range reTruncate.FindAllStringIndex(f.Body, -1) {
			if !stmtVerbIs(f.Body, loc[0], "TRUNCATE") {
				continue
			}
			out = append(out, Finding{
				Rule:     a.ID(),
				Severity: keystonev1alpha1.LintLevelError,
				File:     f.Name,
				Line:     int32(lineOfOffset(f.Body, loc[0])),
				Message: "TRUNCATE removes all rows irrecoverably and bypasses ON DELETE triggers. " +
					"Use DELETE if you need row-level side effects, or policy-override=true if truly intended",
			})
		}
	}
	return out, nil
}

// -- Rule: no-grant-all -------------------------------------------------

type NoGrantAll struct{}

func (NoGrantAll) ID() string { return "no-grant-all" }
func (NoGrantAll) Description() string {
	return "GRANT ALL is a privilege-escalation footgun; enumerate the privileges you actually need"
}

var reGrantAll = regexp.MustCompile(`(?i)\bGRANT\s+ALL\b`)

func (a *NoGrantAll) Check(_ context.Context, m *Migration) ([]Finding, error) {
	return statementMatches(m, reGrantAll, keystonev1alpha1.LintLevelWarning,
		a.ID(),
		"GRANT ALL includes future privileges added by PG upgrades. "+
			"Prefer an explicit privilege list: GRANT SELECT, INSERT, UPDATE, DELETE ..."), nil
}

// -- Rule: require-statement-timeout-on-ddl -----------------------------

type RequireStatementTimeoutOnDDL struct{}

func (RequireStatementTimeoutOnDDL) ID() string { return "require-statement-timeout-on-ddl" }
func (RequireStatementTimeoutOnDDL) Description() string {
	return "bare ALTER TABLE without statement_timeout can block forever on lock contention"
}

var reDDL = regexp.MustCompile(`(?i)\b(ALTER|CREATE|DROP)\s+(TABLE|INDEX|CONSTRAINT)\b`)
var reStatementTimeout = regexp.MustCompile(`(?i)\bSET\s+(LOCAL\s+)?statement_timeout\b`)

func (a *RequireStatementTimeoutOnDDL) Check(_ context.Context, m *Migration) ([]Finding, error) {
	var out []Finding
	for _, f := range m.Files {
		if reDDL.MatchString(f.Body) && !reStatementTimeout.MatchString(f.Body) {
			out = append(out, Finding{
				Rule:     a.ID(),
				Severity: keystonev1alpha1.LintLevelNotice,
				File:     f.Name,
				Message: "DDL migration without SET LOCAL statement_timeout. " +
					"Keystone's runner sets a 30s default at pool level, but explicit SET in the migration " +
					"makes the behaviour visible to reviewers.",
			})
		}
	}
	return out, nil
}

// -- Rule: no-transaction-around-concurrent-index ------------------------

type NoTransactionAroundConcurrentIndex struct{}

func (NoTransactionAroundConcurrentIndex) ID() string {
	return "no-transaction-around-concurrent-index"
}
func (NoTransactionAroundConcurrentIndex) Description() string {
	return "CREATE INDEX CONCURRENTLY cannot run inside a transaction block"
}

// reBeginStatement matches an explicit top-level transaction-control BEGIN
// (with or without TRANSACTION/WORK qualifier). Anchored at start-of-line
// after optional whitespace, terminated by `;` or end-of-line. Critically
// this does NOT match PL/pgSQL block-opener BEGIN — which is bare `BEGIN`
// inside a `DO $$ ... $$;` block or function body and has no terminator on
// the same line. Using `(?im)` so `^` anchors per-line and the match is
// case-insensitive.
var reBeginStatement = regexp.MustCompile(`(?im)^\s*BEGIN\s*(?:TRANSACTION|WORK)?\s*;`)

// reDoBlock matches a top-level DO $tag$ ... $tag$; block (where $tag$ is
// either `$$` or a custom dollar-quoted tag like `$func$`). Stripped from
// migration bodies before scanning for transaction-control BEGIN, so the
// PL/pgSQL `BEGIN`/`END` block delimiters inside DO blocks don't confuse
// transaction-control detection. Differ emits idempotent FK creation as
// `DO $$ BEGIN IF NOT EXISTS (...) THEN ALTER TABLE ... END IF; END $$;` —
// without this strip, every such bundle would false-positive
// no-transaction-around-concurrent-index. (?s) makes . span newlines.
//
// Note: Go's regexp (RE2) doesn't support backreferences, so we accept any
// dollar-quoted close tag, not strictly the same one as the open tag. For
// the linter's purpose (avoiding false positives on PL/pgSQL BEGIN) the
// approximation is harmless — in practice the differ emits balanced
// `$$ ... $$` blocks and never nests them.
var reDoBlock = regexp.MustCompile(`(?is)\bDO\s+\$\w*\$.*?\$\w*\$\s*;`)

func (a *NoTransactionAroundConcurrentIndex) Check(_ context.Context, m *Migration) ([]Finding, error) {
	var out []Finding
	for _, f := range m.Files {
		// Strip DO blocks before checking for transaction-control BEGIN.
		// PL/pgSQL `BEGIN` inside `DO $$ ... $$;` is a block opener, not
		// transaction control, and Postgres tolerates it inside the
		// runner's per-file tx. Only EXPLICIT top-level BEGIN/COMMIT
		// would actually break CONCURRENTLY at runtime.
		bodyNoDo := reDoBlock.ReplaceAllString(f.Body, "")
		if reCreateIndexConcurrently.MatchString(bodyNoDo) && reBeginStatement.MatchString(bodyNoDo) {
			out = append(out, Finding{
				Rule:     a.ID(),
				Severity: keystonev1alpha1.LintLevelError,
				File:     f.Name,
				Message: "CREATE INDEX CONCURRENTLY cannot run inside a transaction. " +
					"Move the CONCURRENTLY statement into its own file (Keystone's runner applies each file in its own tx).",
			})
		}
	}
	return out, nil
}
