// SPDX-License-Identifier: AGPL-3.0-or-later

package analyze

import (
	"context"
	"regexp"
	"strings"

	keystonev1alpha1 "github.com/dogukanturhal/keystone/api/v1alpha1"
)

// Phase A2 — data-dependent operation rules.
//
// These rules flag DML inside migrations that either (a) operates on
// every row because a WHERE clause is missing or (b) interacts with
// table-wide invariants (trigger bypass, bulk load). Mistakes here
// translate directly to data loss or lock-contention incidents.

// -- Rule: no-update-without-where -------------------------------------

// NoUpdateWithoutWhere flags bare UPDATE ... SET without a WHERE clause.
// PostgreSQL will happily rewrite every row, which (1) forces a full
// table rewrite, (2) bloats the table by 2x for the duration of the
// old-row cleanup, and (3) is almost never what the author intended.
// The regex is line-ish: it looks for UPDATE / SET on a single logical
// statement up to the statement terminator and refuses to match when
// WHERE is present anywhere in that statement.
type NoUpdateWithoutWhere struct{}

func (NoUpdateWithoutWhere) ID() string { return "no-update-without-where" }
func (NoUpdateWithoutWhere) Description() string {
	return "UPDATE without WHERE rewrites every row"
}

// reUpdateStmt captures one UPDATE statement from the UPDATE keyword to
// the statement terminator `;`. We then post-filter on "does this
// match contain WHERE?".
var reUpdateStmt = regexp.MustCompile(`(?is)\bUPDATE\s+[^;]*;`)
var reHasWhere = regexp.MustCompile(`(?i)\bWHERE\b`)

func (a *NoUpdateWithoutWhere) Check(_ context.Context, m *Migration) ([]Finding, error) {
	var out []Finding
	for _, f := range m.Files {
		for _, loc := range reUpdateStmt.FindAllStringIndex(f.Body, -1) {
			// Gate: only fire when the match begins an actual UPDATE
			// statement. The greedy `\bUPDATE\s+[^;]*;` regex otherwise
			// captures the suffix of any statement that mentions UPDATE,
			// most notably `GRANT … UPDATE … TO role;` — verified live
			// 2026-05-12 on example-service migration 234.
			if !stmtVerbIs(f.Body, loc[0], "UPDATE") {
				continue
			}
			stmt := f.Body[loc[0]:loc[1]]
			if reHasWhere.MatchString(stmt) {
				continue
			}
			out = append(out, Finding{
				Rule:     a.ID(),
				Severity: keystonev1alpha1.LintLevelError,
				File:     f.Name,
				Line:     int32(lineOfOffset(f.Body, loc[0])),
				Message: "UPDATE without WHERE rewrites every row. Add a WHERE clause, or " +
					"if you truly intend to update everything, annotate with " +
					"`-- update-all:` on the line above and break into a batched migration.",
			})
		}
	}
	return out, nil
}

// -- Rule: no-delete-without-where -------------------------------------

// NoDeleteWithoutWhere is the DELETE mirror of NoUpdateWithoutWhere.
// Same shape, same severity — a missing WHERE deletes the entire table.
type NoDeleteWithoutWhere struct{}

func (NoDeleteWithoutWhere) ID() string { return "no-delete-without-where" }
func (NoDeleteWithoutWhere) Description() string {
	return "DELETE without WHERE removes every row"
}

// reDeleteStmt matches DELETE FROM ... up to the terminator. Excludes
// `DELETE` inside string literals by the simple heuristic of anchoring
// on the FROM keyword that DELETE must carry.
var reDeleteStmt = regexp.MustCompile(`(?is)\bDELETE\s+FROM\s+[^;]*;`)

func (a *NoDeleteWithoutWhere) Check(_ context.Context, m *Migration) ([]Finding, error) {
	var out []Finding
	for _, f := range m.Files {
		for _, loc := range reDeleteStmt.FindAllStringIndex(f.Body, -1) {
			// Gate: only fire when the match begins an actual DELETE
			// statement. Today the `DELETE\s+FROM\s+` regex already
			// makes a GRANT-clause false-positive unlikely, but the
			// statement-verb gate is the canonical defense and stays
			// correct if the regex is ever loosened.
			if !stmtVerbIs(f.Body, loc[0], "DELETE") {
				continue
			}
			stmt := f.Body[loc[0]:loc[1]]
			if reHasWhere.MatchString(stmt) {
				continue
			}
			out = append(out, Finding{
				Rule:     a.ID(),
				Severity: keystonev1alpha1.LintLevelError,
				File:     f.Name,
				Line:     int32(lineOfOffset(f.Body, loc[0])),
				Message: "DELETE without WHERE removes every row and generates row-level " +
					"triggers for each. Add a WHERE clause; if the intent is to empty the table, " +
					"consider TRUNCATE (after no-truncate review) or a policy-override annotation.",
			})
		}
	}
	return out, nil
}

// -- Rule: no-insert-select-without-where ------------------------------

// NoInsertSelectWithoutWhere flags INSERT INTO … SELECT … FROM … that
// omits a WHERE clause. Bulk copies from another table are legitimate,
// but doing the copy inside a migration transaction ties the whole
// commit to the source-side scan — often minutes on a large parent.
// The right pattern is batched COPY / INSERT outside the migration
// framework.
type NoInsertSelectWithoutWhere struct{}

func (NoInsertSelectWithoutWhere) ID() string { return "no-insert-select-without-where" }
func (NoInsertSelectWithoutWhere) Description() string {
	return "INSERT … SELECT without WHERE copies the entire source table inside a migration"
}

// Anchor on the INSERT INTO ... SELECT ... FROM pattern; require the
// SELECT to not have a WHERE clause anywhere before the terminator.
var reInsertSelect = regexp.MustCompile(`(?is)\bINSERT\s+INTO\s+\w+(?:\s*\([^)]*\))?\s*SELECT\s+[^;]*?\bFROM\s+\w+[^;]*;`)

func (a *NoInsertSelectWithoutWhere) Check(_ context.Context, m *Migration) ([]Finding, error) {
	var out []Finding
	for _, f := range m.Files {
		for _, loc := range reInsertSelect.FindAllStringIndex(f.Body, -1) {
			stmt := f.Body[loc[0]:loc[1]]
			if reHasWhere.MatchString(stmt) {
				continue
			}
			out = append(out, Finding{
				Rule:     a.ID(),
				Severity: keystonev1alpha1.LintLevelWarning,
				File:     f.Name,
				Line:     int32(lineOfOffset(f.Body, loc[0])),
				Message: "INSERT INTO … SELECT without WHERE copies every row from the source, " +
					"pinning the migration for the scan's duration. Prefer batched COPY " +
					"outside the migration, or paginate with SELECT … WHERE id > $cursor LIMIT N.",
			})
		}
	}
	return out, nil
}

// -- Rule: no-large-values-list ----------------------------------------

// NoLargeValuesList flags INSERT ... VALUES lists with more than a
// threshold number of row tuples. Large VALUES lists parse slowly, lock
// the target table for the duration, and have worse performance than
// COPY. Threshold: 1000 tuples. We count by scanning for ),( pairs.
type NoLargeValuesList struct {
	// MaxRows caps the acceptable row count per VALUES statement.
	// Default 1000.
	MaxRows int
}

func (NoLargeValuesList) ID() string { return "no-large-values-list" }
func (NoLargeValuesList) Description() string {
	return "VALUES lists > 1000 rows should use COPY"
}

var reInsertValues = regexp.MustCompile(`(?is)\bINSERT\s+INTO\s+\w+[^;]*?\bVALUES\b[^;]*;`)
var reValuesTuple = regexp.MustCompile(`\)\s*,\s*\(`)

func (a *NoLargeValuesList) Check(_ context.Context, m *Migration) ([]Finding, error) {
	cap := a.MaxRows
	if cap == 0 {
		cap = 1000
	}
	var out []Finding
	for _, f := range m.Files {
		for _, loc := range reInsertValues.FindAllStringIndex(f.Body, -1) {
			stmt := f.Body[loc[0]:loc[1]]
			// Number of rows = (comma-separated tuple boundaries) + 1.
			tuples := len(reValuesTuple.FindAllStringIndex(stmt, -1)) + 1
			if tuples <= cap {
				continue
			}
			out = append(out, Finding{
				Rule:     a.ID(),
				Severity: keystonev1alpha1.LintLevelNotice,
				File:     f.Name,
				Line:     int32(lineOfOffset(f.Body, loc[0])),
				Message: "INSERT VALUES with " + itoa(tuples) + " row tuples (>" + itoa(cap) + "). " +
					"Large VALUES lists parse slowly and hold the table lock for the duration. " +
					"Use COPY for bulk loads, or split across batches.",
			})
		}
	}
	return out, nil
}

// -- Rule: no-disable-triggers-all -------------------------------------

// NoDisableTriggersAll flags DISABLE TRIGGER ALL (or session_replication
// _role-style FK bypasses done via ALTER TABLE). The most common use
// case is "bulk load without FK checks" — which is exactly when
// corruption sneaks in. If the constraint matters, validate afterward
// with VALIDATE CONSTRAINT.
type NoDisableTriggersAll struct{}

func (NoDisableTriggersAll) ID() string { return "no-disable-triggers-all" }
func (NoDisableTriggersAll) Description() string {
	return "DISABLE TRIGGER ALL bypasses FK / CHECK / audit triggers"
}

var reDisableTriggersAll = regexp.MustCompile(`(?i)\bDISABLE\s+TRIGGER\s+(ALL|USER)\b`)

func (a *NoDisableTriggersAll) Check(_ context.Context, m *Migration) ([]Finding, error) {
	var out []Finding
	for _, f := range m.Files {
		for i, line := range strings.Split(f.Body, "\n") {
			if !reDisableTriggersAll.MatchString(line) {
				continue
			}
			out = append(out, Finding{
				Rule:     a.ID(),
				Severity: keystonev1alpha1.LintLevelError,
				File:     f.Name,
				Line:     int32(i + 1),
				Message: "DISABLE TRIGGER ALL/USER bypasses every trigger including FK and audit. " +
					"Inserts can create orphan rows. If you need a bulk load path, " +
					"use a CHECK NOT VALID + VALIDATE CONSTRAINT pattern instead.",
			})
		}
	}
	return out, nil
}
