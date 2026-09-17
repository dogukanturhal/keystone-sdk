// SPDX-License-Identifier: AGPL-3.0-or-later

package analyze

import (
	"context"
	"regexp"
	"strings"

	keystonev1alpha1 "github.com/dogukanturhal/keystone/api/v1alpha1"
)

// Cross-migration analyzers (Phase A4).
//
// Unlike the per-file analyzers in rules.go / rules_extended.go, these
// walk the bundle's SQL files in apply order and track schema evolution
// across them. The payoff: catching cases where a single bundle
// introduces a column/index/table and later breaks it — a pattern the
// per-file analyzers can't see.
//
// Scope is intentionally narrow: only bundle-local state is tracked.
// Cross-bundle breaking changes (a later bundle dropping a column
// created in an earlier one) aren't caught here — they belong to a
// future schema-history analyzer that consults apply history.

// -- Rule: cross-migration-breaking-change ------------------------------

// BreakingChangeDetector walks a bundle's SQL files in order and flags
// destructive operations against objects the same bundle just created.
// Severity is error — if you genuinely need to rename or drop within a
// single bundle, use two bundles with a deprecation window between
// them, or switch to pgroll-expand-contract.
type BreakingChangeDetector struct{}

func (BreakingChangeDetector) ID() string { return "cross-migration-breaking-change" }

func (BreakingChangeDetector) Description() string {
	return "flag DROP/RENAME/ALTER COLUMN TYPE against objects created earlier in the same bundle"
}

// Regexes kept intentionally permissive — a false positive is a lint
// warning a human reads; a false negative is silent breakage.
var (
	reCreateTableX4 = regexp.MustCompile(
		`(?is)\bCREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?(?:(?:[a-z_][a-z0-9_]*)\.)?([a-z_][a-z0-9_]*)\s*\(([^;]*?)\)\s*;`)
	reAlterTableAdd = regexp.MustCompile(
		`(?i)\bALTER\s+TABLE\s+(?:(?:[a-z_][a-z0-9_]*)\.)?([a-z_][a-z0-9_]*)\s+ADD\s+(?:COLUMN\s+)?(?:IF\s+NOT\s+EXISTS\s+)?([a-z_][a-z0-9_]*)`)
	reAlterTableDrop = regexp.MustCompile(
		`(?i)\bALTER\s+TABLE\s+(?:(?:[a-z_][a-z0-9_]*)\.)?([a-z_][a-z0-9_]*)\s+DROP\s+(?:COLUMN\s+)?(?:IF\s+EXISTS\s+)?([a-z_][a-z0-9_]*)`)
	reAlterTableRenameCol = regexp.MustCompile(
		`(?i)\bALTER\s+TABLE\s+(?:(?:[a-z_][a-z0-9_]*)\.)?([a-z_][a-z0-9_]*)\s+RENAME\s+(?:COLUMN\s+)?([a-z_][a-z0-9_]*)\s+TO\s+([a-z_][a-z0-9_]*)`)
	reAlterTableAlterType = regexp.MustCompile(
		`(?i)\bALTER\s+TABLE\s+(?:(?:[a-z_][a-z0-9_]*)\.)?([a-z_][a-z0-9_]*)\s+ALTER\s+(?:COLUMN\s+)?([a-z_][a-z0-9_]*)\s+(?:SET\s+DATA\s+)?TYPE\b`)
	reDropTableX4 = regexp.MustCompile(
		`(?i)\bDROP\s+TABLE\s+(?:IF\s+EXISTS\s+)?(?:(?:[a-z_][a-z0-9_]*)\.)?([a-z_][a-z0-9_]*)`)
	reColumnIdent = regexp.MustCompile(`(?m)^\s*([a-z_][a-z0-9_]*)\s+[a-z]`)
)

// isSubcommandKeyword reports whether ident is an ALTER TABLE subcommand
// keyword rather than a column name.
//
// The ALTER TABLE regexes above make `COLUMN` optional, because PostgreSQL
// does, so the identifier they capture after ADD/DROP/RENAME is only a column
// when the subcommand is a table-level column operation. That turns the
// ordinary CHECK-widening idiom
//
//	ALTER TABLE t DROP CONSTRAINT IF EXISTS t_kind_check;
//	ALTER TABLE t ADD CONSTRAINT t_kind_check CHECK (kind IN (...));
//
// into a self-inflicted error finding: the ADD registers a phantom column
// named `constraint`, and the DROP then reports "removes a column the same
// bundle introduced". Every widening of an enumerated CHECK trips it.
//
// Keyed by verb rather than pooled, so the skip is as narrow as possible.
// These are reserved words in PostgreSQL, so a real column of the same name
// could only be written quoted — and a quoted identifier does not match the
// unquoted `[a-z_]` capture in the first place.
func isSubcommandKeyword(verb, ident string) bool {
	switch verb {
	case "add":
		// ADD CONSTRAINT / PRIMARY KEY / UNIQUE / FOREIGN KEY / CHECK / EXCLUDE
		switch ident {
		case "constraint", "primary", "unique", "foreign", "check", "exclude":
			return true
		}
		return false
	case "drop", "rename":
		// DROP CONSTRAINT is the only table-level DROP that is not a column;
		// DROP DEFAULT / NOT NULL are reachable only via ALTER COLUMN, which
		// these regexes do not match.
		return ident == "constraint"
	}
	return false
}

// Check walks the bundle's files in apply order, maintains a set of
// {table → column set} created earlier in the bundle, and reports any
// destructive operation against that set.
func (a *BreakingChangeDetector) Check(_ context.Context, m *Migration) ([]Finding, error) {
	tables := make(map[string]map[string]bool)
	out := make([]Finding, 0)

	for _, f := range m.Files {
		// 1) CREATE TABLE — harvest the column list.
		for _, match := range reCreateTableX4.FindAllStringSubmatch(f.Body, -1) {
			table := strings.ToLower(match[1])
			cols := parseColumnList(match[2])
			if tables[table] == nil {
				tables[table] = make(map[string]bool)
			}
			for _, c := range cols {
				tables[table][c] = true
			}
		}

		// 2) ALTER TABLE ADD COLUMN — extend the column set.
		for _, match := range reAlterTableAdd.FindAllStringSubmatch(f.Body, -1) {
			table := strings.ToLower(match[1])
			col := strings.ToLower(match[2])
			if isSubcommandKeyword("add", col) {
				continue
			}
			if tables[table] == nil {
				// Table wasn't created in this bundle; nothing to track.
				continue
			}
			tables[table][col] = true
		}

		// 3) ALTER TABLE DROP COLUMN — destructive against bundle-local state.
		line := 0
		for _, match := range reAlterTableDrop.FindAllStringSubmatchIndex(f.Body, -1) {
			table := strings.ToLower(f.Body[match[2]:match[3]])
			col := strings.ToLower(f.Body[match[4]:match[5]])
			if isSubcommandKeyword("drop", col) {
				continue
			}
			if colSet, ok := tables[table]; ok && colSet[col] {
				line = lineOfOffset(f.Body, match[0])
				out = append(out, Finding{
					Rule:     a.ID(),
					Severity: keystonev1alpha1.LintLevelError,
					File:     f.Name,
					Line:     int32(line),
					Message: "ALTER TABLE " + table + " DROP COLUMN " + col +
						" removes a column the same bundle introduced — " +
						"split into two bundles with a deprecation window or use pgroll-expand-contract",
				})
			}
		}

		// 4) ALTER TABLE RENAME COLUMN — always a client break.
		for _, match := range reAlterTableRenameCol.FindAllStringSubmatchIndex(f.Body, -1) {
			table := strings.ToLower(f.Body[match[2]:match[3]])
			oldCol := strings.ToLower(f.Body[match[4]:match[5]])
			newCol := strings.ToLower(f.Body[match[6]:match[7]])
			if isSubcommandKeyword("rename", oldCol) {
				continue
			}
			if colSet, ok := tables[table]; ok && colSet[oldCol] {
				line = lineOfOffset(f.Body, match[0])
				out = append(out, Finding{
					Rule:     a.ID(),
					Severity: keystonev1alpha1.LintLevelError,
					File:     f.Name,
					Line:     int32(line),
					Message: "ALTER TABLE " + table + " RENAME COLUMN " + oldCol + " TO " + newCol +
						" breaks clients reading the old name — use add-new-column + backfill + drop-old-column across two bundles",
				})
				// Track the rename so subsequent drops of new_col in this
				// bundle are also flagged.
				delete(colSet, oldCol)
				colSet[newCol] = true
			}
		}

		// 5) ALTER TABLE ALTER COLUMN TYPE — a rewrite under the hood.
		for _, match := range reAlterTableAlterType.FindAllStringSubmatchIndex(f.Body, -1) {
			table := strings.ToLower(f.Body[match[2]:match[3]])
			col := strings.ToLower(f.Body[match[4]:match[5]])
			if colSet, ok := tables[table]; ok && colSet[col] {
				line = lineOfOffset(f.Body, match[0])
				out = append(out, Finding{
					Rule:     a.ID(),
					Severity: keystonev1alpha1.LintLevelError,
					File:     f.Name,
					Line:     int32(line),
					Message: "ALTER TABLE " + table + " ALTER COLUMN " + col + " TYPE … " +
						"is a full-table rewrite against a column the same bundle introduced — " +
						"get the type right in the CREATE TABLE, or split into an expand/contract pair",
				})
			}
		}

		// 6) DROP TABLE that the same bundle CREATEd — almost always a
		// sign of a developer walking back a change mid-authoring. Still
		// flag it so reviewers notice.
		for _, match := range reDropTableX4.FindAllStringSubmatchIndex(f.Body, -1) {
			table := strings.ToLower(f.Body[match[2]:match[3]])
			if _, ok := tables[table]; ok {
				line = lineOfOffset(f.Body, match[0])
				out = append(out, Finding{
					Rule:     a.ID(),
					Severity: keystonev1alpha1.LintLevelError,
					File:     f.Name,
					Line:     int32(line),
					Message: "DROP TABLE " + table + " removes a table the same bundle CREATEd — " +
						"delete the CREATE TABLE and ship a clean bundle instead of creating-then-dropping",
				})
				delete(tables, table)
			}
		}
	}

	return out, nil
}

// parseColumnList extracts column names from the body of a CREATE TABLE
// (...) statement. Kept pragmatic — we split on commas at depth 0 and
// take the first identifier on each line. Multi-column constraints like
// PRIMARY KEY (a, b) produce spurious matches which are harmless for
// breaking-change detection (those names aren't tracked against
// destructive ops anyway — constraints aren't columns).
func parseColumnList(body string) []string {
	segments := splitCommaDepth0(body)
	out := make([]string, 0, len(segments))
	for _, seg := range segments {
		seg = strings.TrimSpace(seg)
		upper := strings.ToUpper(seg)
		// Skip constraint-only segments; they don't declare columns.
		if strings.HasPrefix(upper, "PRIMARY KEY") ||
			strings.HasPrefix(upper, "UNIQUE") ||
			strings.HasPrefix(upper, "CHECK") ||
			strings.HasPrefix(upper, "FOREIGN KEY") ||
			strings.HasPrefix(upper, "CONSTRAINT") {
			continue
		}
		if match := reColumnIdent.FindStringSubmatch(seg + "\n"); len(match) > 0 {
			out = append(out, strings.ToLower(match[1]))
		}
	}
	return out
}

// splitCommaDepth0 splits s on commas that sit outside any parentheses.
func splitCommaDepth0(s string) []string {
	var out []string
	depth := 0
	start := 0
	for i, r := range s {
		switch r {
		case '(':
			depth++
		case ')':
			depth--
		case ',':
			if depth == 0 {
				out = append(out, s[start:i])
				start = i + 1
			}
		}
	}
	if start < len(s) {
		out = append(out, s[start:])
	}
	return out
}

// lineOfOffset returns the 1-based line number for a byte offset in body.
func lineOfOffset(body string, off int) int {
	if off > len(body) {
		off = len(body)
	}
	return 1 + strings.Count(body[:off], "\n")
}
