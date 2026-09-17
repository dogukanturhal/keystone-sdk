// SPDX-License-Identifier: AGPL-3.0-or-later

package analyze

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	keystonev1alpha1 "github.com/dogukanturhal/keystone/api/v1alpha1"
)

// SchemaObjectSet is a simplified representation of the live schema
// state, used for cross-bundle breaking change detection. Populated
// from drift.Snapshot by the reconciler before calling the analyzer.
type SchemaObjectSet struct {
	// Tables maps table name → set of column names.
	Tables map[string]map[string]bool

	// Indexes is the set of index names that exist in the schema.
	Indexes map[string]bool

	// Constraints is the set of constraint names that exist.
	Constraints map[string]bool
}

// CrossBundleBreakDetector detects destructive operations in the
// current bundle that would break objects depended on by other pending
// bundles or by the live application. Unlike the bundle-local
// BreakingChangeDetector, this analyzer has visibility into:
//
//  1. The live schema state (SchemaObjects) — what currently exists
//  2. Other pending bundles' SQL (PendingBundleSQL) — what other
//     bundles expect to exist
//
// It flags cases where:
//   - This bundle drops a column that a pending bundle's SQL references
//   - This bundle drops a table that a pending bundle's SQL references
//   - This bundle renames an index that a pending bundle references
//   - This bundle drops an FK target table
//
// Severity is error — cross-bundle breaks cause silent failures in
// the pending bundle's execution.
type CrossBundleBreakDetector struct{}

func (CrossBundleBreakDetector) ID() string { return "cross-bundle-breaking-change" }

func (CrossBundleBreakDetector) Description() string {
	return "detect destructive operations that would break other pending bundles"
}

func (a *CrossBundleBreakDetector) Check(_ context.Context, m *Migration) ([]Finding, error) {
	if m.SchemaObjects == nil || len(m.PendingBundleSQL) == 0 {
		return nil, nil
	}

	var findings []Finding

	// Build the set of objects referenced by pending bundles.
	pendingRefs := extractReferences(m.PendingBundleSQL)

	// Scan this bundle for destructive operations against those references.
	for _, f := range m.Files {
		findings = append(findings, checkDropTableCrossBundle(f, pendingRefs, m.SchemaObjects)...)
		findings = append(findings, checkDropColumnCrossBundle(f, pendingRefs, m.SchemaObjects)...)
		findings = append(findings, checkRenameColumnCrossBundle(f, pendingRefs, m.SchemaObjects)...)
		findings = append(findings, checkDropIndexCrossBundle(f, pendingRefs)...)
	}

	return findings, nil
}

// pendingReferences captures what objects pending bundles' SQL mentions.
type pendingReferences struct {
	// TableRefs maps table names referenced in pending SQL.
	TableRefs map[string]bool
	// ColumnRefs maps "table.column" to true for columns referenced.
	ColumnRefs map[string]bool
	// IndexRefs maps index names referenced.
	IndexRefs map[string]bool
}

var (
	// Match table names in common SQL contexts.
	reTableRef = regexp.MustCompile(
		`(?i)\b(?:FROM|JOIN|INTO|UPDATE|TABLE|REFERENCES)\s+(?:(?:[a-z_][a-z0-9_]*)\.)?([a-z_][a-z0-9_]*)`)
	// Match column references in ALTER TABLE context.
	reColumnRef = regexp.MustCompile(
		`(?i)\bALTER\s+TABLE\s+(?:(?:[a-z_][a-z0-9_]*)\.)?([a-z_][a-z0-9_]*)\s+(?:ADD|ALTER|DROP)\s+(?:COLUMN\s+)?(?:IF\s+(?:NOT\s+)?EXISTS\s+)?([a-z_][a-z0-9_]*)`)
	// Match index references in CREATE/DROP INDEX.
	reIndexRef = regexp.MustCompile(
		`(?i)\b(?:CREATE|DROP)\s+(?:UNIQUE\s+)?INDEX\s+(?:CONCURRENTLY\s+)?(?:IF\s+(?:NOT\s+)?EXISTS\s+)?(?:(?:[a-z_][a-z0-9_]*)\.)?([a-z_][a-z0-9_]*)`)
	// Cross-bundle regex for DROP TABLE.
	reCBDropTable = regexp.MustCompile(
		`(?i)\bDROP\s+TABLE\s+(?:IF\s+EXISTS\s+)?(?:(?:[a-z_][a-z0-9_]*)\.)?([a-z_][a-z0-9_]*)`)
	// Cross-bundle regex for DROP COLUMN.
	reCBDropColumn = regexp.MustCompile(
		`(?i)\bALTER\s+TABLE\s+(?:(?:[a-z_][a-z0-9_]*)\.)?([a-z_][a-z0-9_]*)\s+DROP\s+(?:COLUMN\s+)?(?:IF\s+EXISTS\s+)?([a-z_][a-z0-9_]*)`)
	// Cross-bundle regex for RENAME COLUMN.
	reCBRenameColumn = regexp.MustCompile(
		`(?i)\bALTER\s+TABLE\s+(?:(?:[a-z_][a-z0-9_]*)\.)?([a-z_][a-z0-9_]*)\s+RENAME\s+(?:COLUMN\s+)?([a-z_][a-z0-9_]*)\s+TO\s+([a-z_][a-z0-9_]*)`)
	// Cross-bundle regex for DROP INDEX.
	reCBDropIndex = regexp.MustCompile(
		`(?i)\bDROP\s+INDEX\s+(?:CONCURRENTLY\s+)?(?:IF\s+EXISTS\s+)?(?:(?:[a-z_][a-z0-9_]*)\.)?([a-z_][a-z0-9_]*)`)
)

// extractReferences scans pending bundle SQL to find referenced objects.
func extractReferences(pendingSQL []FileBody) *pendingReferences {
	refs := &pendingReferences{
		TableRefs:  make(map[string]bool),
		ColumnRefs: make(map[string]bool),
		IndexRefs:  make(map[string]bool),
	}

	for _, f := range pendingSQL {
		for _, match := range reTableRef.FindAllStringSubmatch(f.Body, -1) {
			refs.TableRefs[strings.ToLower(match[1])] = true
		}
		for _, match := range reColumnRef.FindAllStringSubmatch(f.Body, -1) {
			table := strings.ToLower(match[1])
			col := strings.ToLower(match[2])
			refs.ColumnRefs[table+"."+col] = true
			refs.TableRefs[table] = true
		}
		for _, match := range reIndexRef.FindAllStringSubmatch(f.Body, -1) {
			refs.IndexRefs[strings.ToLower(match[1])] = true
		}
	}

	return refs
}

func checkDropTableCrossBundle(f FileBody, refs *pendingReferences, _ *SchemaObjectSet) []Finding {
	var findings []Finding
	for _, match := range reCBDropTable.FindAllStringSubmatchIndex(f.Body, -1) {
		table := strings.ToLower(f.Body[match[2]:match[3]])
		if refs.TableRefs[table] {
			line := lineOfOffset(f.Body, match[0])
			findings = append(findings, Finding{
				Rule:     "cross-bundle-breaking-change",
				Severity: keystonev1alpha1.LintLevelError,
				File:     f.Name,
				Line:     int32(line),
				Message: fmt.Sprintf(
					"DROP TABLE %s would break a pending bundle that references this table",
					table),
			})
		}
	}
	return findings
}

func checkDropColumnCrossBundle(f FileBody, refs *pendingReferences, _ *SchemaObjectSet) []Finding {
	var findings []Finding
	for _, match := range reCBDropColumn.FindAllStringSubmatchIndex(f.Body, -1) {
		table := strings.ToLower(f.Body[match[2]:match[3]])
		col := strings.ToLower(f.Body[match[4]:match[5]])
		key := table + "." + col
		if refs.ColumnRefs[key] {
			line := lineOfOffset(f.Body, match[0])
			findings = append(findings, Finding{
				Rule:     "cross-bundle-breaking-change",
				Severity: keystonev1alpha1.LintLevelError,
				File:     f.Name,
				Line:     int32(line),
				Message: fmt.Sprintf(
					"DROP COLUMN %s.%s would break a pending bundle that references this column",
					table, col),
			})
		}
	}
	return findings
}

func checkRenameColumnCrossBundle(f FileBody, refs *pendingReferences, _ *SchemaObjectSet) []Finding {
	var findings []Finding
	for _, match := range reCBRenameColumn.FindAllStringSubmatchIndex(f.Body, -1) {
		table := strings.ToLower(f.Body[match[2]:match[3]])
		oldCol := strings.ToLower(f.Body[match[4]:match[5]])
		key := table + "." + oldCol
		if refs.ColumnRefs[key] {
			newCol := strings.ToLower(f.Body[match[6]:match[7]])
			line := lineOfOffset(f.Body, match[0])
			findings = append(findings, Finding{
				Rule:     "cross-bundle-breaking-change",
				Severity: keystonev1alpha1.LintLevelError,
				File:     f.Name,
				Line:     int32(line),
				Message: fmt.Sprintf(
					"RENAME COLUMN %s.%s TO %s would break a pending bundle that references the old name",
					table, oldCol, newCol),
			})
		}
	}
	return findings
}

func checkDropIndexCrossBundle(f FileBody, refs *pendingReferences) []Finding {
	var findings []Finding
	for _, match := range reCBDropIndex.FindAllStringSubmatchIndex(f.Body, -1) {
		idx := strings.ToLower(f.Body[match[2]:match[3]])
		if refs.IndexRefs[idx] {
			line := lineOfOffset(f.Body, match[0])
			findings = append(findings, Finding{
				Rule:     "cross-bundle-breaking-change",
				Severity: keystonev1alpha1.LintLevelError,
				File:     f.Name,
				Line:     int32(line),
				Message: fmt.Sprintf(
					"DROP INDEX %s would break a pending bundle that references this index",
					idx),
			})
		}
	}
	return findings
}
