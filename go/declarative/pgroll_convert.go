// SPDX-License-Identifier: AGPL-3.0-or-later

package declarative

import (
	"regexp"
	"strings"

	keystonev1alpha1 "github.com/dogukanturhal/keystone/api/v1alpha1"
)

// PlanToOperations converts a differ Plan's SQL statements into pgroll
// MigrationOperations. This is the bridge between the versioned differ
// (which produces SQL) and the pgroll-expand-contract strategy (which
// needs declarative operations).
//
// Only a subset of SQL patterns can be converted — the function
// returns the converted operations and any statements that couldn't
// be mapped (unconvertible). Callers should warn on unconvertible
// statements.
//
// Supported conversions:
//   - ALTER TABLE ... ADD COLUMN → add_column
//   - ALTER TABLE ... DROP COLUMN → drop_column
//   - ALTER TABLE ... SET NOT NULL → set_not_null
//   - ALTER TABLE ... DROP NOT NULL → drop_not_null
//   - ALTER TABLE ... ADD CONSTRAINT ... NOT VALID → add_constraint
//   - Column type warnings (from differ) → no operation (pgroll needs
//     explicit alter_column_type authored by the operator)
func PlanToOperations(plan *Plan) (ops []keystonev1alpha1.MigrationOperation, unconvertible []string) {
	if plan == nil {
		return nil, nil
	}

	for _, stmt := range plan.Statements {
		if op, ok := convertStatement(stmt); ok {
			ops = append(ops, op)
		} else {
			unconvertible = append(unconvertible, stmt)
		}
	}
	return ops, unconvertible
}

var (
	reAddCol = regexp.MustCompile(
		`(?i)ALTER\s+TABLE\s+(?:\S+\.)?\"?([a-z_][a-z0-9_]*)\"?\s+ADD\s+COLUMN\s+\"?([a-z_][a-z0-9_]*)\"?\s+(\S+)(.*)`)
	reDropCol = regexp.MustCompile(
		`(?i)ALTER\s+TABLE\s+(?:\S+\.)?\"?([a-z_][a-z0-9_]*)\"?\s+DROP\s+COLUMN\s+\"?([a-z_][a-z0-9_]*)\"?`)
	reSetNotNull = regexp.MustCompile(
		`(?i)ALTER\s+TABLE\s+(?:\S+\.)?\"?([a-z_][a-z0-9_]*)\"?\s+ALTER\s+COLUMN\s+\"?([a-z_][a-z0-9_]*)\"?\s+SET\s+NOT\s+NULL`)
	reDropNotNull = regexp.MustCompile(
		`(?i)ALTER\s+TABLE\s+(?:\S+\.)?\"?([a-z_][a-z0-9_]*)\"?\s+ALTER\s+COLUMN\s+\"?([a-z_][a-z0-9_]*)\"?\s+DROP\s+NOT\s+NULL`)
	reAddConstraint = regexp.MustCompile(
		`(?i)ALTER\s+TABLE\s+(?:\S+\.)?\"?([a-z_][a-z0-9_]*)\"?\s+ADD\s+CONSTRAINT\s+\"?([a-z_][a-z0-9_]*)\"?\s+(.+?)\s+NOT\s+VALID`)
)

func convertStatement(stmt string) (keystonev1alpha1.MigrationOperation, bool) {
	stmt = strings.TrimSpace(stmt)

	// ADD COLUMN
	if m := reAddCol.FindStringSubmatch(stmt); m != nil {
		table := m[1]
		colName := m[2]
		colType := m[3]
		rest := strings.TrimSpace(m[4])

		nullable := true
		if strings.Contains(strings.ToUpper(rest), "NOT NULL") {
			nullable = false
		}
		var defaultVal string
		if idx := strings.Index(strings.ToUpper(rest), "DEFAULT "); idx >= 0 {
			defaultVal = strings.TrimSpace(rest[idx+len("DEFAULT "):])
			// Strip trailing NOT NULL if present after default.
			if ni := strings.Index(strings.ToUpper(defaultVal), " NOT NULL"); ni >= 0 {
				defaultVal = strings.TrimSpace(defaultVal[:ni])
			}
		}

		return keystonev1alpha1.MigrationOperation{
			Kind:  keystonev1alpha1.MigrationOperationAddColumn,
			Table: table,
			AddColumn: &keystonev1alpha1.AddColumnOp{
				Name:     colName,
				Type:     colType,
				Default:  defaultVal,
				Nullable: nullable,
			},
		}, true
	}

	// DROP COLUMN
	if m := reDropCol.FindStringSubmatch(stmt); m != nil {
		return keystonev1alpha1.MigrationOperation{
			Kind:  keystonev1alpha1.MigrationOperationDropColumn,
			Table: m[1],
			DropColumn: &keystonev1alpha1.DropColumnOp{
				Name: m[2],
			},
		}, true
	}

	// SET NOT NULL
	if m := reSetNotNull.FindStringSubmatch(stmt); m != nil {
		return keystonev1alpha1.MigrationOperation{
			Kind:  keystonev1alpha1.MigrationOperationSetNotNull,
			Table: m[1],
			SetNotNull: &keystonev1alpha1.SetNotNullOp{
				Column: m[2],
			},
		}, true
	}

	// DROP NOT NULL
	if m := reDropNotNull.FindStringSubmatch(stmt); m != nil {
		return keystonev1alpha1.MigrationOperation{
			Kind:  keystonev1alpha1.MigrationOperationDropNotNull,
			Table: m[1],
			DropNotNull: &keystonev1alpha1.DropNotNullOp{
				Column: m[2],
			},
		}, true
	}

	// ADD CONSTRAINT ... NOT VALID
	if m := reAddConstraint.FindStringSubmatch(stmt); m != nil {
		table := m[1]
		cName := m[2]
		definition := strings.TrimSpace(m[3])

		cType := "check"
		upper := strings.ToUpper(definition)
		if strings.HasPrefix(upper, "FOREIGN KEY") {
			cType = "foreign_key"
		}

		return keystonev1alpha1.MigrationOperation{
			Kind:  keystonev1alpha1.MigrationOperationAddConstraint,
			Table: table,
			AddConstraint: &keystonev1alpha1.AddConstraintOp{
				Name:       cName,
				Type:       cType,
				Definition: definition,
			},
		}, true
	}

	// Anything else is unconvertible.
	return keystonev1alpha1.MigrationOperation{}, false
}
