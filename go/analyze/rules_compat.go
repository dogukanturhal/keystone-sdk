// SPDX-License-Identifier: AGPL-3.0-or-later

package analyze

import (
	"context"
	"regexp"

	keystonev1alpha1 "github.com/dogukanturhal/keystone/api/v1alpha1"
)

// Phase A2 — backward-compatibility rules.
//
// These rules flag DDL that is atomic from PostgreSQL's perspective but
// fatal from the application's: every client holding a prepared
// statement, cached plan, or code reference by the old name breaks the
// instant the migration commits. Enterprise rollouts stage the change
// across multiple migrations with an alias or deprecation cycle.

// -- Rule: no-rename-column --------------------------------------------

// NoRenameColumn flags ALTER TABLE … RENAME COLUMN. Renames are
// invisible to the column's reference graph — every GORM model, every
// client query, every view using SELECT * over the old alias starts
// erroring at commit.
type NoRenameColumn struct{}

func (NoRenameColumn) ID() string { return "no-rename-column" }
func (NoRenameColumn) Description() string {
	return "ALTER TABLE RENAME COLUMN is synchronously visible; clients using the old name error"
}

var reRenameColumn = regexp.MustCompile(`(?i)\bALTER\s+TABLE\b[^;]*\bRENAME\s+COLUMN\b`)

func (a *NoRenameColumn) Check(_ context.Context, m *Migration) ([]Finding, error) {
	return statementMatches(m, reRenameColumn, keystonev1alpha1.LintLevelError,
		a.ID(),
		"RENAME COLUMN is atomic and synchronously visible. Every client "+
			"still referencing the old column name fails. Stage instead: "+
			"ADD new column → dual-write trigger → backfill → deploy readers → "+
			"deploy writers → DROP old column."), nil
}

// -- Rule: no-rename-constraint ----------------------------------------

// NoRenameConstraint flags ALTER TABLE … RENAME CONSTRAINT. Infra code
// (Atlas diffs, GORM check constraints, monitoring dashboards) often
// keys off constraint names; a rename breaks those references silently.
type NoRenameConstraint struct{}

func (NoRenameConstraint) ID() string { return "no-rename-constraint" }
func (NoRenameConstraint) Description() string {
	return "ALTER TABLE RENAME CONSTRAINT breaks any tooling keyed on the old name"
}

var reRenameConstraint = regexp.MustCompile(`(?i)\bALTER\s+TABLE\b[^;]*\bRENAME\s+CONSTRAINT\b`)

func (a *NoRenameConstraint) Check(_ context.Context, m *Migration) ([]Finding, error) {
	return statementMatches(m, reRenameConstraint, keystonev1alpha1.LintLevelWarning,
		a.ID(),
		"RENAME CONSTRAINT invalidates any diff tool, dashboard, or "+
			"migration history keyed on the old constraint name. If a rename "+
			"is truly necessary, drop and re-add under the new name with the same definition."), nil
}

// -- Rule: no-drop-view ------------------------------------------------

// NoDropView flags DROP VIEW. Views are the PG-native API surface for
// a schema; dropping one breaks every caller. The two-step swap is
// CREATE OR REPLACE VIEW — which PG supports — followed by a deprecation
// window before the old view is retired.
type NoDropView struct{}

func (NoDropView) ID() string { return "no-drop-view" }
func (NoDropView) Description() string {
	return "DROP VIEW breaks every caller; prefer CREATE OR REPLACE + deprecation"
}

var reDropView = regexp.MustCompile(`(?i)\bDROP\s+(MATERIALIZED\s+)?VIEW\b`)

func (a *NoDropView) Check(_ context.Context, m *Migration) ([]Finding, error) {
	return statementMatches(m, reDropView, keystonev1alpha1.LintLevelWarning,
		a.ID(),
		"DROP VIEW breaks every query that uses the view. "+
			"Prefer CREATE OR REPLACE VIEW for compatible shape changes, "+
			"or run a deprecation cycle: rename → new-name view → readers migrate → drop."), nil
}

// -- Rule: no-drop-function --------------------------------------------

// NoDropFunction flags DROP FUNCTION. Stored procedures and functions
// may be called by triggers, views, RLS policies, or application code
// that Keystone can't see. CREATE OR REPLACE is the forward-compatible
// path; DROP + CREATE introduces a visible gap.
type NoDropFunction struct{}

func (NoDropFunction) ID() string { return "no-drop-function" }
func (NoDropFunction) Description() string {
	return "DROP FUNCTION breaks triggers, views, and RLS policies that reference it"
}

var reDropFunction = regexp.MustCompile(`(?i)\bDROP\s+(FUNCTION|PROCEDURE)\b`)

func (a *NoDropFunction) Check(_ context.Context, m *Migration) ([]Finding, error) {
	return statementMatches(m, reDropFunction, keystonev1alpha1.LintLevelWarning,
		a.ID(),
		"DROP FUNCTION/PROCEDURE breaks everything that calls it — triggers, "+
			"views, RLS policies, application code. Use CREATE OR REPLACE for "+
			"in-place updates; DROP only during maintenance windows with full dependency review."), nil
}

// -- Rule: no-drop-sequence --------------------------------------------

// NoDropSequence flags DROP SEQUENCE. Identity columns, DEFAULT
// nextval() expressions, and application code all hold references
// that break on drop. When the backing column has been converted to
// IDENTITY the sequence is owned and dropped automatically — explicit
// DROP SEQUENCE usually means the author didn't mean to.
type NoDropSequence struct{}

func (NoDropSequence) ID() string { return "no-drop-sequence" }
func (NoDropSequence) Description() string {
	return "DROP SEQUENCE breaks DEFAULT nextval() and IDENTITY ownership"
}

var reDropSequence = regexp.MustCompile(`(?i)\bDROP\s+SEQUENCE\b`)

func (a *NoDropSequence) Check(_ context.Context, m *Migration) ([]Finding, error) {
	return statementMatches(m, reDropSequence, keystonev1alpha1.LintLevelWarning,
		a.ID(),
		"DROP SEQUENCE breaks every DEFAULT nextval() expression that references it, "+
			"including columns converted from SERIAL. If you're migrating to "+
			"GENERATED AS IDENTITY, the drop happens automatically when the column changes — "+
			"explicit DROP SEQUENCE is usually unintended."), nil
}
