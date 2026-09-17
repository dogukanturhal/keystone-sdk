// SPDX-License-Identifier: AGPL-3.0-or-later

package analyze

import (
	"context"

	keystonev1alpha1 "github.com/dogukanturhal/keystone/api/v1alpha1"
)

// -- Rule: require-down-migration -----------------------------------------

// RequireDownMigration warns when a versioned MigrationBundle does not
// have a downSource configured. Without a down source, the only
// recovery option on failure is a forward-fix — no automatic rollback
// is possible.
//
// Severity is warning (not error) because forward-fix is a legitimate
// strategy. Operators can suppress this per SchemaPolicy when they
// decide forward-fix is sufficient for their risk tier.
type RequireDownMigration struct{}

func (RequireDownMigration) ID() string { return "require-down-migration" }
func (RequireDownMigration) Description() string {
	return "warn when a versioned migration has no down source for rollback"
}

func (a *RequireDownMigration) Check(_ context.Context, m *Migration) ([]Finding, error) {
	// Only applies to versioned strategy — pgroll-expand-contract has
	// built-in abort handlers, and declarative diffs auto-generate
	// reverse SQL.
	if m.Strategy != "" && m.Strategy != string(keystonev1alpha1.StrategyVersioned) {
		return nil, nil
	}

	// Skip if no SQL files (operation-based bundle).
	if len(m.Files) == 0 {
		return nil, nil
	}

	if m.HasDownSource {
		return nil, nil
	}

	return []Finding{{
		Rule:     a.ID(),
		Severity: keystonev1alpha1.LintLevelWarning,
		Message: "no down source configured; if this migration fails, automatic rollback " +
			"is not possible — only forward-fix. Add spec.downSource with *.down.sql files " +
			"to enable rollback capability",
	}}, nil
}
