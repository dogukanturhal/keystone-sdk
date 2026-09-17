// SPDX-License-Identifier: AGPL-3.0-or-later

package analyze

import (
	"context"
	"regexp"
	"strings"

	keystonev1alpha1 "github.com/dogukanturhal/keystone/api/v1alpha1"
)

// Phase A2 — transaction and session-state rules.
//
// Keystone's runner wraps every migration file in an implicit
// transaction (see internal/migration/runner.go). That invariant is
// load-bearing — on failure the runner rolls back and nothing leaks.
// These rules flag session-state manipulation that breaks that
// invariant (committing / rolling back mid-migration) or bypasses
// trigger-based integrity (session_replication_role, SET CONSTRAINTS
// DEFERRED as an escape hatch).

// -- Rule: no-commit-in-migration --------------------------------------

// NoCommitInMigration flags bare COMMIT inside a migration file. The
// runner owns transaction control; an author-supplied COMMIT splits a
// single logical migration into multiple physical transactions, which
// silently prevents rollback on failure.
type NoCommitInMigration struct{}

func (NoCommitInMigration) ID() string { return "no-commit-in-migration" }
func (NoCommitInMigration) Description() string {
	return "COMMIT inside a migration breaks the runner's rollback invariant"
}

// Match COMMIT on its own line (with optional trailing semicolon).
// Avoid matching 2PC variants like `COMMIT PREPARED 'xid'` which have
// different semantics.
var reCommit = regexp.MustCompile(`(?i)^\s*COMMIT\s*;?\s*(--.*)?$`)

func (a *NoCommitInMigration) Check(_ context.Context, m *Migration) ([]Finding, error) {
	var out []Finding
	for _, f := range m.Files {
		for i, line := range strings.Split(f.Body, "\n") {
			if !reCommit.MatchString(line) {
				continue
			}
			out = append(out, Finding{
				Rule:     a.ID(),
				Severity: keystonev1alpha1.LintLevelError,
				File:     f.Name,
				Line:     int32(i + 1),
				Message: "COMMIT inside the migration body splits it into multiple physical " +
					"transactions. The runner wraps each file in its own transaction; " +
					"an author-supplied COMMIT makes partial failures non-rollbackable.",
			})
		}
	}
	return out, nil
}

// -- Rule: no-rollback-in-migration ------------------------------------

// NoRollbackInMigration mirrors NoCommitInMigration for ROLLBACK. The
// runner rolls back automatically on error; an explicit ROLLBACK inside
// the migration is almost always a leftover debug statement.
type NoRollbackInMigration struct{}

func (NoRollbackInMigration) ID() string { return "no-rollback-in-migration" }
func (NoRollbackInMigration) Description() string {
	return "ROLLBACK inside a migration is almost always a leftover debug statement"
}

var reRollback = regexp.MustCompile(`(?i)^\s*ROLLBACK\s*;?\s*(--.*)?$`)

func (a *NoRollbackInMigration) Check(_ context.Context, m *Migration) ([]Finding, error) {
	var out []Finding
	for _, f := range m.Files {
		for i, line := range strings.Split(f.Body, "\n") {
			if !reRollback.MatchString(line) {
				continue
			}
			out = append(out, Finding{
				Rule:     a.ID(),
				Severity: keystonev1alpha1.LintLevelError,
				File:     f.Name,
				Line:     int32(i + 1),
				Message: "ROLLBACK inside the migration body is a debug remnant. The runner " +
					"rolls back automatically when a statement errors; explicit ROLLBACK " +
					"discards work the author apparently meant to commit.",
			})
		}
	}
	return out, nil
}

// -- Rule: no-set-session-replication-role -----------------------------

// NoSetSessionReplicationRole flags the classic FK-bypass trick
// `SET session_replication_role = replica`. Under that setting,
// user-defined triggers (including FK triggers) don't fire, so an
// INSERT can plant an orphan row that violates every downstream
// invariant.
type NoSetSessionReplicationRole struct{}

func (NoSetSessionReplicationRole) ID() string { return "no-set-session-replication-role" }
func (NoSetSessionReplicationRole) Description() string {
	return "SET session_replication_role bypasses FK and user triggers"
}

var reSessionReplicationRole = regexp.MustCompile(`(?i)\bSET\s+(SESSION\s+|LOCAL\s+)?session_replication_role\b`)

func (a *NoSetSessionReplicationRole) Check(_ context.Context, m *Migration) ([]Finding, error) {
	return statementMatches(m, reSessionReplicationRole, keystonev1alpha1.LintLevelError,
		a.ID(),
		"SET session_replication_role silences every user-defined trigger, "+
			"including FK enforcement. Orphan rows planted this way survive the migration "+
			"and break every downstream invariant. Use CHECK NOT VALID + VALIDATE CONSTRAINT "+
			"if you need a deferred constraint check instead."), nil
}

// -- Rule: no-set-constraints-deferred ---------------------------------

// NoSetConstraintsDeferred flags SET CONSTRAINTS ALL DEFERRED (or its
// named form). Deferring the FK check to COMMIT time is a legitimate
// feature for circular FK inserts, but the blast-radius form
// `SET CONSTRAINTS ALL DEFERRED` is overkill in 99% of cases — it
// defers every constraint, including ones that should fire immediately
// for tight feedback.
type NoSetConstraintsDeferred struct{}

func (NoSetConstraintsDeferred) ID() string { return "no-set-constraints-deferred" }
func (NoSetConstraintsDeferred) Description() string {
	return "SET CONSTRAINTS ALL DEFERRED delays every FK/CHECK validation to COMMIT"
}

var reSetConstraintsDeferred = regexp.MustCompile(`(?i)\bSET\s+CONSTRAINTS\s+ALL\s+DEFERRED\b`)

func (a *NoSetConstraintsDeferred) Check(_ context.Context, m *Migration) ([]Finding, error) {
	return statementMatches(m, reSetConstraintsDeferred, keystonev1alpha1.LintLevelWarning,
		a.ID(),
		"SET CONSTRAINTS ALL DEFERRED postpones every FK/CHECK to COMMIT. "+
			"For circular inserts, defer only the specific constraint: "+
			"`SET CONSTRAINTS <name> DEFERRED`. Wholesale deferral hides errors "+
			"that should fire immediately and makes debugging harder."), nil
}
