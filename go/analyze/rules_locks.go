// SPDX-License-Identifier: AGPL-3.0-or-later

package analyze

import (
	"context"
	"regexp"
	"strings"

	keystonev1alpha1 "github.com/dogukanturhal/keystone/api/v1alpha1"
)

// Phase A2 — lock-heavy operations.
//
// Each rule here flags a DDL/DML construct that takes an
// AccessExclusive or similarly coarse lock on a relation, and suggests
// the PostgreSQL-native pattern that achieves the same outcome without
// blocking concurrent reads/writes. Keystone targets tier-1 production
// where "five seconds of write downtime" is user-visible; the rules
// are calibrated for that audience.

// -- Rule: no-add-fk-without-not-valid ---------------------------------

// NoAddFKWithoutNotValid flags ALTER TABLE … ADD FOREIGN KEY that does
// not carry NOT VALID. A validating ADD FK scans every row under a
// ShareRowExclusive lock; the NOT VALID form is constant-time, and a
// follow-up VALIDATE CONSTRAINT only takes a RowExclusive lock.
type NoAddFKWithoutNotValid struct{}

func (NoAddFKWithoutNotValid) ID() string { return "no-add-fk-without-not-valid" }
func (NoAddFKWithoutNotValid) Description() string {
	return "ALTER TABLE ADD FOREIGN KEY without NOT VALID scans every row under a lock"
}

var reAddForeignKey = regexp.MustCompile(`(?i)\bALTER\s+TABLE\b[^;]*\bADD\s+(?:CONSTRAINT\s+\w+\s+)?FOREIGN\s+KEY\b`)
var reNotValid = regexp.MustCompile(`(?i)\bNOT\s+VALID\b`)

func (a *NoAddFKWithoutNotValid) Check(_ context.Context, m *Migration) ([]Finding, error) {
	var out []Finding
	for _, f := range m.Files {
		// File-level scan: NOT VALID may live on a later line of the
		// same ADD FK statement. False positives for multi-statement
		// files with independent ADD FKs are rare and acceptable.
		locs := reAddForeignKey.FindAllStringIndex(f.Body, -1)
		if len(locs) == 0 {
			continue
		}
		if reNotValid.MatchString(f.Body) {
			continue
		}
		for _, loc := range locs {
			out = append(out, Finding{
				Rule:     a.ID(),
				Severity: keystonev1alpha1.LintLevelWarning,
				File:     f.Name,
				Line:     int32(lineOfOffset(f.Body, loc[0])),
				Message: "ALTER TABLE ADD FOREIGN KEY without NOT VALID scans every row " +
					"under ShareRowExclusive. Two-step: ADD CONSTRAINT … FOREIGN KEY … NOT VALID; " +
					"then VALIDATE CONSTRAINT (RowExclusive, concurrent-safe).",
			})
		}
	}
	return out, nil
}

// -- Rule: no-add-check-without-not-valid ------------------------------

// NoAddCheckWithoutNotValid mirrors the FK rule for CHECK constraints.
// Identical lock behaviour; identical two-step workaround.
type NoAddCheckWithoutNotValid struct{}

func (NoAddCheckWithoutNotValid) ID() string { return "no-add-check-without-not-valid" }
func (NoAddCheckWithoutNotValid) Description() string {
	return "ALTER TABLE ADD CHECK without NOT VALID scans every row under a lock"
}

var reAddCheck = regexp.MustCompile(`(?i)\bALTER\s+TABLE\b[^;]*\bADD\s+(?:CONSTRAINT\s+\w+\s+)?CHECK\s*\(`)

func (a *NoAddCheckWithoutNotValid) Check(_ context.Context, m *Migration) ([]Finding, error) {
	var out []Finding
	for _, f := range m.Files {
		locs := reAddCheck.FindAllStringIndex(f.Body, -1)
		if len(locs) == 0 {
			continue
		}
		if reNotValid.MatchString(f.Body) {
			continue
		}
		for _, loc := range locs {
			out = append(out, Finding{
				Rule:     a.ID(),
				Severity: keystonev1alpha1.LintLevelWarning,
				File:     f.Name,
				Line:     int32(lineOfOffset(f.Body, loc[0])),
				Message: "ALTER TABLE ADD CHECK without NOT VALID validates every row synchronously. " +
					"Two-step: ADD CONSTRAINT … CHECK (…) NOT VALID; then VALIDATE CONSTRAINT.",
			})
		}
	}
	return out, nil
}

// -- Rule: no-unique-constraint-direct ---------------------------------

// NoUniqueConstraintDirect flags ALTER TABLE … ADD CONSTRAINT … UNIQUE
// used *without* the USING INDEX form. Direct ADD UNIQUE builds the
// index under an AccessExclusive lock; the CONCURRENTLY alternative
// (CREATE UNIQUE INDEX CONCURRENTLY + ADD CONSTRAINT … USING INDEX)
// blocks only briefly at the attachment step.
type NoUniqueConstraintDirect struct{}

func (NoUniqueConstraintDirect) ID() string { return "no-unique-constraint-direct" }
func (NoUniqueConstraintDirect) Description() string {
	return "ALTER TABLE ADD CONSTRAINT … UNIQUE without USING INDEX locks writes during build"
}

var reAddUniqueConstraint = regexp.MustCompile(`(?i)\bALTER\s+TABLE\b[^;]*\bADD\s+(?:CONSTRAINT\s+\w+\s+)?UNIQUE\s*\(`)
var reUsingIndex = regexp.MustCompile(`(?i)\bUSING\s+INDEX\b`)

func (a *NoUniqueConstraintDirect) Check(_ context.Context, m *Migration) ([]Finding, error) {
	var out []Finding
	for _, f := range m.Files {
		locs := reAddUniqueConstraint.FindAllStringIndex(f.Body, -1)
		if len(locs) == 0 {
			continue
		}
		// If the file already uses USING INDEX anywhere, assume the
		// author is following the two-step pattern.
		if reUsingIndex.MatchString(f.Body) {
			continue
		}
		for _, loc := range locs {
			out = append(out, Finding{
				Rule:     a.ID(),
				Severity: keystonev1alpha1.LintLevelWarning,
				File:     f.Name,
				Line:     int32(lineOfOffset(f.Body, loc[0])),
				Message: "Direct ADD UNIQUE builds the backing index under AccessExclusive. " +
					"Two-step: CREATE UNIQUE INDEX CONCURRENTLY idx ON t(col); " +
					"ALTER TABLE t ADD CONSTRAINT c UNIQUE USING INDEX idx;",
			})
		}
	}
	return out, nil
}

// -- Rule: no-set-not-null-direct --------------------------------------

// NoSetNotNullDirect flags ALTER COLUMN … SET NOT NULL without an
// accompanying CHECK NOT VALID helper. The direct form scans every
// row under AccessExclusive; the workaround on PG 12+ is to add a
// CHECK (col IS NOT NULL) NOT VALID, VALIDATE it, then SET NOT NULL
// (which then recognises the proven constraint and is near-instant).
type NoSetNotNullDirect struct{}

func (NoSetNotNullDirect) ID() string { return "no-set-not-null-direct" }
func (NoSetNotNullDirect) Description() string {
	return "ALTER COLUMN SET NOT NULL scans every row under AccessExclusive"
}

var reSetNotNull = regexp.MustCompile(`(?i)\bALTER\s+COLUMN\s+\w+\s+SET\s+NOT\s+NULL\b`)
var reCheckIsNotNull = regexp.MustCompile(`(?i)\bCHECK\s*\(\s*\w+\s+IS\s+NOT\s+NULL\s*\)\s*NOT\s+VALID\b`)

func (a *NoSetNotNullDirect) Check(_ context.Context, m *Migration) ([]Finding, error) {
	var out []Finding
	for _, f := range m.Files {
		locs := reSetNotNull.FindAllStringIndex(f.Body, -1)
		if len(locs) == 0 {
			continue
		}
		// Author who set up the CHECK NOT VALID helper is already
		// following the recommended pattern — don't double-warn.
		if reCheckIsNotNull.MatchString(f.Body) {
			continue
		}
		for _, loc := range locs {
			out = append(out, Finding{
				Rule:     a.ID(),
				Severity: keystonev1alpha1.LintLevelWarning,
				File:     f.Name,
				Line:     int32(lineOfOffset(f.Body, loc[0])),
				Message: "ALTER COLUMN SET NOT NULL scans every row under AccessExclusive. " +
					"On PG 12+: ADD CHECK (col IS NOT NULL) NOT VALID; VALIDATE CONSTRAINT; " +
					"SET NOT NULL (now instant because the CHECK is proven).",
			})
		}
	}
	return out, nil
}

// -- Rule: no-vacuum-full ----------------------------------------------

// NoVacuumFull flags VACUUM FULL inside a migration. It takes an
// AccessExclusive lock on the relation for the rewrite's duration,
// which is proportional to table size. pg_repack does the same work
// online.
type NoVacuumFull struct{}

func (NoVacuumFull) ID() string { return "no-vacuum-full" }
func (NoVacuumFull) Description() string {
	return "VACUUM FULL rewrites the table under AccessExclusive; use pg_repack instead"
}

var reVacuumFull = regexp.MustCompile(`(?i)\bVACUUM\s+FULL\b`)

func (a *NoVacuumFull) Check(_ context.Context, m *Migration) ([]Finding, error) {
	return statementMatches(m, reVacuumFull, keystonev1alpha1.LintLevelError,
		a.ID(),
		"VACUUM FULL takes AccessExclusive for the rewrite's duration. "+
			"For live tables use pg_repack (online equivalent); for one-offs schedule a maintenance window."), nil
}

// -- Rule: no-cluster --------------------------------------------------

// NoCluster flags the CLUSTER command. Same lock semantics as VACUUM
// FULL; same recommendation.
type NoCluster struct{}

func (NoCluster) ID() string { return "no-cluster" }
func (NoCluster) Description() string {
	return "CLUSTER rewrites the table under AccessExclusive"
}

var reCluster = regexp.MustCompile(`(?i)^\s*CLUSTER\b|\bCLUSTER\s+\w+\s+USING\b`)

func (a *NoCluster) Check(_ context.Context, m *Migration) ([]Finding, error) {
	var out []Finding
	for _, f := range m.Files {
		for i, line := range strings.Split(f.Body, "\n") {
			if reCluster.MatchString(line) {
				out = append(out, Finding{
					Rule:     a.ID(),
					Severity: keystonev1alpha1.LintLevelError,
					File:     f.Name,
					Line:     int32(i + 1),
					Message: "CLUSTER rewrites the table under AccessExclusive. " +
						"Use pg_repack for online equivalent; reserve CLUSTER for maintenance windows.",
				})
			}
		}
	}
	return out, nil
}

// -- Rule: no-reindex-without-concurrently -----------------------------

// NoReindexWithoutConcurrently flags REINDEX TABLE/INDEX without
// CONCURRENTLY (PG 12+). The non-CONCURRENTLY form locks writes.
type NoReindexWithoutConcurrently struct{}

func (NoReindexWithoutConcurrently) ID() string { return "no-reindex-without-concurrently" }
func (NoReindexWithoutConcurrently) Description() string {
	return "REINDEX without CONCURRENTLY blocks writes for the rebuild"
}

var reReindex = regexp.MustCompile(`(?i)\bREINDEX\s+(TABLE|INDEX|SCHEMA|DATABASE|SYSTEM)\b`)
var reReindexConcurrently = regexp.MustCompile(`(?i)\bREINDEX\s+(TABLE|INDEX|SCHEMA|DATABASE|SYSTEM)\s+CONCURRENTLY\b`)

func (a *NoReindexWithoutConcurrently) Check(_ context.Context, m *Migration) ([]Finding, error) {
	var out []Finding
	for _, f := range m.Files {
		for i, line := range strings.Split(f.Body, "\n") {
			if !reReindex.MatchString(line) {
				continue
			}
			if reReindexConcurrently.MatchString(line) {
				continue
			}
			out = append(out, Finding{
				Rule:     a.ID(),
				Severity: keystonev1alpha1.LintLevelWarning,
				File:     f.Name,
				Line:     int32(i + 1),
				Message: "REINDEX without CONCURRENTLY takes an exclusive lock for the rebuild's duration. " +
					"Use REINDEX ... CONCURRENTLY on PG 12+ for an online rebuild.",
			})
		}
	}
	return out, nil
}

// -- Rule: no-drop-index-without-concurrently --------------------------

// NoDropIndexWithoutConcurrently flags DROP INDEX without CONCURRENTLY.
// DROP INDEX takes an AccessExclusive lock on the parent table for the
// brief metadata flip; CONCURRENTLY widens that window but avoids
// holding the lock while physical cleanup happens. On hot tables the
// difference is user-visible.
type NoDropIndexWithoutConcurrently struct{}

func (NoDropIndexWithoutConcurrently) ID() string { return "no-drop-index-without-concurrently" }
func (NoDropIndexWithoutConcurrently) Description() string {
	return "DROP INDEX without CONCURRENTLY takes AccessExclusive on the parent table"
}

var reDropIndex = regexp.MustCompile(`(?i)\bDROP\s+INDEX\b`)
var reDropIndexConcurrently = regexp.MustCompile(`(?i)\bDROP\s+INDEX\s+CONCURRENTLY\b`)

func (a *NoDropIndexWithoutConcurrently) Check(_ context.Context, m *Migration) ([]Finding, error) {
	var out []Finding
	for _, f := range m.Files {
		for i, line := range strings.Split(f.Body, "\n") {
			if !reDropIndex.MatchString(line) {
				continue
			}
			if reDropIndexConcurrently.MatchString(line) {
				continue
			}
			out = append(out, Finding{
				Rule:     a.ID(),
				Severity: keystonev1alpha1.LintLevelWarning,
				File:     f.Name,
				Line:     int32(i + 1),
				Message: "DROP INDEX without CONCURRENTLY takes AccessExclusive on the parent. " +
					"Use DROP INDEX CONCURRENTLY to drop without blocking concurrent writes.",
			})
		}
	}
	return out, nil
}

// -- Rule: no-lock-table-explicit --------------------------------------

// NoLockTableExplicit flags explicit LOCK TABLE statements. PostgreSQL
// acquires the minimum lock level it needs; explicit LOCK TABLE almost
// always means the author is working around a symptom instead of
// fixing the root cause (concurrent migration, missing index, etc.).
type NoLockTableExplicit struct{}

func (NoLockTableExplicit) ID() string { return "no-lock-table-explicit" }
func (NoLockTableExplicit) Description() string {
	return "LOCK TABLE is rarely the right answer; prefer transactional semantics"
}

var reLockTable = regexp.MustCompile(`(?i)\bLOCK\s+TABLE\b`)

func (a *NoLockTableExplicit) Check(_ context.Context, m *Migration) ([]Finding, error) {
	return statementMatches(m, reLockTable, keystonev1alpha1.LintLevelWarning,
		a.ID(),
		"Explicit LOCK TABLE is almost always a workaround. "+
			"PostgreSQL's transaction machinery acquires the minimum lock; "+
			"if you truly need an exclusive lock, consider restructuring the migration."), nil
}
