// SPDX-License-Identifier: AGPL-3.0-or-later

package declarative

import (
	"strings"
	"testing"

	"github.com/dogukanturhal/keystone-sdk/go/drift"
	keystonev1alpha1 "github.com/dogukanturhal/keystone/api/v1alpha1"
)

// planWith runs diffRLS over a single table against a given observed state.
// A nil snapshot means greenfield: nothing is known about the table, which is
// also what every caller saw before diffRLS consulted the snapshot at all.
func planWith(t *testing.T, observed *drift.Snapshot, table keystonev1alpha1.DesiredTable) *Plan {
	t.Helper()
	plan := &Plan{}
	diffRLS(plan, "public", observed, &keystonev1alpha1.SchemaDefinitionSpec{
		Tables: []keystonev1alpha1.DesiredTable{table},
	})
	return plan
}

// planFor returns the emitted SQL for a table nothing is known about.
func planFor(t *testing.T, table keystonev1alpha1.DesiredTable) []string {
	t.Helper()
	return planWith(t, nil, table).Statements
}

// reverseFor returns the rollback SQL, index-aligned with planFor.
func reverseFor(t *testing.T, table keystonev1alpha1.DesiredTable) []string {
	t.Helper()
	return planWith(t, nil, table).ReverseStatements
}

// seen builds an observed snapshot holding one table in a known RLS state.
// forced is three-valued: nil is a snapshot written before the FORCE bit was
// recorded, not a table that is unforced.
func seen(name string, enabled bool, forced *bool) *drift.Snapshot {
	return &drift.Snapshot{
		Schema: "public",
		Tables: []drift.TableShape{{
			Name:       name,
			Kind:       "BASE TABLE",
			RLSEnabled: enabled,
			RLSForced:  forced,
		}},
	}
}

func contains(steps []string, substr string) bool {
	for _, s := range steps {
		if strings.Contains(s, substr) {
			return true
		}
	}
	return false
}

func boolPtr(b bool) *bool { return &b }

// A SchemaDefinition written before forceRLS existed leaves it unset. Those
// definitions were being FORCE-d unconditionally, so unset has to keep
// meaning forced — otherwise adding the field would silently strip
// owner-side enforcement from every table already deployed.
func TestForceRLSUnsetStillForces(t *testing.T) {
	steps := planFor(t, keystonev1alpha1.DesiredTable{Name: "messages", EnableRLS: true})
	if !contains(steps, "ENABLE ROW LEVEL SECURITY") {
		t.Errorf("expected ENABLE, got %v", steps)
	}
	if !contains(steps, "FORCE ROW LEVEL SECURITY") {
		t.Fatalf("unset forceRLS must still FORCE (backward compatibility), got %v", steps)
	}
	if contains(steps, "NO FORCE ROW LEVEL SECURITY") {
		t.Errorf("unset forceRLS must not emit NO FORCE, got %v", steps)
	}
}

func TestForceRLSTrueForces(t *testing.T) {
	steps := planFor(t, keystonev1alpha1.DesiredTable{
		Name: "messages", EnableRLS: true, ForceRLS: boolPtr(true),
	})
	if !contains(steps, "FORCE ROW LEVEL SECURITY") || contains(steps, "NO FORCE") {
		t.Fatalf("expected FORCE, got %v", steps)
	}
}

// Explicit false has to emit NO FORCE rather than emitting nothing: a table
// that was previously forced must converge, not be left as it happens to be.
func TestForceRLSFalseEmitsNoForce(t *testing.T) {
	steps := planFor(t, keystonev1alpha1.DesiredTable{
		Name: "messages", EnableRLS: true, ForceRLS: boolPtr(false),
	})
	if !contains(steps, "ENABLE ROW LEVEL SECURITY") {
		t.Errorf("expected ENABLE to still be emitted, got %v", steps)
	}
	if !contains(steps, "NO FORCE ROW LEVEL SECURITY") {
		t.Fatalf("explicit forceRLS=false must emit NO FORCE so the table converges, got %v", steps)
	}
}

// Plan.ReverseStatements is index-aligned rollback SQL. The rollback of
// "NO FORCE" is "FORCE" — inverted relative to the default branch, so it is
// worth pinning: a rollback that re-applied NO FORCE would turn an undo into
// a second way to lose owner-side enforcement.
func TestForceRLSFalseReversesToForce(t *testing.T) {
	rev := reverseFor(t, keystonev1alpha1.DesiredTable{
		Name: "messages", EnableRLS: true, ForceRLS: boolPtr(false),
	})
	if !contains(rev, "FORCE ROW LEVEL SECURITY") {
		t.Fatalf("expected rollback to restore FORCE, got %v", rev)
	}
	for _, s := range rev {
		if strings.Contains(s, "NO FORCE") {
			t.Fatalf("rollback must not itself remove FORCE, got %v", rev)
		}
	}
}

// forceRLS is meaningless without enableRLS and must not emit on its own.
func TestForceRLSIgnoredWhenRLSDisabled(t *testing.T) {
	steps := planFor(t, keystonev1alpha1.DesiredTable{
		Name: "messages", EnableRLS: false, ForceRLS: boolPtr(true),
	})
	if len(steps) != 0 {
		t.Fatalf("expected no RLS statements when enableRLS is false, got %v", steps)
	}
}

// Both RLS statements are idempotent, so emitting them unconditionally was
// never wrong — it was just noise, and a plan that is never empty is a plan
// nobody reads. downstream-service's 97-table schema produced 172 no-op statements on
// a database that already matched its declaration exactly.
func TestRLSEmitsNothingWhenAlreadyConverged(t *testing.T) {
	plan := planWith(t, seen("messages", true, boolPtr(true)),
		keystonev1alpha1.DesiredTable{Name: "messages", EnableRLS: true, ForceRLS: boolPtr(true)})
	if len(plan.Statements) != 0 {
		t.Fatalf("converged table must plan to nothing, got %v", plan.Statements)
	}
}

// Unset means forced, so an already-forced table converges against a
// declaration that never mentions the field.
func TestRLSEmitsNothingWhenConvergedAndForceUnset(t *testing.T) {
	plan := planWith(t, seen("messages", true, boolPtr(true)),
		keystonev1alpha1.DesiredTable{Name: "messages", EnableRLS: true})
	if len(plan.Statements) != 0 {
		t.Fatalf("unset forceRLS against a forced table must plan to nothing, got %v", plan.Statements)
	}
}

// The half that actually matters. ENABLE alone exempts the table owner from
// every policy, and applications routinely connect as the owning role, so a
// table that is enabled-but-not-forced is unprotected in practice. Skipping
// the FORCE statement here would leave it that way.
func TestRLSEmitsForceOnlyWhenEnabledButNotForced(t *testing.T) {
	plan := planWith(t, seen("messages", true, boolPtr(false)),
		keystonev1alpha1.DesiredTable{Name: "messages", EnableRLS: true})
	if contains(plan.Statements, "ENABLE ROW LEVEL SECURITY") {
		t.Errorf("RLS is already enabled; ENABLE is noise, got %v", plan.Statements)
	}
	if !contains(plan.Statements, "FORCE ROW LEVEL SECURITY") {
		t.Fatalf("owner is exempt until FORCE is applied, got %v", plan.Statements)
	}
}

func TestRLSEmitsEnableWhenObservedDisabled(t *testing.T) {
	plan := planWith(t, seen("messages", false, boolPtr(true)),
		keystonev1alpha1.DesiredTable{Name: "messages", EnableRLS: true})
	if !contains(plan.Statements, "ENABLE ROW LEVEL SECURITY") {
		t.Fatalf("expected ENABLE, got %v", plan.Statements)
	}
}

// A nil FORCE bit comes from a snapshot taken before the field was recorded,
// which is not the same as observing an unforced table. Treating unknown as
// "already forced" would skip the statement on exactly the tables whose state
// nobody has ever checked.
func TestRLSUnknownForceBitStillEmitsForce(t *testing.T) {
	plan := planWith(t, seen("messages", true, nil),
		keystonev1alpha1.DesiredTable{Name: "messages", EnableRLS: true})
	if !contains(plan.Statements, "FORCE ROW LEVEL SECURITY") {
		t.Fatalf("unknown FORCE state must still be asserted, got %v", plan.Statements)
	}
}

// A table this same plan is about to CREATE is absent from the snapshot. It
// still needs both statements, or it lands with no row-level security at all.
func TestRLSEmitsForTableAbsentFromObserved(t *testing.T) {
	plan := planWith(t, seen("accounts", true, boolPtr(true)),
		keystonev1alpha1.DesiredTable{Name: "messages", EnableRLS: true})
	if !contains(plan.Statements, "ENABLE ROW LEVEL SECURITY") ||
		!contains(plan.Statements, "FORCE ROW LEVEL SECURITY") {
		t.Fatalf("a table being created needs both statements, got %v", plan.Statements)
	}
}

// Un-forcing destroys no data, so it is easy to mistake for an ordinary
// ALTER. It hands the application role a blanket exemption from every policy
// on the table, which on a multi-tenant schema is a cross-tenant read. It has
// to count as destructive so allowDestructive=false refuses it outright.
func TestRLSNoForceIsDestructive(t *testing.T) {
	plan := planWith(t, seen("messages", true, boolPtr(true)),
		keystonev1alpha1.DesiredTable{Name: "messages", EnableRLS: true, ForceRLS: boolPtr(false)})
	if !contains(plan.Statements, "NO FORCE ROW LEVEL SECURITY") {
		t.Fatalf("expected NO FORCE, got %v", plan.Statements)
	}
	if plan.DestructiveOps != 1 {
		t.Fatalf("dropping owner-side enforcement must count as destructive, got %d", plan.DestructiveOps)
	}
}

// ...but only when it changes something. An already-unforced table matching a
// forceRLS=false declaration is converged, and must not trip the destructive
// gate on every reconcile.
func TestRLSNoForceSkippedWhenAlreadyUnforced(t *testing.T) {
	plan := planWith(t, seen("messages", true, boolPtr(false)),
		keystonev1alpha1.DesiredTable{Name: "messages", EnableRLS: true, ForceRLS: boolPtr(false)})
	if len(plan.Statements) != 0 {
		t.Fatalf("converged table must plan to nothing, got %v", plan.Statements)
	}
	if plan.DestructiveOps != 0 {
		t.Fatalf("a no-op must not be destructive, got %d", plan.DestructiveOps)
	}
}

// Clearing enableRLS skips the table rather than turning RLS off on a live
// one. That asymmetry against the NO FORCE path is deliberate — deleting a
// line from a manifest should not be able to strip row-level security from a
// table that has it — so it is pinned rather than left to be "fixed" later.
func TestRLSNeverDisablesAnObservedEnabledTable(t *testing.T) {
	plan := planWith(t, seen("messages", true, boolPtr(true)),
		keystonev1alpha1.DesiredTable{Name: "messages", EnableRLS: false})
	if len(plan.Statements) != 0 {
		t.Fatalf("expected no statements, got %v", plan.Statements)
	}
}
