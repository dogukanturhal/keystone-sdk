// SPDX-License-Identifier: AGPL-3.0-or-later

package drift

import (
	"strings"
	"testing"

	keystonev1alpha1 "github.com/dogukanturhal/keystone/api/v1alpha1"
)

// tenantTable builds a table in the shape this platform's multi-tenant
// tables take: RLS on, forced, one tenant_isolation policy.
func tenantTable(name string, enabled, forced bool) TableShape {
	return TableShape{
		Name: name,
		Kind: "BASE TABLE",
		Columns: []ColumnShape{
			{Name: "tenant_id", DataType: "uuid"},
			{Name: "payload", DataType: "text", Nullable: true},
		},
		RLSEnabled: enabled,
		RLSForced:  &forced,
	}
}

// legacyTable is a table as an old snapshot recorded it: RLSForced was not
// modelled, so decoding the stored JSON leaves the pointer nil.
func legacyTable(name string, enabled bool) TableShape {
	t := tenantTable(name, enabled, false)
	t.RLSForced = nil
	return t
}

func isolationPolicy(table string) PolicyShape {
	return PolicyShape{
		Name:       "tenant_isolation",
		Table:      table,
		Command:    "ALL",
		Permissive: true,
		Roles:      []string{"public"},
		Using:      "(tenant_id = (current_setting('app.current_tenant'::text, true))::uuid)",
		WithCheck:  "(tenant_id = (current_setting('app.current_tenant'::text, true))::uuid)",
	}
}

func protectedSnapshot() *Snapshot {
	return &Snapshot{
		Schema:   "public",
		Tables:   []TableShape{tenantTable("messages", true, true)},
		Policies: []PolicyShape{isolationPolicy("messages")},
	}
}

func kinds(findings []keystonev1alpha1.DriftFinding) []string {
	out := make([]string, 0, len(findings))
	for _, f := range findings {
		out = append(out, f.Kind)
	}
	return out
}

func hasKind(findings []keystonev1alpha1.DriftFinding, kind string) bool {
	for _, f := range findings {
		if f.Kind == kind {
			return true
		}
	}
	return false
}

// TestHashDetectsUnforcedRLS is the regression that motivated tracking
// relforcerowsecurity at all.
//
// Hash() is a digest of the Snapshot struct. While the struct modelled only
// relrowsecurity, `ALTER TABLE … NO FORCE ROW LEVEL SECURITY` produced a
// byte-identical snapshot: the drift controller compares the observed hash
// against the stored baseline, so an identical hash meant the schema was
// never even considered drifted. No report, no findings, no event — while
// every policy on the table had stopped applying to the role the application
// connects as.
func TestHashDetectsUnforcedRLS(t *testing.T) {
	forced := protectedSnapshot()
	unforced := protectedSnapshot()
	unforced.Tables[0].RLSForced = boolPtr(false)

	h1, err := Hash(forced)
	if err != nil {
		t.Fatalf("hash forced: %v", err)
	}
	h2, err := Hash(unforced)
	if err != nil {
		t.Fatalf("hash unforced: %v", err)
	}
	if h1 == h2 {
		t.Fatal("hash is identical with and without FORCE ROW LEVEL SECURITY: " +
			"losing owner-side RLS enforcement would not register as drift")
	}
}

// TestHashStableForIdenticalSnapshots guards the other direction — the hash
// must not become noisy, or every reconcile would report drift.
func TestHashStableForIdenticalSnapshots(t *testing.T) {
	h1, err := Hash(protectedSnapshot())
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	h2, err := Hash(protectedSnapshot())
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	if h1 != h2 {
		t.Fatalf("identical snapshots hashed differently: %s vs %s", h1, h2)
	}
}

func TestDiffReportsUnforcedRLSAsCritical(t *testing.T) {
	baseline := protectedSnapshot()
	observed := protectedSnapshot()
	observed.Tables[0].RLSForced = boolPtr(false)

	findings := Diff(baseline, observed)
	if !hasKind(findings, "RLSUnforced") {
		t.Fatalf("expected RLSUnforced finding, got %v", kinds(findings))
	}
	if got := Severity(findings); got != keystonev1alpha1.DriftSeverityCritical {
		t.Errorf("expected Critical severity for lost FORCE, got %q", got)
	}
	// The description has to explain the consequence: the shape of the
	// schema is unchanged, so a reader who only sees "RLS changed" has no
	// reason to treat it as urgent.
	for _, f := range findings {
		if f.Kind != "RLSUnforced" {
			continue
		}
		if !strings.Contains(f.Description, "owner") {
			t.Errorf("RLSUnforced description should explain the owner bypass, got %q", f.Description)
		}
		if f.Object != "public.messages" {
			t.Errorf("expected qualified object public.messages, got %q", f.Object)
		}
	}
}

func TestDiffReportsDisabledRLSAsCritical(t *testing.T) {
	baseline := protectedSnapshot()
	observed := protectedSnapshot()
	observed.Tables[0].RLSEnabled = false
	observed.Tables[0].RLSForced = boolPtr(false)

	findings := Diff(baseline, observed)
	if !hasKind(findings, "RLSDisabled") {
		t.Fatalf("expected RLSDisabled finding, got %v", kinds(findings))
	}
	if got := Severity(findings); got != keystonev1alpha1.DriftSeverityCritical {
		t.Errorf("expected Critical severity, got %q", got)
	}
}

// Gaining protection is drift worth reporting but is not an incident.
func TestDiffGradesAddedProtectionAsWarning(t *testing.T) {
	baseline := &Snapshot{
		Schema: "public",
		Tables: []TableShape{tenantTable("messages", false, false)},
	}
	observed := &Snapshot{
		Schema: "public",
		Tables: []TableShape{tenantTable("messages", true, true)},
	}
	findings := Diff(baseline, observed)
	if !hasKind(findings, "RLSEnabled") || !hasKind(findings, "RLSForced") {
		t.Fatalf("expected RLSEnabled and RLSForced findings, got %v", kinds(findings))
	}
	if got := Severity(findings); got != keystonev1alpha1.DriftSeverityWarning {
		t.Errorf("expected Warning when protection is ADDED, got %q", got)
	}
}

func TestDiffIgnoresUnchangedRLS(t *testing.T) {
	if findings := Diff(protectedSnapshot(), protectedSnapshot()); len(findings) != 0 {
		t.Fatalf("expected no findings for identical snapshots, got %v", kinds(findings))
	}
}

// TestDiffReportsDroppedPolicy covers the second half of the gap: policies
// were part of the hash but never compared, so dropping tenant_isolation
// tripped drift detection and then attached an EMPTY finding list, which
// Severity() graded Info.
func TestDiffReportsDroppedPolicy(t *testing.T) {
	baseline := protectedSnapshot()
	observed := protectedSnapshot()
	observed.Policies = nil

	findings := Diff(baseline, observed)
	if !hasKind(findings, "PolicyDropped") {
		t.Fatalf("expected PolicyDropped finding, got %v", kinds(findings))
	}
	if got := Severity(findings); got != keystonev1alpha1.DriftSeverityCritical {
		t.Errorf("expected Critical severity for a dropped policy, got %q", got)
	}
}

func TestDiffReportsRewrittenPolicy(t *testing.T) {
	baseline := protectedSnapshot()
	observed := protectedSnapshot()
	// The policy still exists, still covers ALL, still named the same —
	// and now matches every row.
	observed.Policies[0].Using = "true"

	findings := Diff(baseline, observed)
	if !hasKind(findings, "PolicyChanged") {
		t.Fatalf("expected PolicyChanged finding, got %v", kinds(findings))
	}
	if got := Severity(findings); got != keystonev1alpha1.DriftSeverityCritical {
		t.Errorf("expected Critical severity for a rewritten USING clause, got %q", got)
	}
}

func TestDiffReportsAddedPolicy(t *testing.T) {
	baseline := protectedSnapshot()
	observed := protectedSnapshot()
	observed.Policies = append(observed.Policies, PolicyShape{
		Name: "admin_read", Table: "messages", Command: "SELECT",
		Permissive: true, Using: "true",
	})
	findings := Diff(baseline, observed)
	if !hasKind(findings, "PolicyAdded") {
		t.Fatalf("expected PolicyAdded finding, got %v", kinds(findings))
	}
}

// Policy names are unique per table, not per schema. Two tables each
// carrying `tenant_isolation` must not collide in the comparison map — if
// they did, dropping one would look like it still existed.
func TestDiffKeysPoliciesByTable(t *testing.T) {
	baseline := &Snapshot{
		Schema: "public",
		Tables: []TableShape{tenantTable("messages", true, true), tenantTable("mailboxes", true, true)},
		Policies: []PolicyShape{
			isolationPolicy("messages"),
			isolationPolicy("mailboxes"),
		},
	}
	observed := &Snapshot{
		Schema:   "public",
		Tables:   []TableShape{tenantTable("messages", true, true), tenantTable("mailboxes", true, true)},
		Policies: []PolicyShape{isolationPolicy("messages")},
	}
	findings := Diff(baseline, observed)
	if !hasKind(findings, "PolicyDropped") {
		t.Fatalf("dropping mailboxes.tenant_isolation went unreported: %v", kinds(findings))
	}
	for _, f := range findings {
		if f.Kind == "PolicyDropped" && !strings.Contains(f.Object, "mailboxes") {
			t.Errorf("expected the mailboxes policy to be reported, got %q", f.Object)
		}
	}
}

// TestSecurityFindingsSurviveTruncation — findings are capped at 128 for the
// CRD's MaxItems. Truncation is positional, so a schema that gained a large
// number of benign objects in one pass could otherwise push a cross-tenant
// exposure past the cap and report it as "additional findings omitted".
func TestSecurityFindingsSurviveTruncation(t *testing.T) {
	baseline := &Snapshot{Schema: "public"}
	observed := &Snapshot{Schema: "public"}

	// One table that loses FORCE. Named to sort last so that, without the
	// partition, its finding lands beyond the cap.
	baseline.Tables = append(baseline.Tables, tenantTable("zzz_last", true, true))
	observed.Tables = append(observed.Tables, tenantTable("zzz_last", true, false))

	// 200 added tables ahead of it alphabetically.
	for i := 0; i < 200; i++ {
		name := "aaa_bulk_" + string(rune('a'+i%26)) + string(rune('a'+i/26))
		observed.Tables = append(observed.Tables, tenantTable(name, false, false))
	}

	findings := Diff(baseline, observed)
	if len(findings) > 128 {
		t.Fatalf("findings exceed the CRD cap: %d", len(findings))
	}
	if !hasKind(findings, "RLSUnforced") {
		t.Fatal("the RLSUnforced finding was truncated away by benign findings")
	}
	if got := Severity(findings); got != keystonev1alpha1.DriftSeverityCritical {
		t.Errorf("expected Critical to survive truncation, got %q", got)
	}
}

// Determinism matters for status-patch idempotency: a diff that reorders
// findings between runs would rewrite the DriftReport on every reconcile.
func TestDiffIsDeterministic(t *testing.T) {
	baseline := protectedSnapshot()
	observed := protectedSnapshot()
	observed.Tables[0].RLSForced = boolPtr(false)
	observed.Policies[0].Using = "true"

	first := kinds(Diff(baseline, observed))
	for i := 0; i < 5; i++ {
		again := kinds(Diff(baseline, observed))
		if len(first) != len(again) {
			t.Fatalf("finding count varied between runs: %d vs %d", len(first), len(again))
		}
		for j := range first {
			if first[j] != again[j] {
				t.Fatalf("finding order varied between runs at %d: %s vs %s", j, first[j], again[j])
			}
		}
	}
}

func TestDiffNilSnapshots(t *testing.T) {
	if Diff(nil, protectedSnapshot()) != nil {
		t.Error("expected nil for a nil baseline")
	}
	if Diff(protectedSnapshot(), nil) != nil {
		t.Error("expected nil for a nil observation")
	}
}

func boolPtr(b bool) *bool { return &b }

// The snapshot store keeps the baseline document until an operator accepts
// drift, so on the first reconcile after this field ships every baseline in
// the fleet is an old-model document that never recorded FORCE. Decoding the
// missing key as false would read all 86 already-forced tables on a schema
// like downstream-service's as "FORCE was just added" — and keep reporting them on
// every reconcile, because nothing rewrites the baseline. The comparison has
// to be skipped instead.
func TestDiffSkipsForceComparisonAgainstLegacyBaseline(t *testing.T) {
	baseline := &Snapshot{
		Schema: "public",
		Tables: []TableShape{legacyTable("messages", true)},
	}
	observed := &Snapshot{
		Schema: "public",
		Tables: []TableShape{tenantTable("messages", true, true)},
	}
	findings := Diff(baseline, observed)
	if hasKind(findings, "RLSForced") {
		t.Fatalf("a baseline predating the field must not produce RLSForced findings, got %v", kinds(findings))
	}
	if len(findings) != 0 {
		t.Fatalf("expected no findings when only the snapshot model changed, got %v", kinds(findings))
	}
}

// Skipping the unknown case must not become a way to lose the security
// signal: once a baseline records FORCE, losing it is still Critical.
func TestDiffStillReportsUnforcedAgainstKnownBaseline(t *testing.T) {
	baseline := &Snapshot{Schema: "public", Tables: []TableShape{tenantTable("messages", true, true)}}
	observed := &Snapshot{Schema: "public", Tables: []TableShape{tenantTable("messages", true, false)}}
	if !hasKind(Diff(baseline, observed), "RLSUnforced") {
		t.Fatal("a known baseline must still report lost FORCE")
	}
}

// PredatesRLSForce dates the whole document off any single nil, because the
// inspector populates the field on every table it returns.
func TestPredatesRLSForce(t *testing.T) {
	legacy := &Snapshot{Schema: "public", Tables: []TableShape{legacyTable("messages", true)}}
	if !legacy.PredatesRLSForce() {
		t.Error("a snapshot with a nil RLSForced should be dated as pre-field")
	}
	if protectedSnapshot().PredatesRLSForce() {
		t.Error("an inspected snapshot should not be dated as pre-field")
	}
	var nilSnap *Snapshot
	if nilSnap.PredatesRLSForce() {
		t.Error("nil snapshot should report false, not panic")
	}
}

// WithoutRLSForce is what lets the controller tell "only the model changed"
// from "something really changed" during the upgrade: its projection has to
// hash exactly like a document written before the field existed.
func TestWithoutRLSForceHashesLikeLegacy(t *testing.T) {
	observed := protectedSnapshot()
	legacy := &Snapshot{
		Schema:   "public",
		Tables:   []TableShape{legacyTable("messages", true)},
		Policies: []PolicyShape{isolationPolicy("messages")},
	}

	hProjected, err := Hash(observed.WithoutRLSForce())
	if err != nil {
		t.Fatalf("hash projection: %v", err)
	}
	hLegacy, err := Hash(legacy)
	if err != nil {
		t.Fatalf("hash legacy: %v", err)
	}
	if hProjected != hLegacy {
		t.Fatalf("projection must hash identically to a pre-field snapshot:\n  projected %s\n  legacy    %s", hProjected, hLegacy)
	}

	// And it must not mutate the source — the controller hashes the real
	// snapshot immediately afterwards to write the new baseline.
	if observed.Tables[0].RLSForced == nil || !*observed.Tables[0].RLSForced {
		t.Error("WithoutRLSForce mutated its receiver")
	}
}

// The projection must only neutralise the model change, never a real one.
func TestWithoutRLSForceStillDiffersOnRealChange(t *testing.T) {
	observed := protectedSnapshot()
	observed.Policies = nil // a genuine change, on top of the model change

	legacy := &Snapshot{
		Schema:   "public",
		Tables:   []TableShape{legacyTable("messages", true)},
		Policies: []PolicyShape{isolationPolicy("messages")},
	}
	hProjected, _ := Hash(observed.WithoutRLSForce())
	hLegacy, _ := Hash(legacy)
	if hProjected == hLegacy {
		t.Fatal("a dropped policy must survive the projection, or the upgrade path would silently re-baseline over it")
	}
}

// -- extension version, the model-3 field -------------------------------

// An extension whose version the inspector recorded.
func versionedExt(name, schema, version string) ExtShape {
	return ExtShape{Name: name, Schema: schema, Version: version}
}

// PredatesExtVersion dates the whole document off any single empty version,
// because pg_extension.extversion is NOT NULL — the inspector cannot produce
// a recorded-but-blank one.
func TestPredatesExtVersion(t *testing.T) {
	legacy := &Snapshot{
		Schema:     "public",
		Extensions: []ExtShape{{Name: "pgcrypto", Schema: "public"}},
	}
	if !legacy.PredatesExtVersion() {
		t.Error("a snapshot with a blank extension version should be dated as pre-field")
	}

	current := &Snapshot{
		Schema:     "public",
		Extensions: []ExtShape{versionedExt("pgcrypto", "public", "1.3")},
	}
	if current.PredatesExtVersion() {
		t.Error("an inspected snapshot should not be dated as pre-field")
	}

	// A schema with no extensions is not missing anything: its JSON is
	// already identical under both models, so dating it pre-field would
	// invite a pointless re-baseline.
	if (&Snapshot{Schema: "public"}).PredatesExtVersion() {
		t.Error("a snapshot with no extensions should not be dated as pre-field")
	}

	var nilSnap *Snapshot
	if nilSnap.PredatesExtVersion() {
		t.Error("nil snapshot should report false, not panic")
	}
}

// The projection has to hash exactly like a document written before the
// field existed, or the upgrade marks the whole fleet drifted.
func TestWithoutExtVersionHashesLikeLegacy(t *testing.T) {
	observed := &Snapshot{
		Schema:     "public",
		Extensions: []ExtShape{versionedExt("pgcrypto", "public", "1.3")},
	}
	legacy := &Snapshot{
		Schema:     "public",
		Extensions: []ExtShape{{Name: "pgcrypto", Schema: "public"}},
	}

	hProjected, err := Hash(observed.WithoutExtVersion())
	if err != nil {
		t.Fatalf("hash projection: %v", err)
	}
	hLegacy, err := Hash(legacy)
	if err != nil {
		t.Fatalf("hash legacy: %v", err)
	}
	if hProjected != hLegacy {
		t.Fatalf("projection must hash identically to a pre-field snapshot:\n  projected %s\n  legacy    %s", hProjected, hLegacy)
	}

	// The controller hashes the real snapshot immediately afterwards to
	// write the new baseline, so the receiver must be untouched.
	if observed.Extensions[0].Version != "1.3" {
		t.Error("WithoutExtVersion mutated its receiver")
	}
}

// The projection must only neutralise the model change, never a real one.
func TestWithoutExtVersionStillDiffersOnRealChange(t *testing.T) {
	observed := &Snapshot{
		Schema: "public",
		Extensions: []ExtShape{
			versionedExt("pgcrypto", "public", "1.3"),
			versionedExt("citext", "public", "1.6"),
		},
	}
	legacy := &Snapshot{
		Schema:     "public",
		Extensions: []ExtShape{{Name: "pgcrypto", Schema: "public"}},
	}
	hProjected, _ := Hash(observed.WithoutExtVersion())
	hLegacy, _ := Hash(legacy)
	if hProjected == hLegacy {
		t.Fatal("an added extension must survive the projection, or the upgrade path would silently re-baseline over it")
	}
}

// The whole point of the field: an in-place ALTER EXTENSION ... UPDATE TO
// leaves the name and schema alone, so before model 3 it hashed identically
// and was invisible.
func TestExtVersionMakesInPlaceUpgradeVisible(t *testing.T) {
	before := &Snapshot{
		Schema:     "public",
		Extensions: []ExtShape{versionedExt("pgcrypto", "public", "1.3")},
	}
	after := &Snapshot{
		Schema:     "public",
		Extensions: []ExtShape{versionedExt("pgcrypto", "public", "1.4")},
	}
	hBefore, _ := Hash(before)
	hAfter, _ := Hash(after)
	if hBefore == hAfter {
		t.Fatal("an extension version bump must change the snapshot hash")
	}
	// And it was genuinely invisible without the field — the regression
	// this guards is someone dropping Version back out of the shape.
	hBeforeLegacy, _ := Hash(before.WithoutExtVersion())
	hAfterLegacy, _ := Hash(after.WithoutExtVersion())
	if hBeforeLegacy != hAfterLegacy {
		t.Fatal("projected back onto the old model the upgrade should be indistinguishable, which is why the field was added")
	}
}
