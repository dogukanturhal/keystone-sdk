// SPDX-License-Identifier: AGPL-3.0-or-later

package drift

import (
	"fmt"

	keystonev1alpha1 "github.com/dogukanturhal/keystone/api/v1alpha1"
)

// Diff returns the structural deltas between two snapshots. Both
// snapshots must be from the same schema. Findings are returned in
// stable order so repeated diffs of identical inputs produce identical
// output (important for status-patch idempotency).
//
// Severity is computed by Severity() over the returned slice — caller
// usually wants both.
func Diff(baseline, observed *Snapshot) []keystonev1alpha1.DriftFinding {
	if baseline == nil || observed == nil {
		return nil
	}
	out := make([]keystonev1alpha1.DriftFinding, 0)

	// Tables: walk baseline, then walk observed for "added" entries.
	bTables := tablesByName(baseline)
	oTables := tablesByName(observed)
	for _, name := range sortedTableNames(bTables) {
		bt := bTables[name]
		ot, ok := oTables[name]
		if !ok {
			out = append(out, keystonev1alpha1.DriftFinding{
				Kind:        "TableDropped",
				Object:      fmt.Sprintf("%s.%s", baseline.Schema, name),
				Description: fmt.Sprintf("table existed in baseline (%s) but is absent now", bt.Kind),
			})
			continue
		}
		// Same name: compare columns.
		bc := columnsByName(bt.Columns)
		oc := columnsByName(ot.Columns)
		for _, cn := range sortedColumnNames(bc) {
			bcol := bc[cn]
			ocol, ok := oc[cn]
			if !ok {
				out = append(out, keystonev1alpha1.DriftFinding{
					Kind:        "ColumnDropped",
					Object:      fmt.Sprintf("%s.%s.%s", baseline.Schema, name, cn),
					Description: fmt.Sprintf("column was %s NULL=%t default=%q", bcol.DataType, bcol.Nullable, bcol.Default),
				})
				continue
			}
			if changed := columnChange(bcol, ocol); changed != "" {
				out = append(out, keystonev1alpha1.DriftFinding{
					Kind:        "ColumnChanged",
					Object:      fmt.Sprintf("%s.%s.%s", baseline.Schema, name, cn),
					Description: changed,
				})
			}
		}
		for _, cn := range sortedColumnNames(oc) {
			if _, ok := bc[cn]; ok {
				continue
			}
			ocol := oc[cn]
			out = append(out, keystonev1alpha1.DriftFinding{
				Kind:        "ColumnAdded",
				Object:      fmt.Sprintf("%s.%s.%s", baseline.Schema, name, cn),
				Description: fmt.Sprintf("column added with %s NULL=%t default=%q", ocol.DataType, ocol.Nullable, ocol.Default),
			})
		}

		// RLS bits. Losing either one silently un-enforces every policy on
		// the table, so both directions are reported and the losing
		// direction is graded Critical by Severity().
		out = append(out, rlsFindings(baseline.Schema, name, bt, ot)...)
	}
	for _, name := range sortedTableNames(oTables) {
		if _, ok := bTables[name]; ok {
			continue
		}
		out = append(out, keystonev1alpha1.DriftFinding{
			Kind:        "TableAdded",
			Object:      fmt.Sprintf("%s.%s", baseline.Schema, name),
			Description: fmt.Sprintf("table added (%s) with %d column(s)", oTables[name].Kind, len(oTables[name].Columns)),
		})
	}

	// Indexes — keyed by (table, name).
	bIdx := objectsByKey(baseline.Indexes)
	oIdx := objectsByKey(observed.Indexes)
	for _, k := range sortedObjectKeys(bIdx) {
		if _, ok := oIdx[k]; !ok {
			out = append(out, keystonev1alpha1.DriftFinding{
				Kind:        "IndexDropped",
				Object:      fmt.Sprintf("%s.%s", baseline.Schema, k),
				Description: bIdx[k].Definition,
			})
		}
	}
	for _, k := range sortedObjectKeys(oIdx) {
		if _, ok := bIdx[k]; !ok {
			out = append(out, keystonev1alpha1.DriftFinding{
				Kind:        "IndexAdded",
				Object:      fmt.Sprintf("%s.%s", baseline.Schema, k),
				Description: oIdx[k].Definition,
			})
		}
	}

	// Constraints.
	bCon := objectsByKey(baseline.Constraints)
	oCon := objectsByKey(observed.Constraints)
	for _, k := range sortedObjectKeys(bCon) {
		if _, ok := oCon[k]; !ok {
			out = append(out, keystonev1alpha1.DriftFinding{
				Kind:        "ConstraintDropped",
				Object:      fmt.Sprintf("%s.%s", baseline.Schema, k),
				Description: fmt.Sprintf("%s: %s", bCon[k].Type, bCon[k].Definition),
			})
		}
	}
	for _, k := range sortedObjectKeys(oCon) {
		if _, ok := bCon[k]; !ok {
			out = append(out, keystonev1alpha1.DriftFinding{
				Kind:        "ConstraintAdded",
				Object:      fmt.Sprintf("%s.%s", baseline.Schema, k),
				Description: fmt.Sprintf("%s: %s", oCon[k].Type, oCon[k].Definition),
			})
		}
	}

	// Policies. These were previously not compared at all, which made the
	// report actively misleading rather than merely incomplete: policies are
	// part of the Snapshot and therefore part of Hash(), so dropping one DID
	// trip drift detection — the controller marked the schema drifted, then
	// attached a report with zero findings, which Severity() graded Info.
	// A dropped `tenant_isolation` surfaced as informational drift with no
	// stated cause.
	bPol := policiesByKey(baseline.Policies)
	oPol := policiesByKey(observed.Policies)
	for _, k := range sortedPolicyKeys(bPol) {
		bp := bPol[k]
		op, ok := oPol[k]
		if !ok {
			out = append(out, keystonev1alpha1.DriftFinding{
				Kind:   "PolicyDropped",
				Object: fmt.Sprintf("%s.%s", baseline.Schema, k),
				Description: fmt.Sprintf("policy on %s for %s was USING(%s)",
					bp.Table, bp.Command, orNone(bp.Using)),
			})
			continue
		}
		if changed := policyChange(bp, op); changed != "" {
			out = append(out, keystonev1alpha1.DriftFinding{
				Kind:        "PolicyChanged",
				Object:      fmt.Sprintf("%s.%s", baseline.Schema, k),
				Description: changed,
			})
		}
	}
	for _, k := range sortedPolicyKeys(oPol) {
		if _, ok := bPol[k]; !ok {
			op := oPol[k]
			out = append(out, keystonev1alpha1.DriftFinding{
				Kind:   "PolicyAdded",
				Object: fmt.Sprintf("%s.%s", baseline.Schema, k),
				Description: fmt.Sprintf("policy added on %s for %s USING(%s)",
					op.Table, op.Command, orNone(op.Using)),
			})
		}
	}

	// Cap — DriftReport schema enforces MaxItems=128 anyway; truncate
	// here so the controller patch doesn't reject.
	//
	// Security findings are retained ahead of the rest. Truncation is
	// positional, and the findings above are emitted in object order, so a
	// schema that gained 200 columns in one pass could push a
	// cross-tenant-exposure finding past the cap and report it as
	// "additional findings omitted". The partition is stable — relative
	// order within each group is preserved — so repeated diffs of identical
	// input still produce identical output.
	if len(out) > 128 {
		out = partitionSecurityFirst(out)
		extra := len(out) - 127
		out = out[:127]
		out = append(out, keystonev1alpha1.DriftFinding{
			Kind:        "Other",
			Object:      "(truncated)",
			Description: fmt.Sprintf("%d additional findings omitted; inspect schema directly", extra),
		})
	}
	return out
}

// rlsFindings compares the two row-level-security bits on one table.
//
// The two are reported separately because they fail differently. Losing
// ENABLE turns policies off for everyone. Losing FORCE turns them off only
// for the table's owner — which sounds narrower and is usually worse, because
// the owner is typically the role the application itself connects as, so the
// policies remain visibly present while enforcing nothing on the one
// connection that matters.
func rlsFindings(schema, table string, b, o TableShape) []keystonev1alpha1.DriftFinding {
	var out []keystonev1alpha1.DriftFinding
	obj := fmt.Sprintf("%s.%s", schema, table)
	switch {
	case b.RLSEnabled && !o.RLSEnabled:
		out = append(out, keystonev1alpha1.DriftFinding{
			Kind:        "RLSDisabled",
			Object:      obj,
			Description: "row-level security was ENABLED in baseline and is now DISABLED; every policy on this table is inert",
		})
	case !b.RLSEnabled && o.RLSEnabled:
		out = append(out, keystonev1alpha1.DriftFinding{
			Kind:        "RLSEnabled",
			Object:      obj,
			Description: "row-level security enabled (was disabled in baseline)",
		})
	}
	// A baseline written before RLSForced existed cannot be compared on it.
	// Reporting the difference anyway would turn every already-forced table
	// into an "RLSForced was added" finding on the first reconcile after the
	// upgrade — and keep reporting it, because the stored baseline is only
	// rewritten when an operator accepts the drift. The callers that need to
	// distinguish a genuine change from the model change use
	// Snapshot.PredatesRLSForce and Snapshot.WithoutRLSForce.
	if b.RLSForced == nil || o.RLSForced == nil {
		return out
	}
	switch {
	case *b.RLSForced && !*o.RLSForced:
		out = append(out, keystonev1alpha1.DriftFinding{
			Kind:        "RLSUnforced",
			Object:      obj,
			Description: "row-level security is no longer FORCED; policies are bypassed for the table owner, so an application connecting as the owner reads and writes across all rows regardless of policy",
		})
	case !*b.RLSForced && *o.RLSForced:
		out = append(out, keystonev1alpha1.DriftFinding{
			Kind:        "RLSForced",
			Object:      obj,
			Description: "row-level security is now FORCED (applies to the table owner)",
		})
	}
	return out
}

// securityKinds are the findings that describe a loss of enforcement rather
// than a change of shape. They survive truncation and drive Critical.
var securityKinds = map[string]bool{
	"RLSDisabled":   true,
	"RLSUnforced":   true,
	"PolicyDropped": true,
	"PolicyChanged": true,
}

// partitionSecurityFirst moves security findings to the front, preserving
// relative order within both groups.
func partitionSecurityFirst(in []keystonev1alpha1.DriftFinding) []keystonev1alpha1.DriftFinding {
	sec := make([]keystonev1alpha1.DriftFinding, 0, len(in))
	rest := make([]keystonev1alpha1.DriftFinding, 0, len(in))
	for _, f := range in {
		if securityKinds[f.Kind] {
			sec = append(sec, f)
			continue
		}
		rest = append(rest, f)
	}
	return append(sec, rest...)
}

// policyChange returns a description of how two same-named policies differ,
// or "" when equivalent. The USING and WITH CHECK expressions are the
// enforcement itself, so a rewrite is as significant as a drop.
func policyChange(b, o PolicyShape) string {
	switch {
	case b.Using != o.Using:
		return fmt.Sprintf("USING expression changed from (%s) to (%s)", orNone(b.Using), orNone(o.Using))
	case b.WithCheck != o.WithCheck:
		return fmt.Sprintf("WITH CHECK expression changed from (%s) to (%s)", orNone(b.WithCheck), orNone(o.WithCheck))
	case b.Command != o.Command:
		return fmt.Sprintf("command changed from %s to %s", b.Command, o.Command)
	case b.Permissive != o.Permissive:
		return fmt.Sprintf("changed from permissive=%t to permissive=%t", b.Permissive, o.Permissive)
	case !equalStrings(b.Roles, o.Roles):
		return fmt.Sprintf("roles changed from %v to %v", b.Roles, o.Roles)
	}
	return ""
}

func orNone(s string) string {
	if s == "" {
		return "none"
	}
	return s
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// Severity grades a slice of findings. Critical iff any *Dropped is
// present, or any finding describes a loss of row-level-security
// enforcement; Warning if anything else is in the list; Info if empty.
//
// The enforcement-loss kinds are Critical for a different reason than the
// *Dropped kinds. A dropped column is Critical because data is gone. A
// table that is no longer FORCE-d has lost nothing visible — every row,
// column and policy is still present and a shape comparison reads clean —
// while having stopped isolating tenants from each other. It is graded at
// the top precisely because nothing else about it looks alarming.
func Severity(findings []keystonev1alpha1.DriftFinding) keystonev1alpha1.DriftSeverity {
	if len(findings) == 0 {
		return keystonev1alpha1.DriftSeverityInfo
	}
	for _, f := range findings {
		switch f.Kind {
		case "TableDropped", "ColumnDropped", "IndexDropped", "ConstraintDropped",
			"RLSDisabled", "RLSUnforced", "PolicyDropped", "PolicyChanged":
			return keystonev1alpha1.DriftSeverityCritical
		}
	}
	return keystonev1alpha1.DriftSeverityWarning
}

// columnChange returns a non-empty string describing the change, or ""
// if columns are equivalent. Compares the security-relevant fields
// only — ordinal swaps without other changes are intentionally ignored
// because PG doesn't preserve column order across operations like
// drop+re-add anyway.
func columnChange(b, o ColumnShape) string {
	if b.DataType != o.DataType || b.UDTName != o.UDTName {
		return fmt.Sprintf("type %s→%s (udt %s→%s)", b.DataType, o.DataType, b.UDTName, o.UDTName)
	}
	if b.Nullable != o.Nullable {
		return fmt.Sprintf("nullability %t→%t", b.Nullable, o.Nullable)
	}
	if b.Default != o.Default {
		return fmt.Sprintf("default %q→%q", b.Default, o.Default)
	}
	return ""
}

// --- small ordering helpers (snapshot is already sorted, but we
// re-sort here for safety against any future change) ---

func tablesByName(s *Snapshot) map[string]TableShape {
	m := make(map[string]TableShape, len(s.Tables))
	for _, t := range s.Tables {
		m[t.Name] = t
	}
	return m
}

func columnsByName(in []ColumnShape) map[string]ColumnShape {
	m := make(map[string]ColumnShape, len(in))
	for _, c := range in {
		m[c.Name] = c
	}
	return m
}

func objectsByKey(in []ObjectDDL) map[string]ObjectDDL {
	m := make(map[string]ObjectDDL, len(in))
	for _, o := range in {
		k := o.Table + "." + o.Name
		m[k] = o
	}
	return m
}

func sortedTableNames(m map[string]TableShape) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sortStrings(out)
	return out
}

func sortedColumnNames(m map[string]ColumnShape) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sortStrings(out)
	return out
}

func sortedObjectKeys(m map[string]ObjectDDL) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sortStrings(out)
	return out
}

// policiesByKey keys on table+name, matching objectsByKey. Policy names are
// unique per table, not per schema, so the table must be part of the key —
// two tables may each carry a `tenant_isolation`, and on this platform most
// of them do.
func policiesByKey(in []PolicyShape) map[string]PolicyShape {
	m := make(map[string]PolicyShape, len(in))
	for _, p := range in {
		m[p.Table+"."+p.Name] = p
	}
	return m
}

func sortedPolicyKeys(m map[string]PolicyShape) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sortStrings(out)
	return out
}

// sortStrings is a thin wrapper to avoid importing "sort" everywhere.
// Kept out of init order to make the diff package self-contained for
// callers that import only the Diff/Severity public surface.
func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j-1] > s[j]; j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
}
