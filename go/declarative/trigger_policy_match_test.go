// SPDX-License-Identifier: AGPL-3.0-or-later

package declarative

import (
	"testing"

	"github.com/dogukanturhal/keystone-sdk/go/drift"
	keystonev1alpha1 "github.com/dogukanturhal/keystone/api/v1alpha1"
)

func TestTriggerMatches(t *testing.T) {
	cases := []struct {
		name     string
		observed drift.TriggerShape
		desired  keystonev1alpha1.DesiredTrigger
		want     bool
	}{
		{
			name: "identical",
			observed: drift.TriggerShape{
				Name: "audit_iam_api_keys", Table: "iam_api_keys",
				Timing: "AFTER", Events: []string{"INSERT", "DELETE", "UPDATE"},
				ForEachRow: true, Function: "log_changes",
			},
			desired: keystonev1alpha1.DesiredTrigger{
				Name: "audit_iam_api_keys", Table: "iam_api_keys",
				Timing: "AFTER", Events: []string{"INSERT", "DELETE", "UPDATE"},
				ForEachRow: true, Function: "log_changes",
			},
			want: true,
		},
		{
			name: "events-different-order-still-equal",
			observed: drift.TriggerShape{
				Name: "t", Table: "tbl", Timing: "AFTER",
				Events:     []string{"INSERT", "DELETE", "UPDATE"},
				ForEachRow: true, Function: "f",
			},
			desired: keystonev1alpha1.DesiredTrigger{
				Name: "t", Table: "tbl", Timing: "AFTER",
				Events:     []string{"UPDATE", "INSERT", "DELETE"},
				ForEachRow: true, Function: "f",
			},
			want: true,
		},
		{
			name: "timing-case-insensitive",
			observed: drift.TriggerShape{
				Name: "t", Table: "tbl", Timing: "before",
				Events: []string{"INSERT"}, ForEachRow: true, Function: "f",
			},
			desired: keystonev1alpha1.DesiredTrigger{
				Name: "t", Table: "tbl", Timing: "BEFORE",
				Events: []string{"INSERT"}, ForEachRow: true, Function: "f",
			},
			want: true,
		},
		{
			name: "different-function-not-equal",
			observed: drift.TriggerShape{
				Name: "t", Table: "tbl", Timing: "AFTER",
				Events: []string{"INSERT"}, ForEachRow: true, Function: "f",
			},
			desired: keystonev1alpha1.DesiredTrigger{
				Name: "t", Table: "tbl", Timing: "AFTER",
				Events: []string{"INSERT"}, ForEachRow: true, Function: "g",
			},
			want: false,
		},
		{
			name: "different-events-not-equal",
			observed: drift.TriggerShape{
				Name: "t", Table: "tbl", Timing: "AFTER",
				Events: []string{"INSERT"}, ForEachRow: true, Function: "f",
			},
			desired: keystonev1alpha1.DesiredTrigger{
				Name: "t", Table: "tbl", Timing: "AFTER",
				Events: []string{"INSERT", "UPDATE"}, ForEachRow: true, Function: "f",
			},
			want: false,
		},
		{
			name: "different-foreachrow-not-equal",
			observed: drift.TriggerShape{
				Name: "t", Table: "tbl", Timing: "AFTER",
				Events: []string{"INSERT"}, ForEachRow: false, Function: "f",
			},
			desired: keystonev1alpha1.DesiredTrigger{
				Name: "t", Table: "tbl", Timing: "AFTER",
				Events: []string{"INSERT"}, ForEachRow: true, Function: "f",
			},
			want: false,
		},
		{
			name: "when-clause-with-quoted-vs-unquoted-identifier",
			observed: drift.TriggerShape{
				Name: "t", Table: "tbl", Timing: "AFTER",
				Events: []string{"UPDATE"}, ForEachRow: true, Function: "f",
				When: "(new.status IS DISTINCT FROM old.status)",
			},
			desired: keystonev1alpha1.DesiredTrigger{
				Name: "t", Table: "tbl", Timing: "AFTER",
				Events: []string{"UPDATE"}, ForEachRow: true, Function: "f",
				When: `(NEW."status" IS DISTINCT FROM OLD."status")`,
			},
			want: true,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := triggerMatches(c.observed, c.desired); got != c.want {
				t.Errorf("triggerMatches() = %v, want %v", got, c.want)
			}
		})
	}
}

func TestPolicyMatches(t *testing.T) {
	cases := []struct {
		name     string
		observed drift.PolicyShape
		desired  keystonev1alpha1.DesiredPolicy
		want     bool
	}{
		{
			name: "identical",
			observed: drift.PolicyShape{
				Name: "tenant_isolation", Table: "iam_users",
				Command: "ALL", Permissive: true,
				Roles: []string{"app"},
				Using: "tenant_id = current_setting('app.tenant_id')::uuid",
			},
			desired: keystonev1alpha1.DesiredPolicy{
				Name: "tenant_isolation", Table: "iam_users",
				Command: "ALL", Permissive: true,
				Roles: []string{"app"},
				Using: "tenant_id = current_setting('app.tenant_id')::uuid",
			},
			want: true,
		},
		{
			name: "default-command-empty-equals-ALL",
			observed: drift.PolicyShape{
				Name: "p", Table: "t", Command: "ALL", Permissive: true,
				Roles: []string{"app"}, Using: "true",
			},
			desired: keystonev1alpha1.DesiredPolicy{
				Name: "p", Table: "t", Command: "", Permissive: true,
				Roles: []string{"app"}, Using: "true",
			},
			want: true,
		},
		{
			name: "command-case-insensitive",
			observed: drift.PolicyShape{
				Name: "p", Table: "t", Command: "select", Permissive: true,
				Roles: []string{"app"}, Using: "true",
			},
			desired: keystonev1alpha1.DesiredPolicy{
				Name: "p", Table: "t", Command: "SELECT", Permissive: true,
				Roles: []string{"app"}, Using: "true",
			},
			want: true,
		},
		{
			name: "empty-roles-equals-PUBLIC",
			observed: drift.PolicyShape{
				Name: "p", Table: "t", Command: "ALL", Permissive: true,
				Roles: []string{"public"}, Using: "true",
			},
			desired: keystonev1alpha1.DesiredPolicy{
				Name: "p", Table: "t", Command: "ALL", Permissive: true,
				Roles: nil, Using: "true",
			},
			want: true,
		},
		{
			name: "different-permissive-not-equal",
			observed: drift.PolicyShape{
				Name: "p", Table: "t", Command: "ALL", Permissive: true,
				Roles: []string{"app"}, Using: "true",
			},
			desired: keystonev1alpha1.DesiredPolicy{
				Name: "p", Table: "t", Command: "ALL", Permissive: false,
				Roles: []string{"app"}, Using: "true",
			},
			want: false,
		},
		{
			name: "different-using-not-equal",
			observed: drift.PolicyShape{
				Name: "p", Table: "t", Command: "ALL", Permissive: true,
				Roles: []string{"app"}, Using: "tenant_id = $1",
			},
			desired: keystonev1alpha1.DesiredPolicy{
				Name: "p", Table: "t", Command: "ALL", Permissive: true,
				Roles: []string{"app"}, Using: "tenant_id = $2",
			},
			want: false,
		},
		{
			name: "using-with-quoted-vs-unquoted-identifier",
			observed: drift.PolicyShape{
				Name: "p", Table: "t", Command: "ALL", Permissive: true,
				Roles: []string{"app"},
				Using: "tenant_id = current_setting('app.tenant_id')::uuid",
			},
			desired: keystonev1alpha1.DesiredPolicy{
				Name: "p", Table: "t", Command: "ALL", Permissive: true,
				Roles: []string{"app"},
				Using: `"tenant_id" = current_setting('app.tenant_id')::uuid`,
			},
			want: true,
		},
		{
			name: "with-check-only-on-one-side",
			observed: drift.PolicyShape{
				Name: "p", Table: "t", Command: "ALL", Permissive: true,
				Roles: []string{"app"}, Using: "true",
			},
			desired: keystonev1alpha1.DesiredPolicy{
				Name: "p", Table: "t", Command: "ALL", Permissive: true,
				Roles: []string{"app"}, Using: "true", WithCheck: "tenant_id IS NOT NULL",
			},
			want: false,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := policyMatches(c.observed, c.desired); got != c.want {
				t.Errorf("policyMatches() = %v, want %v", got, c.want)
			}
		})
	}
}

func TestStringSetEqualCI(t *testing.T) {
	cases := []struct {
		a, b []string
		want bool
	}{
		{[]string{"INSERT", "UPDATE"}, []string{"update", "insert"}, true},
		{[]string{"INSERT"}, []string{"INSERT", "UPDATE"}, false},
		{[]string{}, []string{}, true},
		{nil, nil, true},
		{[]string{"a", "a"}, []string{"a", "b"}, false}, // multiset semantics
	}
	for i, c := range cases {
		if got := stringSetEqualCI(c.a, c.b); got != c.want {
			t.Errorf("case %d: stringSetEqualCI(%v, %v) = %v, want %v", i, c.a, c.b, got, c.want)
		}
	}
}

func TestRolesEqual(t *testing.T) {
	cases := []struct {
		a, b []string
		want bool
	}{
		{nil, []string{"public"}, true},
		{[]string{}, []string{"PUBLIC"}, true},
		{[]string{"app", "admin"}, []string{"ADMIN", "app"}, true},
		{[]string{"app"}, []string{"public"}, false},
		{nil, nil, true},
	}
	for i, c := range cases {
		if got := rolesEqual(c.a, c.b); got != c.want {
			t.Errorf("case %d: rolesEqual(%v, %v) = %v, want %v", i, c.a, c.b, got, c.want)
		}
	}
}
