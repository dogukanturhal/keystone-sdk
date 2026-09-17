// SPDX-License-Identifier: AGPL-3.0-or-later

package declarative

import (
	"testing"

	keystonev1alpha1 "github.com/dogukanturhal/keystone/api/v1alpha1"
)

func TestNullsNotDistinct_RenderEmitsKeyword(t *testing.T) {
	idx := keystonev1alpha1.DesiredIndex{
		Name: "iam_policies_tenant_id_name_key", Unique: true,
		NullsNotDistinct: true,
		Columns:          []string{"tenant_id", "name"},
	}
	got := renderCreateIndexConcurrently("public", "iam_policies", idx)
	want := `CREATE UNIQUE INDEX CONCURRENTLY IF NOT EXISTS "iam_policies_tenant_id_name_key" ON "public"."iam_policies" USING btree ("tenant_id", "name") NULLS NOT DISTINCT`
	if got != want {
		t.Errorf("\n got: %s\nwant: %s", got, want)
	}
}

func TestNullsNotDistinct_NotEmittedWithoutUnique(t *testing.T) {
	idx := keystonev1alpha1.DesiredIndex{
		Name: "x", Unique: false, NullsNotDistinct: true,
		Columns: []string{"a"},
	}
	got := renderCreateIndexConcurrently("public", "t", idx)
	if containsSubstr(got, "NULLS NOT DISTINCT") {
		t.Errorf("non-unique index should not emit NULLS NOT DISTINCT: %s", got)
	}
}

func TestNullsNotDistinct_DiffMatchesPgGetIndexdef(t *testing.T) {
	// PG returns NULLS NOT DISTINCT for unique-with-not-distinct
	// indexes; renderer emits the same token. After normaliseDDL the
	// two should compare equal.
	observed := `CREATE UNIQUE INDEX iam_policies_tenant_id_name_key ON public.iam_policies USING btree (tenant_id, name) NULLS NOT DISTINCT`
	rendered := `CREATE UNIQUE INDEX CONCURRENTLY IF NOT EXISTS "iam_policies_tenant_id_name_key" ON "public"."iam_policies" USING btree ("tenant_id", "name") NULLS NOT DISTINCT`
	if !indexDDLMatch(observed, rendered) {
		t.Errorf("expected match:\n  obs: %s\n  ren: %s\n  norm-obs: %q\n  norm-ren: %q",
			observed, rendered, normaliseDDL(observed), normaliseDDL(rendered))
	}
}

func containsSubstr(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
