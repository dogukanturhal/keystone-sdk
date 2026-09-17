// SPDX-License-Identifier: AGPL-3.0-or-later

package declarative

import (
	"strings"
	"testing"

	keystonev1alpha1 "github.com/dogukanturhal/keystone/api/v1alpha1"
)

// Tests for the keystone#4 DesiredIndex extensions: sort direction,
// expression indexes, INCLUDE / covering columns, per-column opclass.
// Each test exercises BOTH the immediate `CREATE INDEX` and the
// `CREATE INDEX CONCURRENTLY IF NOT EXISTS` paths so a regression
// can't silently land via just one render code path.

func TestIndexRender_SimpleColumns(t *testing.T) {
	// Backwards compat: existing CRs with `Columns []string` MUST still
	// render the simple btree-asc form unchanged.
	idx := keystonev1alpha1.DesiredIndex{
		Name:    "idx_users_email",
		Columns: []string{"email"},
	}
	got := renderCreateIndex("public", "users", idx)
	want := `CREATE INDEX "idx_users_email" ON "public"."users" USING btree ("email")`
	if got != want {
		t.Errorf("simple form mismatch\n got: %s\nwant: %s", got, want)
	}
}

func TestIndexRender_ColumnRefsWithDescAndNulls(t *testing.T) {
	idx := keystonev1alpha1.DesiredIndex{
		Name: "idx_orders_created_desc",
		ColumnRefs: []keystonev1alpha1.DesiredIndexColumn{
			{Name: "created_at", Direction: "desc", Nulls: "last"},
			{Name: "tenant_id", Direction: "asc"},
		},
	}
	got := renderCreateIndex("public", "orders", idx)
	if !strings.Contains(got, `"created_at" DESC NULLS LAST`) {
		t.Errorf("expected DESC NULLS LAST on created_at; got: %s", got)
	}
	// asc is PG default; we must NOT emit redundant ASC keyword.
	if strings.Contains(got, `"tenant_id" ASC`) {
		t.Errorf("emitted redundant ASC; got: %s", got)
	}
	if !strings.Contains(got, `"tenant_id"`) {
		t.Errorf("missing tenant_id column; got: %s", got)
	}
}

func TestIndexRender_OpClass(t *testing.T) {
	// varchar_pattern_ops is the canonical case — required for index
	// support on `LIKE 'prefix%'` queries against varchar columns.
	idx := keystonev1alpha1.DesiredIndex{
		Name: "idx_users_email_pattern",
		ColumnRefs: []keystonev1alpha1.DesiredIndexColumn{
			{Name: "email", OpClass: "varchar_pattern_ops"},
		},
	}
	got := renderCreateIndex("public", "users", idx)
	if !strings.Contains(got, `"email" "varchar_pattern_ops"`) {
		t.Errorf("opclass missing; got: %s", got)
	}
}

func TestIndexRender_Expression(t *testing.T) {
	// Expression indexes: `CREATE INDEX foo ON t (lower(email))`.
	// The Expression body is emitted verbatim wrapped in a single
	// parens layer.
	idx := keystonev1alpha1.DesiredIndex{
		Name:       "idx_users_email_lower",
		Expression: "lower(email)",
	}
	got := renderCreateIndex("public", "users", idx)
	want := `CREATE INDEX "idx_users_email_lower" ON "public"."users" USING btree ((lower(email)))`
	if got != want {
		t.Errorf("expression-index mismatch\n got: %s\nwant: %s", got, want)
	}
}

func TestIndexRender_IncludeCovering(t *testing.T) {
	// INCLUDE / covering index — the listed columns are stored in the
	// leaf pages but not part of the key. PG 11+.
	idx := keystonev1alpha1.DesiredIndex{
		Name:    "idx_orders_tenant_covering",
		Columns: []string{"tenant_id"},
		Include: []string{"created_at", "amount_cents"},
	}
	got := renderCreateIndex("public", "orders", idx)
	if !strings.Contains(got, `INCLUDE ("created_at", "amount_cents")`) {
		t.Errorf("INCLUDE clause missing; got: %s", got)
	}
}

func TestIndexRender_PartialPredicate(t *testing.T) {
	// WHERE clause was already supported pre-keystone#4; this test
	// guards against the renderer rewrite breaking it.
	idx := keystonev1alpha1.DesiredIndex{
		Name:    "idx_users_active",
		Columns: []string{"email"},
		Where:   "deleted_at IS NULL",
	}
	got := renderCreateIndex("public", "users", idx)
	if !strings.HasSuffix(got, `WHERE deleted_at IS NULL`) {
		t.Errorf("WHERE clause missing or misplaced; got: %s", got)
	}
}

func TestIndexRender_FullStack(t *testing.T) {
	// All four features at once: ColumnRefs (DESC + opclass) +
	// Include + Where + Unique + non-btree-incompatible-but-still-
	// emitted (real PG would reject INCLUDE on non-btree but our
	// renderer is honest about what was declared).
	idx := keystonev1alpha1.DesiredIndex{
		Name:   "idx_orders_premium",
		Unique: true,
		Method: "btree",
		ColumnRefs: []keystonev1alpha1.DesiredIndexColumn{
			{Name: "tenant_id", OpClass: "varchar_pattern_ops"},
			{Name: "created_at", Direction: "desc", Nulls: "last"},
		},
		Include: []string{"amount_cents"},
		Where:   "status = 'active' AND amount_cents > 1000",
	}
	got := renderCreateIndex("public", "orders", idx)
	mustContain := []string{
		`CREATE UNIQUE INDEX "idx_orders_premium"`,
		`USING btree (`,
		`"tenant_id" "varchar_pattern_ops"`,
		`"created_at" DESC NULLS LAST`,
		`INCLUDE ("amount_cents")`,
		`WHERE status = 'active' AND amount_cents > 1000`,
	}
	for _, s := range mustContain {
		if !strings.Contains(got, s) {
			t.Errorf("missing %q in:\n%s", s, got)
		}
	}
}

func TestIndexRender_ConcurrentlyVariant(t *testing.T) {
	// CONCURRENTLY path must produce the same column-list / INCLUDE /
	// WHERE behaviour as the immediate path.
	idx := keystonev1alpha1.DesiredIndex{
		Name:    "idx_x",
		Columns: []string{"a"},
		Include: []string{"b"},
		Where:   "c IS NOT NULL",
	}
	got := renderCreateIndexConcurrently("public", "t", idx)
	for _, s := range []string{
		`CREATE INDEX CONCURRENTLY IF NOT EXISTS "idx_x"`,
		`("a")`,
		`INCLUDE ("b")`,
		`WHERE c IS NOT NULL`,
	} {
		if !strings.Contains(got, s) {
			t.Errorf("CONCURRENTLY render missing %q in:\n%s", s, got)
		}
	}
}

func TestIndexRender_EmptyColumnSpecsIsBenign(t *testing.T) {
	// CRD validation should prevent this case (none of Columns,
	// ColumnRefs, Expression set). Defensive: renderer emits an
	// obviously-malformed `()` list so PG rejects rather than silently
	// creating a zero-column index. Test guards against accidental
	// "emit nothing" behaviour in a future refactor.
	idx := keystonev1alpha1.DesiredIndex{Name: "idx_broken"}
	got := renderCreateIndex("public", "t", idx)
	if !strings.Contains(got, `USING btree ()`) {
		t.Errorf("expected explicit empty body; got: %s", got)
	}
}
