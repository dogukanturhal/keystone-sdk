// SPDX-License-Identifier: Apache-2.0

package schemaspec

import (
	"reflect"
	"testing"

	"github.com/dogukanturhal/keystone-sdk/go/drift"
)

// Tests for the extended index DDL parser. Each case is a real
// pg_indexes.indexdef sample drawn from example-service's live public schema;
// these are the shapes the inspector must round-trip cleanly.

func TestParseIndexDDL_SimpleColumns(t *testing.T) {
	idx := drift.ObjectDDL{
		Name:       "idx_users_email",
		Definition: `CREATE INDEX idx_users_email ON public.users USING btree (email)`,
	}
	got := parseIndexDDL(idx)
	if got.Name != "idx_users_email" {
		t.Errorf("name=%q, want idx_users_email", got.Name)
	}
	if !reflect.DeepEqual(got.Columns, []string{"email"}) {
		t.Errorf("Columns=%v, want [email]", got.Columns)
	}
	if got.Method != "btree" {
		t.Errorf("Method=%q, want btree", got.Method)
	}
	if got.ColumnRefs != nil {
		t.Errorf("ColumnRefs should be nil for simple form; got %v", got.ColumnRefs)
	}
}

func TestParseIndexDDL_SortDirection(t *testing.T) {
	idx := drift.ObjectDDL{
		Name:       "idx_orders_created",
		Definition: `CREATE INDEX idx_orders_created ON public.orders USING btree (tenant_id, created_at DESC)`,
	}
	got := parseIndexDDL(idx)
	if got.Columns != nil {
		t.Errorf("expected ColumnRefs path (DESC modifier present); got Columns=%v", got.Columns)
	}
	if len(got.ColumnRefs) != 2 {
		t.Fatalf("ColumnRefs length=%d, want 2", len(got.ColumnRefs))
	}
	if got.ColumnRefs[0].Name != "tenant_id" || got.ColumnRefs[0].Direction != "" {
		t.Errorf("col[0]=%+v, want tenant_id with no direction", got.ColumnRefs[0])
	}
	if got.ColumnRefs[1].Name != "created_at" || got.ColumnRefs[1].Direction != "desc" {
		t.Errorf("col[1]=%+v, want created_at DESC", got.ColumnRefs[1])
	}
}

func TestParseIndexDDL_DescNullsLast(t *testing.T) {
	idx := drift.ObjectDDL{
		Name:       "idx_iam_users_last_login",
		Definition: `CREATE INDEX idx_iam_users_last_login ON public.iam_users USING btree (tenant_id, last_login_at DESC NULLS LAST)`,
	}
	got := parseIndexDDL(idx)
	if len(got.ColumnRefs) != 2 {
		t.Fatalf("ColumnRefs length=%d, want 2", len(got.ColumnRefs))
	}
	c2 := got.ColumnRefs[1]
	if c2.Name != "last_login_at" || c2.Direction != "desc" || c2.Nulls != "last" {
		t.Errorf("col[1]=%+v, want last_login_at DESC NULLS LAST", c2)
	}
}

func TestParseIndexDDL_OpClass(t *testing.T) {
	idx := drift.ObjectDDL{
		Name:       "idx_iam_users_email_pattern",
		Definition: `CREATE INDEX idx_iam_users_email_pattern ON public.iam_users USING btree (email varchar_pattern_ops)`,
	}
	got := parseIndexDDL(idx)
	if len(got.ColumnRefs) != 1 {
		t.Fatalf("ColumnRefs length=%d, want 1", len(got.ColumnRefs))
	}
	c := got.ColumnRefs[0]
	if c.Name != "email" || c.OpClass != "varchar_pattern_ops" {
		t.Errorf("col=%+v, want email + varchar_pattern_ops", c)
	}
}

func TestParseIndexDDL_PartialPredicate(t *testing.T) {
	idx := drift.ObjectDDL{
		Name:       "idx_iam_login_risk_high",
		Definition: `CREATE INDEX idx_iam_login_risk_high ON public.iam_login_risk_events USING btree (created_at DESC) WHERE ((level)::text = ANY ((ARRAY['high'::character varying, 'critical'::character varying])::text[]))`,
	}
	got := parseIndexDDL(idx)
	if len(got.ColumnRefs) != 1 {
		t.Fatalf("ColumnRefs length=%d, want 1", len(got.ColumnRefs))
	}
	if got.ColumnRefs[0].Direction != "desc" {
		t.Errorf("col[0].Direction=%q, want desc", got.ColumnRefs[0].Direction)
	}
	if got.Where == "" {
		t.Errorf("Where clause not extracted")
	}
}

func TestParseIndexDDL_ExpressionIndex(t *testing.T) {
	idx := drift.ObjectDDL{
		Name:       "idx_users_email_lower",
		Definition: `CREATE INDEX idx_users_email_lower ON public.users USING btree ((lower(email)))`,
	}
	got := parseIndexDDL(idx)
	if got.Expression != "lower(email)" {
		t.Errorf("Expression=%q, want lower(email)", got.Expression)
	}
	if len(got.Columns) != 0 || len(got.ColumnRefs) != 0 {
		t.Errorf("expected empty Columns + ColumnRefs for expression index; got Columns=%v ColumnRefs=%v",
			got.Columns, got.ColumnRefs)
	}
}

func TestParseIndexDDL_IncludeCovering(t *testing.T) {
	idx := drift.ObjectDDL{
		Name:       "idx_orders_tenant_covering",
		Definition: `CREATE INDEX idx_orders_tenant_covering ON public.orders USING btree (tenant_id) INCLUDE (created_at, amount_cents)`,
	}
	got := parseIndexDDL(idx)
	if !reflect.DeepEqual(got.Columns, []string{"tenant_id"}) {
		t.Errorf("Columns=%v, want [tenant_id]", got.Columns)
	}
	if !reflect.DeepEqual(got.Include, []string{"created_at", "amount_cents"}) {
		t.Errorf("Include=%v, want [created_at, amount_cents]", got.Include)
	}
}

func TestParseIndexDDL_UniqueIndex(t *testing.T) {
	idx := drift.ObjectDDL{
		Name:       "idx_users_email_unique",
		Definition: `CREATE UNIQUE INDEX idx_users_email_unique ON public.users USING btree (email)`,
	}
	got := parseIndexDDL(idx)
	if !got.Unique {
		t.Errorf("Unique=false, want true")
	}
}

func TestParseIndexDDL_FullStack(t *testing.T) {
	// Realistic combination: UNIQUE + opclass + DESC NULLS LAST +
	// INCLUDE + WHERE.
	idx := drift.ObjectDDL{
		Name:       "idx_orders_premium",
		Definition: `CREATE UNIQUE INDEX idx_orders_premium ON public.orders USING btree (tenant_id varchar_pattern_ops, created_at DESC NULLS LAST) INCLUDE (amount_cents) WHERE (status = 'active')`,
	}
	got := parseIndexDDL(idx)
	if !got.Unique {
		t.Errorf("Unique not set")
	}
	if len(got.ColumnRefs) != 2 {
		t.Fatalf("ColumnRefs len=%d, want 2", len(got.ColumnRefs))
	}
	if got.ColumnRefs[0].OpClass != "varchar_pattern_ops" {
		t.Errorf("col[0].OpClass=%q, want varchar_pattern_ops", got.ColumnRefs[0].OpClass)
	}
	if got.ColumnRefs[1].Direction != "desc" || got.ColumnRefs[1].Nulls != "last" {
		t.Errorf("col[1] modifiers wrong: %+v", got.ColumnRefs[1])
	}
	if !reflect.DeepEqual(got.Include, []string{"amount_cents"}) {
		t.Errorf("Include=%v, want [amount_cents]", got.Include)
	}
	if got.Where == "" {
		t.Errorf("Where not extracted")
	}
}

func TestSplitTopLevelCommas(t *testing.T) {
	// Index columns can be expressions containing commas — split must
	// respect parens depth.
	got := splitTopLevelCommas(`a, b, coalesce(x, y, 'z'), d`)
	want := []string{"a", " b", " coalesce(x, y, 'z')", " d"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("splitTopLevelCommas:\n got: %v\nwant: %v", got, want)
	}
}

func TestMatchedParens_Nested(t *testing.T) {
	open, closeIdx := matchedParens(`USING btree (a, b, (c, d))`)
	if open < 0 || closeIdx <= open {
		t.Fatalf("got open=%d close=%d", open, closeIdx)
	}
	// Should match the OUTER parens.
	got := `USING btree (a, b, (c, d))`[open : closeIdx+1]
	if got != `(a, b, (c, d))` {
		t.Errorf("matched=%q, want (a, b, (c, d))", got)
	}
}
