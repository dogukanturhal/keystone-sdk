// SPDX-License-Identifier: AGPL-3.0-or-later

package analyze

import (
	"context"
	"strings"
	"testing"

	keystonev1alpha1 "github.com/dogukanturhal/keystone/api/v1alpha1"
)

func TestCrossBundleBreak_DropTableReferencedByPending(t *testing.T) {
	a := &CrossBundleBreakDetector{}
	m := &Migration{
		Files: []FileBody{
			{Name: "001.up.sql", Body: "DROP TABLE users;"},
		},
		SchemaObjects: &SchemaObjectSet{
			Tables: map[string]map[string]bool{
				"users": {"id": true, "email": true},
			},
		},
		PendingBundleSQL: []FileBody{
			{Name: "pending_001.up.sql", Body: "ALTER TABLE users ADD COLUMN phone text;"},
		},
	}

	findings, err := a.Check(context.Background(), m)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d: %+v", len(findings), findings)
	}
	if findings[0].Rule != "cross-bundle-breaking-change" {
		t.Errorf("rule = %q", findings[0].Rule)
	}
	if findings[0].Severity != keystonev1alpha1.LintLevelError {
		t.Errorf("severity = %q", findings[0].Severity)
	}
	if !strings.Contains(findings[0].Message, "DROP TABLE users") {
		t.Errorf("message = %q", findings[0].Message)
	}
}

func TestCrossBundleBreak_DropColumnReferencedByPending(t *testing.T) {
	a := &CrossBundleBreakDetector{}
	m := &Migration{
		Files: []FileBody{
			{Name: "001.up.sql", Body: "ALTER TABLE orders DROP COLUMN customer_id;"},
		},
		SchemaObjects: &SchemaObjectSet{
			Tables: map[string]map[string]bool{
				"orders": {"id": true, "customer_id": true},
			},
		},
		PendingBundleSQL: []FileBody{
			{Name: "pending.up.sql", Body: "ALTER TABLE orders ALTER COLUMN customer_id SET NOT NULL;"},
		},
	}

	findings, err := a.Check(context.Background(), m)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d: %+v", len(findings), findings)
	}
	if !strings.Contains(findings[0].Message, "DROP COLUMN orders.customer_id") {
		t.Errorf("message = %q", findings[0].Message)
	}
}

func TestCrossBundleBreak_RenameColumnReferencedByPending(t *testing.T) {
	a := &CrossBundleBreakDetector{}
	m := &Migration{
		Files: []FileBody{
			{Name: "001.up.sql", Body: "ALTER TABLE products RENAME COLUMN sku TO product_code;"},
		},
		SchemaObjects: &SchemaObjectSet{
			Tables: map[string]map[string]bool{
				"products": {"id": true, "sku": true},
			},
		},
		PendingBundleSQL: []FileBody{
			{Name: "pending.up.sql", Body: "ALTER TABLE products ALTER COLUMN sku SET DEFAULT 'UNKNOWN';"},
		},
	}

	findings, err := a.Check(context.Background(), m)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d: %+v", len(findings), findings)
	}
	if !strings.Contains(findings[0].Message, "RENAME COLUMN products.sku TO product_code") {
		t.Errorf("message = %q", findings[0].Message)
	}
}

func TestCrossBundleBreak_DropIndexReferencedByPending(t *testing.T) {
	a := &CrossBundleBreakDetector{}
	m := &Migration{
		Files: []FileBody{
			{Name: "001.up.sql", Body: "DROP INDEX idx_users_email;"},
		},
		SchemaObjects: &SchemaObjectSet{
			Indexes: map[string]bool{"idx_users_email": true},
		},
		PendingBundleSQL: []FileBody{
			{Name: "pending.up.sql", Body: "DROP INDEX CONCURRENTLY idx_users_email;\nCREATE INDEX CONCURRENTLY idx_users_email ON users(email, name);"},
		},
	}

	findings, err := a.Check(context.Background(), m)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d: %+v", len(findings), findings)
	}
	if !strings.Contains(findings[0].Message, "DROP INDEX idx_users_email") {
		t.Errorf("message = %q", findings[0].Message)
	}
}

func TestCrossBundleBreak_NoPendingBundles(t *testing.T) {
	a := &CrossBundleBreakDetector{}
	m := &Migration{
		Files: []FileBody{
			{Name: "001.up.sql", Body: "DROP TABLE users;"},
		},
		SchemaObjects: &SchemaObjectSet{
			Tables: map[string]map[string]bool{
				"users": {"id": true},
			},
		},
		PendingBundleSQL: nil, // no pending bundles
	}

	findings, err := a.Check(context.Background(), m)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings with no pending bundles, got %d", len(findings))
	}
}

func TestCrossBundleBreak_NilSchemaObjects(t *testing.T) {
	a := &CrossBundleBreakDetector{}
	m := &Migration{
		Files: []FileBody{
			{Name: "001.up.sql", Body: "DROP TABLE users;"},
		},
		SchemaObjects:    nil,
		PendingBundleSQL: []FileBody{{Name: "p.sql", Body: "SELECT * FROM users;"}},
	}

	findings, err := a.Check(context.Background(), m)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings with nil schema objects, got %d", len(findings))
	}
}

func TestCrossBundleBreak_DropTableNotReferencedByPending(t *testing.T) {
	a := &CrossBundleBreakDetector{}
	m := &Migration{
		Files: []FileBody{
			{Name: "001.up.sql", Body: "DROP TABLE old_logs;"},
		},
		SchemaObjects: &SchemaObjectSet{
			Tables: map[string]map[string]bool{
				"old_logs": {"id": true},
				"users":    {"id": true},
			},
		},
		PendingBundleSQL: []FileBody{
			{Name: "pending.up.sql", Body: "ALTER TABLE users ADD COLUMN age int;"},
		},
	}

	findings, err := a.Check(context.Background(), m)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for non-referenced table, got %d: %+v", len(findings), findings)
	}
}

func TestExtractReferences(t *testing.T) {
	pending := []FileBody{
		{Name: "a.sql", Body: "ALTER TABLE orders ADD COLUMN total numeric;\nCREATE INDEX idx_orders_total ON orders(total);"},
		{Name: "b.sql", Body: "INSERT INTO users SELECT * FROM customers;"},
	}

	refs := extractReferences(pending)

	if !refs.TableRefs["orders"] {
		t.Error("expected orders in table refs")
	}
	if !refs.TableRefs["users"] {
		t.Error("expected users in table refs")
	}
	if !refs.TableRefs["customers"] {
		t.Error("expected customers in table refs")
	}
	if !refs.ColumnRefs["orders.total"] {
		t.Error("expected orders.total in column refs")
	}
	if !refs.IndexRefs["idx_orders_total"] {
		t.Error("expected idx_orders_total in index refs")
	}
}

func TestCrossBundleBreak_RegisteredInDefaultRegistry(t *testing.T) {
	reg := DefaultRegistry()
	found := false
	for _, a := range reg.analyzers {
		if a.ID() == "cross-bundle-breaking-change" {
			found = true
			break
		}
	}
	if !found {
		t.Error("CrossBundleBreakDetector not registered in DefaultRegistry")
	}
}
