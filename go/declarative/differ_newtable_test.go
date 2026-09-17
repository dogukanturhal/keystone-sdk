// SPDX-License-Identifier: AGPL-3.0-or-later

package declarative

import (
	"strings"
	"testing"

	keystonev1alpha1 "github.com/dogukanturhal/keystone/api/v1alpha1"
	"github.com/dogukanturhal/keystone-sdk/go/drift"
)

// TestDiff_NewTableEmitsIndexesAndForeignKeys guards the fidelity fix:
// renderCreateTable only emits columns + the primary key, so a brand-new
// table's secondary objects (indexes, foreign keys) must be emitted by
// diffTableObjects in the create path. Without it, a from-empty diff
// (scaffold baseline, or `migrate diff` adding a new table) would silently
// drop every index and FK.
func TestDiff_NewTableEmitsIndexesAndForeignKeys(t *testing.T) {
	observed := &drift.Snapshot{Schema: "app"} // empty: everything is new

	desired := &keystonev1alpha1.SchemaDefinitionSpec{
		Tables: []keystonev1alpha1.DesiredTable{
			{
				Name: "customers",
				Columns: []keystonev1alpha1.DesiredColumn{
					{Name: "id", Type: "bigint", PrimaryKey: true},
					{Name: "email", Type: "text"},
				},
				Indexes: []keystonev1alpha1.DesiredIndex{
					{Name: "idx_customers_email", Columns: []string{"email"}, Unique: true},
				},
			},
			{
				Name: "orders",
				Columns: []keystonev1alpha1.DesiredColumn{
					{Name: "id", Type: "bigint", PrimaryKey: true},
					{Name: "customer_id", Type: "bigint"},
				},
				ForeignKeys: []keystonev1alpha1.DesiredForeignKey{
					{
						Name:              "orders_customer_fk",
						Columns:           []string{"customer_id"},
						ReferencesTable:   "customers",
						ReferencesColumns: []string{"id"},
						OnDelete:          "CASCADE",
					},
				},
			},
		},
	}

	plan, err := Diff(observed, desired)
	if err != nil {
		t.Fatalf("Diff: %v", err)
	}
	all := strings.Join(plan.Statements, "\n")

	if !strings.Contains(all, `CREATE TABLE "app"."customers"`) || !strings.Contains(all, `CREATE TABLE "app"."orders"`) {
		t.Fatalf("missing CREATE TABLE statements:\n%s", all)
	}
	if !strings.Contains(all, `idx_customers_email`) {
		t.Errorf("new table's index was dropped from the plan:\n%s", all)
	}
	if !strings.Contains(all, `orders_customer_fk`) || !strings.Contains(all, `REFERENCES "app"."customers"`) {
		t.Errorf("new table's foreign key was dropped from the plan:\n%s", all)
	}

	// CREATE TABLE for the FK target must precede the ADD CONSTRAINT so the
	// reference resolves at apply time.
	createCustomers := strings.Index(all, `CREATE TABLE "app"."customers"`)
	addFK := strings.Index(all, "orders_customer_fk")
	if createCustomers < 0 || addFK < 0 || createCustomers > addFK {
		t.Errorf("FK ADD must come after its target table's CREATE:\n%s", all)
	}
}

// TestDiff_CompositeInlinePrimaryKeyHasComma guards the missing-comma
// regression: when ≥2 columns carry PrimaryKey:true (composite PK) but no
// table-level PrimaryKey list is set, renderCreateTable suppresses the inline
// PRIMARY KEY and synthesises a table-level "PRIMARY KEY (a, b)" line. The
// last column line must still be terminated with a comma before that line,
// otherwise the emitted DDL is invalid SQL — e.g. for
// iam_oauth_client_trusted_external_issuers this produced
//
//	"created_by" uuid
//	PRIMARY KEY ("client_id", "issuer_id")
//
// → `syntax error at or near "("` at apply time.
func TestDiff_CompositeInlinePrimaryKeyHasComma(t *testing.T) {
	observed := &drift.Snapshot{Schema: "app"} // empty: table is new

	desired := &keystonev1alpha1.SchemaDefinitionSpec{
		Tables: []keystonev1alpha1.DesiredTable{
			{
				Name: "client_issuers",
				Columns: []keystonev1alpha1.DesiredColumn{
					{Name: "client_id", Type: "uuid", PrimaryKey: true},
					{Name: "issuer_id", Type: "uuid", PrimaryKey: true},
					{Name: "created_by", Type: "uuid"}, // non-PK trailing column
				},
			},
		},
	}

	plan, err := Diff(observed, desired)
	if err != nil {
		t.Fatalf("Diff: %v", err)
	}
	all := strings.Join(plan.Statements, "\n")

	if !strings.Contains(all, `PRIMARY KEY ("client_id", "issuer_id")`) {
		t.Fatalf("expected synthesised composite PRIMARY KEY clause:\n%s", all)
	}
	// The synthesised PRIMARY KEY line must be preceded by a comma terminating
	// the last column definition — otherwise the DDL is invalid SQL.
	if !strings.Contains(all, ",\n    PRIMARY KEY (") {
		t.Errorf("composite PRIMARY KEY line not comma-separated from last column (invalid SQL):\n%s", all)
	}
	// The no-comma signature (`<col> NOT NULL` directly followed by PRIMARY KEY)
	// must NOT appear — that was the bug.
	if strings.Contains(all, "NOT NULL\n    PRIMARY KEY") {
		t.Errorf("last column line directly followed by PRIMARY KEY without comma — invalid DDL:\n%s", all)
	}
}
