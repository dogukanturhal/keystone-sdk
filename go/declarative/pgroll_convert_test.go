// SPDX-License-Identifier: AGPL-3.0-or-later

package declarative

import (
	"testing"

	keystonev1alpha1 "github.com/dogukanturhal/keystone/api/v1alpha1"
)

func TestPlanToOperations_AddColumn(t *testing.T) {
	plan := &Plan{
		Statements: []string{
			`ALTER TABLE "billing"."invoices" ADD COLUMN "tax_rate" numeric NOT NULL DEFAULT 0.0`,
		},
	}
	ops, unconvertible := PlanToOperations(plan)
	if len(unconvertible) != 0 {
		t.Errorf("unexpected unconvertible: %v", unconvertible)
	}
	if len(ops) != 1 {
		t.Fatalf("expected 1 op, got %d", len(ops))
	}
	op := ops[0]
	if op.Kind != keystonev1alpha1.MigrationOperationAddColumn {
		t.Errorf("kind = %q, want add_column", op.Kind)
	}
	if op.Table != "invoices" {
		t.Errorf("table = %q, want invoices", op.Table)
	}
	if op.AddColumn == nil {
		t.Fatal("AddColumn is nil")
	}
	if op.AddColumn.Name != "tax_rate" {
		t.Errorf("name = %q", op.AddColumn.Name)
	}
	if op.AddColumn.Type != "numeric" {
		t.Errorf("type = %q", op.AddColumn.Type)
	}
	if op.AddColumn.Nullable {
		t.Error("expected nullable=false")
	}
	if op.AddColumn.Default != "0.0" {
		t.Errorf("default = %q, want 0.0", op.AddColumn.Default)
	}
}

func TestPlanToOperations_AddColumnNullable(t *testing.T) {
	plan := &Plan{
		Statements: []string{
			`ALTER TABLE "app"."users" ADD COLUMN "bio" text`,
		},
	}
	ops, _ := PlanToOperations(plan)
	if len(ops) != 1 {
		t.Fatalf("expected 1 op, got %d", len(ops))
	}
	if !ops[0].AddColumn.Nullable {
		t.Error("expected nullable=true for column without NOT NULL")
	}
}

func TestPlanToOperations_DropColumn(t *testing.T) {
	plan := &Plan{
		Statements: []string{
			`ALTER TABLE "app"."users" DROP COLUMN "legacy_field"`,
		},
	}
	ops, _ := PlanToOperations(plan)
	if len(ops) != 1 {
		t.Fatalf("expected 1 op, got %d", len(ops))
	}
	if ops[0].Kind != keystonev1alpha1.MigrationOperationDropColumn {
		t.Errorf("kind = %q", ops[0].Kind)
	}
	if ops[0].DropColumn.Name != "legacy_field" {
		t.Errorf("name = %q", ops[0].DropColumn.Name)
	}
}

func TestPlanToOperations_SetNotNull(t *testing.T) {
	plan := &Plan{
		Statements: []string{
			`ALTER TABLE "app"."orders" ALTER COLUMN "status" SET NOT NULL`,
		},
	}
	ops, _ := PlanToOperations(plan)
	if len(ops) != 1 {
		t.Fatalf("expected 1 op, got %d", len(ops))
	}
	if ops[0].Kind != keystonev1alpha1.MigrationOperationSetNotNull {
		t.Errorf("kind = %q", ops[0].Kind)
	}
	if ops[0].SetNotNull.Column != "status" {
		t.Errorf("column = %q", ops[0].SetNotNull.Column)
	}
}

func TestPlanToOperations_DropNotNull(t *testing.T) {
	plan := &Plan{
		Statements: []string{
			`ALTER TABLE "app"."orders" ALTER COLUMN "notes" DROP NOT NULL`,
		},
	}
	ops, _ := PlanToOperations(plan)
	if len(ops) != 1 {
		t.Fatalf("expected 1 op, got %d", len(ops))
	}
	if ops[0].Kind != keystonev1alpha1.MigrationOperationDropNotNull {
		t.Errorf("kind = %q", ops[0].Kind)
	}
}

func TestPlanToOperations_AddConstraintFK(t *testing.T) {
	plan := &Plan{
		Statements: []string{
			`ALTER TABLE "sales"."orders" ADD CONSTRAINT "orders_customer_fk" FOREIGN KEY ("customer_id") REFERENCES "sales"."customers" ("id") ON DELETE CASCADE NOT VALID`,
		},
	}
	ops, _ := PlanToOperations(plan)
	if len(ops) != 1 {
		t.Fatalf("expected 1 op, got %d", len(ops))
	}
	if ops[0].Kind != keystonev1alpha1.MigrationOperationAddConstraint {
		t.Errorf("kind = %q", ops[0].Kind)
	}
	if ops[0].AddConstraint.Type != "foreign_key" {
		t.Errorf("type = %q, want foreign_key", ops[0].AddConstraint.Type)
	}
	if ops[0].AddConstraint.Name != "orders_customer_fk" {
		t.Errorf("name = %q", ops[0].AddConstraint.Name)
	}
}

func TestPlanToOperations_Unconvertible(t *testing.T) {
	plan := &Plan{
		Statements: []string{
			`CREATE TABLE "app"."new_table" (id uuid PRIMARY KEY)`,
			`CREATE INDEX CONCURRENTLY IF NOT EXISTS "idx_email" ON "app"."users" USING btree ("email")`,
			`ALTER TABLE "app"."users" ADD COLUMN "age" integer`,
		},
	}
	ops, unconvertible := PlanToOperations(plan)
	if len(ops) != 1 {
		t.Errorf("expected 1 convertible op, got %d", len(ops))
	}
	if len(unconvertible) != 2 {
		t.Errorf("expected 2 unconvertible, got %d: %v", len(unconvertible), unconvertible)
	}
}

func TestPlanToOperations_NilPlan(t *testing.T) {
	ops, unconvertible := PlanToOperations(nil)
	if ops != nil || unconvertible != nil {
		t.Errorf("nil plan should return nils")
	}
}

func TestPlanToOperations_EmptyPlan(t *testing.T) {
	ops, unconvertible := PlanToOperations(&Plan{})
	if len(ops) != 0 || len(unconvertible) != 0 {
		t.Errorf("empty plan should return empty slices")
	}
}

func TestPlanToOperations_MixedStatements(t *testing.T) {
	plan := &Plan{
		Statements: []string{
			`ALTER TABLE "app"."users" ADD COLUMN "phone" text`,
			`ALTER TABLE "app"."users" ALTER COLUMN "email" SET NOT NULL`,
			`CREATE OR REPLACE VIEW "app"."active_users" AS SELECT * FROM users WHERE active`,
			`ALTER TABLE "app"."orders" DROP COLUMN "obsolete"`,
		},
	}
	ops, unconvertible := PlanToOperations(plan)
	if len(ops) != 3 {
		t.Errorf("expected 3 convertible ops, got %d", len(ops))
	}
	if len(unconvertible) != 1 {
		t.Errorf("expected 1 unconvertible (VIEW), got %d", len(unconvertible))
	}
}
