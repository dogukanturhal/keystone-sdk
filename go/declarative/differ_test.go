// SPDX-License-Identifier: AGPL-3.0-or-later

package declarative

import (
	"errors"
	"strings"
	"testing"

	"github.com/dogukanturhal/keystone-sdk/go/drift"
	keystonev1alpha1 "github.com/dogukanturhal/keystone/api/v1alpha1"
)

func TestDiff_EmptySchema_CreatesEverything(t *testing.T) {
	obs := &drift.Snapshot{Schema: "crm"}
	desired := &keystonev1alpha1.SchemaDefinitionSpec{
		SchemaRef: "crm",
		Tables: []keystonev1alpha1.DesiredTable{
			{
				Name: "leads",
				Columns: []keystonev1alpha1.DesiredColumn{
					{Name: "id", Type: "uuid", Nullable: false, PrimaryKey: true, Default: "gen_random_uuid()"},
					{Name: "email", Type: "text", Nullable: false},
				},
			},
		},
	}
	plan, err := Diff(obs, desired)
	if err != nil {
		t.Fatalf("Diff: %v", err)
	}
	if len(plan.Statements) != 1 {
		t.Fatalf("expected 1 statement, got %d: %v", len(plan.Statements), plan.Statements)
	}
	if !strings.Contains(plan.Statements[0], "CREATE TABLE") {
		t.Errorf("expected CREATE TABLE, got %q", plan.Statements[0])
	}
	if !strings.Contains(plan.Statements[0], `"leads"`) {
		t.Errorf("expected table name quoted, got %q", plan.Statements[0])
	}
	if plan.DestructiveOps != 0 {
		t.Errorf("expected 0 destructive ops, got %d", plan.DestructiveOps)
	}
	// Reverse should be DROP TABLE.
	if len(plan.ReverseStatements) != 1 || !strings.Contains(plan.ReverseStatements[0], "DROP TABLE") {
		t.Errorf("expected reverse DROP TABLE, got %v", plan.ReverseStatements)
	}
}

func TestDiff_MatchingState_EmptyPlan(t *testing.T) {
	obs := &drift.Snapshot{
		Schema: "crm",
		Tables: []drift.TableShape{
			{
				Name: "leads",
				Kind: "BASE TABLE",
				Columns: []drift.ColumnShape{
					{Name: "id", Ordinal: 1, DataType: "uuid", Nullable: false, Default: "gen_random_uuid()"},
					{Name: "email", Ordinal: 2, DataType: "text", Nullable: false},
				},
			},
		},
	}
	desired := &keystonev1alpha1.SchemaDefinitionSpec{
		SchemaRef: "crm",
		Tables: []keystonev1alpha1.DesiredTable{
			{
				Name: "leads",
				Columns: []keystonev1alpha1.DesiredColumn{
					{Name: "id", Type: "uuid", Nullable: false, Default: "gen_random_uuid()", PrimaryKey: true},
					{Name: "email", Type: "text", Nullable: false},
				},
			},
		},
	}
	plan, err := Diff(obs, desired)
	if err != nil {
		t.Fatalf("Diff: %v", err)
	}
	if !plan.Empty() {
		t.Errorf("expected empty plan, got %d statements: %v", len(plan.Statements), plan.Statements)
	}
}

func TestDiff_AddColumn(t *testing.T) {
	obs := &drift.Snapshot{
		Schema: "crm",
		Tables: []drift.TableShape{
			{
				Name:    "leads",
				Kind:    "BASE TABLE",
				Columns: []drift.ColumnShape{{Name: "id", Ordinal: 1, DataType: "uuid", Nullable: false}},
			},
		},
	}
	desired := &keystonev1alpha1.SchemaDefinitionSpec{
		SchemaRef: "crm",
		Tables: []keystonev1alpha1.DesiredTable{
			{
				Name: "leads",
				Columns: []keystonev1alpha1.DesiredColumn{
					{Name: "id", Type: "uuid", Nullable: false},
					{Name: "score", Type: "numeric", Nullable: true},
				},
			},
		},
	}
	plan, err := Diff(obs, desired)
	if err != nil {
		t.Fatalf("Diff: %v", err)
	}
	if len(plan.Statements) != 1 {
		t.Fatalf("expected 1 statement, got %d", len(plan.Statements))
	}
	s := plan.Statements[0]
	if !strings.Contains(s, "ADD COLUMN") || !strings.Contains(s, `"score"`) {
		t.Errorf("expected ADD COLUMN score, got %q", s)
	}
	if plan.DestructiveOps != 0 {
		t.Errorf("non-destructive op, got %d", plan.DestructiveOps)
	}
	// Reverse should be DROP COLUMN.
	if !strings.Contains(plan.ReverseStatements[0], "DROP COLUMN") {
		t.Errorf("expected reverse DROP COLUMN, got %q", plan.ReverseStatements[0])
	}
}

func TestDiff_DropColumn_RefusedWhenDestructiveDisabled(t *testing.T) {
	obs := &drift.Snapshot{
		Schema: "crm",
		Tables: []drift.TableShape{
			{
				Name: "leads",
				Kind: "BASE TABLE",
				Columns: []drift.ColumnShape{
					{Name: "id", Ordinal: 1, DataType: "uuid", Nullable: false},
					{Name: "deprecated_field", Ordinal: 2, DataType: "text", Nullable: true},
				},
			},
		},
	}
	desired := &keystonev1alpha1.SchemaDefinitionSpec{
		SchemaRef:        "crm",
		AllowDestructive: false,
		Tables: []keystonev1alpha1.DesiredTable{
			{
				Name: "leads",
				Columns: []keystonev1alpha1.DesiredColumn{
					{Name: "id", Type: "uuid", Nullable: false},
				},
			},
		},
	}
	plan, err := Diff(obs, desired)
	if err == nil {
		t.Fatal("expected ErrDestructiveRefused, got nil")
	}
	var dr *ErrDestructiveRefused
	if !errors.As(err, &dr) {
		t.Fatalf("expected ErrDestructiveRefused, got %T: %v", err, err)
	}
	if plan.DestructiveOps != 1 {
		t.Errorf("expected 1 destructive op, got %d", plan.DestructiveOps)
	}
	if len(plan.Statements) != 1 {
		t.Errorf("plan should still contain the DROP COLUMN for review, got %d", len(plan.Statements))
	}
}

func TestDiff_DropColumn_AllowedWhenDestructiveTrue(t *testing.T) {
	obs := &drift.Snapshot{
		Schema: "crm",
		Tables: []drift.TableShape{
			{
				Name: "leads",
				Kind: "BASE TABLE",
				Columns: []drift.ColumnShape{
					{Name: "id", Ordinal: 1, DataType: "uuid", Nullable: false},
					{Name: "deprecated_field", Ordinal: 2, DataType: "text", Nullable: true},
				},
			},
		},
	}
	desired := &keystonev1alpha1.SchemaDefinitionSpec{
		SchemaRef:        "crm",
		AllowDestructive: true,
		Tables: []keystonev1alpha1.DesiredTable{
			{
				Name: "leads",
				Columns: []keystonev1alpha1.DesiredColumn{
					{Name: "id", Type: "uuid", Nullable: false},
				},
			},
		},
	}
	plan, err := Diff(obs, desired)
	if err != nil {
		t.Fatalf("Diff: %v", err)
	}
	if plan.DestructiveOps != 1 {
		t.Errorf("expected 1 destructive op, got %d", plan.DestructiveOps)
	}
	if len(plan.Statements) != 1 || !strings.Contains(plan.Statements[0], "DROP COLUMN") {
		t.Errorf("expected DROP COLUMN statement, got %v", plan.Statements)
	}
}

func TestDiff_TypeChange_WarnsNotEmits(t *testing.T) {
	obs := &drift.Snapshot{
		Schema: "crm",
		Tables: []drift.TableShape{
			{
				Name:    "leads",
				Kind:    "BASE TABLE",
				Columns: []drift.ColumnShape{{Name: "score", Ordinal: 1, DataType: "integer", Nullable: true}},
			},
		},
	}
	desired := &keystonev1alpha1.SchemaDefinitionSpec{
		SchemaRef: "crm",
		Tables: []keystonev1alpha1.DesiredTable{
			{
				Name: "leads",
				Columns: []keystonev1alpha1.DesiredColumn{
					{Name: "score", Type: "bigint", Nullable: true},
				},
			},
		},
	}
	plan, err := Diff(obs, desired)
	if err != nil {
		t.Fatalf("Diff: %v", err)
	}
	if len(plan.Statements) != 0 {
		t.Errorf("type changes should NOT emit statements; got %v", plan.Statements)
	}
	if len(plan.Warnings) == 0 {
		t.Error("expected a warning about type drift")
	}
}

func TestDiff_DropTable_Destructive(t *testing.T) {
	obs := &drift.Snapshot{
		Schema: "crm",
		Tables: []drift.TableShape{{Name: "old_thing", Kind: "BASE TABLE"}},
	}
	desired := &keystonev1alpha1.SchemaDefinitionSpec{
		SchemaRef:        "crm",
		AllowDestructive: true,
		Tables:           []keystonev1alpha1.DesiredTable{},
	}
	plan, err := Diff(obs, desired)
	if err != nil {
		t.Fatalf("Diff: %v", err)
	}
	if plan.DestructiveOps != 1 {
		t.Errorf("expected 1 destructive op, got %d", plan.DestructiveOps)
	}
	if !strings.Contains(plan.Statements[0], "DROP TABLE") {
		t.Errorf("expected DROP TABLE, got %q", plan.Statements[0])
	}
}

// --- Phase 9.2 new tests ---

func TestDiff_TopoSort_FKDependencyOrder(t *testing.T) {
	obs := &drift.Snapshot{Schema: "sales"}
	desired := &keystonev1alpha1.SchemaDefinitionSpec{
		SchemaRef: "sales",
		Tables: []keystonev1alpha1.DesiredTable{
			{
				Name: "order_items",
				Columns: []keystonev1alpha1.DesiredColumn{
					{Name: "id", Type: "uuid", Nullable: false, PrimaryKey: true},
					{Name: "order_id", Type: "uuid", Nullable: false},
				},
				ForeignKeys: []keystonev1alpha1.DesiredForeignKey{
					{Name: "fk_order", Columns: []string{"order_id"},
						ReferencesTable: "orders", ReferencesColumns: []string{"id"}},
				},
			},
			{
				Name: "orders",
				Columns: []keystonev1alpha1.DesiredColumn{
					{Name: "id", Type: "uuid", Nullable: false, PrimaryKey: true},
					{Name: "customer_id", Type: "uuid", Nullable: false},
				},
				ForeignKeys: []keystonev1alpha1.DesiredForeignKey{
					{Name: "fk_customer", Columns: []string{"customer_id"},
						ReferencesTable: "customers", ReferencesColumns: []string{"id"}},
				},
			},
			{
				Name: "customers",
				Columns: []keystonev1alpha1.DesiredColumn{
					{Name: "id", Type: "uuid", Nullable: false, PrimaryKey: true},
					{Name: "name", Type: "text", Nullable: false},
				},
			},
		},
	}
	plan, err := Diff(obs, desired)
	if err != nil {
		t.Fatalf("Diff: %v", err)
	}

	// Find CREATE TABLE positions.
	positions := map[string]int{}
	for i, s := range plan.Statements {
		if strings.Contains(s, "CREATE TABLE") {
			for _, name := range []string{"customers", "orders", "order_items"} {
				if strings.Contains(s, `"`+name+`"`) {
					positions[name] = i
				}
			}
		}
	}

	if positions["customers"] >= positions["orders"] {
		t.Errorf("customers (pos %d) should be created before orders (pos %d)",
			positions["customers"], positions["orders"])
	}
	if positions["orders"] >= positions["order_items"] {
		t.Errorf("orders (pos %d) should be created before order_items (pos %d)",
			positions["orders"], positions["order_items"])
	}
}

func TestDiff_CreateIndexConcurrently(t *testing.T) {
	obs := &drift.Snapshot{
		Schema: "app",
		Tables: []drift.TableShape{
			{
				Name: "users",
				Kind: "BASE TABLE",
				Columns: []drift.ColumnShape{
					{Name: "id", Ordinal: 1, DataType: "uuid", Nullable: false},
					{Name: "email", Ordinal: 2, DataType: "text", Nullable: false},
				},
			},
		},
	}
	desired := &keystonev1alpha1.SchemaDefinitionSpec{
		SchemaRef: "app",
		Tables: []keystonev1alpha1.DesiredTable{
			{
				Name: "users",
				Columns: []keystonev1alpha1.DesiredColumn{
					{Name: "id", Type: "uuid", Nullable: false},
					{Name: "email", Type: "text", Nullable: false},
				},
				Indexes: []keystonev1alpha1.DesiredIndex{
					{Name: "idx_users_email", Columns: []string{"email"}, Unique: true},
				},
			},
		},
	}
	plan, err := Diff(obs, desired)
	if err != nil {
		t.Fatalf("Diff: %v", err)
	}

	found := false
	for _, s := range plan.Statements {
		if strings.Contains(s, "CONCURRENTLY") && strings.Contains(s, "idx_users_email") {
			found = true
			if !strings.Contains(s, "UNIQUE") {
				t.Errorf("expected UNIQUE in concurrent index, got %q", s)
			}
			break
		}
	}
	if !found {
		t.Errorf("expected CREATE INDEX CONCURRENTLY; statements: %v", plan.Statements)
	}
}

func TestDiff_NotNullBackfill(t *testing.T) {
	obs := &drift.Snapshot{
		Schema: "app",
		Tables: []drift.TableShape{
			{
				Name: "users",
				Kind: "BASE TABLE",
				Columns: []drift.ColumnShape{
					{Name: "id", Ordinal: 1, DataType: "uuid", Nullable: false},
					{Name: "status", Ordinal: 2, DataType: "text", Nullable: true},
				},
			},
		},
	}
	desired := &keystonev1alpha1.SchemaDefinitionSpec{
		SchemaRef: "app",
		Tables: []keystonev1alpha1.DesiredTable{
			{
				Name: "users",
				Columns: []keystonev1alpha1.DesiredColumn{
					{Name: "id", Type: "uuid", Nullable: false},
					{Name: "status", Type: "text", Nullable: false, Default: "'active'"},
				},
			},
		},
	}
	plan, err := Diff(obs, desired)
	if err != nil {
		t.Fatalf("Diff: %v", err)
	}

	// Should emit: SET DEFAULT → UPDATE → SET NOT NULL (3 statements).
	if len(plan.Statements) < 3 {
		t.Fatalf("expected at least 3 statements for backfill, got %d: %v",
			len(plan.Statements), plan.Statements)
	}

	hasSetDefault := false
	hasUpdate := false
	hasSetNotNull := false
	for _, s := range plan.Statements {
		if strings.Contains(s, "SET DEFAULT") {
			hasSetDefault = true
		}
		if strings.Contains(s, "UPDATE") && strings.Contains(s, "IS NULL") {
			hasUpdate = true
		}
		if strings.Contains(s, "SET NOT NULL") {
			hasSetNotNull = true
		}
	}
	if !hasSetDefault {
		t.Error("missing SET DEFAULT step")
	}
	if !hasUpdate {
		t.Error("missing UPDATE backfill step")
	}
	if !hasSetNotNull {
		t.Error("missing SET NOT NULL step")
	}
}

func TestDiff_ForeignKeyAddNotValid(t *testing.T) {
	obs := &drift.Snapshot{
		Schema: "sales",
		Tables: []drift.TableShape{
			{
				Name: "orders",
				Kind: "BASE TABLE",
				Columns: []drift.ColumnShape{
					{Name: "id", Ordinal: 1, DataType: "uuid", Nullable: false},
					{Name: "customer_id", Ordinal: 2, DataType: "uuid", Nullable: false},
				},
			},
			{
				Name: "customers",
				Kind: "BASE TABLE",
				Columns: []drift.ColumnShape{
					{Name: "id", Ordinal: 1, DataType: "uuid", Nullable: false},
				},
			},
		},
	}
	desired := &keystonev1alpha1.SchemaDefinitionSpec{
		SchemaRef: "sales",
		Tables: []keystonev1alpha1.DesiredTable{
			{
				Name: "orders",
				Columns: []keystonev1alpha1.DesiredColumn{
					{Name: "id", Type: "uuid", Nullable: false},
					{Name: "customer_id", Type: "uuid", Nullable: false},
				},
				ForeignKeys: []keystonev1alpha1.DesiredForeignKey{
					{Name: "orders_customer_fk", Columns: []string{"customer_id"},
						ReferencesTable: "customers", ReferencesColumns: []string{"id"},
						OnDelete: "CASCADE"},
				},
			},
			{
				Name: "customers",
				Columns: []keystonev1alpha1.DesiredColumn{
					{Name: "id", Type: "uuid", Nullable: false},
				},
			},
		},
	}
	plan, err := Diff(obs, desired)
	if err != nil {
		t.Fatalf("Diff: %v", err)
	}

	hasNotValid := false
	hasValidate := false
	for _, s := range plan.Statements {
		if strings.Contains(s, "NOT VALID") && strings.Contains(s, "orders_customer_fk") {
			hasNotValid = true
			if !strings.Contains(s, "CASCADE") {
				t.Errorf("FK should include ON DELETE CASCADE, got %q", s)
			}
		}
		if strings.Contains(s, "VALIDATE CONSTRAINT") && strings.Contains(s, "orders_customer_fk") {
			hasValidate = true
		}
	}
	if !hasNotValid {
		t.Errorf("expected ADD CONSTRAINT NOT VALID; statements: %v", plan.Statements)
	}
	if !hasValidate {
		t.Errorf("expected VALIDATE CONSTRAINT; statements: %v", plan.Statements)
	}
}

func TestDiff_Enums(t *testing.T) {
	obs := &drift.Snapshot{Schema: "app"}
	desired := &keystonev1alpha1.SchemaDefinitionSpec{
		SchemaRef: "app",
		Tables: []keystonev1alpha1.DesiredTable{
			{
				Name: "tickets",
				Columns: []keystonev1alpha1.DesiredColumn{
					{Name: "id", Type: "uuid", Nullable: false, PrimaryKey: true},
					{Name: "priority", Type: "ticket_priority", Nullable: false},
				},
			},
		},
		Enums: []keystonev1alpha1.DesiredEnum{
			{Name: "ticket_priority", Values: []string{"low", "medium", "high", "critical"}},
		},
	}
	plan, err := Diff(obs, desired)
	if err != nil {
		t.Fatalf("Diff: %v", err)
	}

	// Enum creation should come before table creation.
	enumIdx := -1
	tableIdx := -1
	for i, s := range plan.Statements {
		if strings.Contains(s, "ticket_priority") && strings.Contains(s, "CREATE TYPE") {
			enumIdx = i
		}
		if strings.Contains(s, "CREATE TABLE") && strings.Contains(s, "tickets") {
			tableIdx = i
		}
	}
	if enumIdx < 0 {
		t.Fatalf("enum CREATE TYPE not found; statements: %v", plan.Statements)
	}
	if tableIdx < 0 {
		t.Fatalf("table CREATE TABLE not found; statements: %v", plan.Statements)
	}
	if enumIdx >= tableIdx {
		t.Errorf("enum (pos %d) should be created before table (pos %d)", enumIdx, tableIdx)
	}
}

func TestDiff_Sequences(t *testing.T) {
	obs := &drift.Snapshot{Schema: "app"}
	desired := &keystonev1alpha1.SchemaDefinitionSpec{
		SchemaRef: "app",
		Tables: []keystonev1alpha1.DesiredTable{
			{
				Name: "counters",
				Columns: []keystonev1alpha1.DesiredColumn{
					{Name: "id", Type: "integer", Nullable: false, PrimaryKey: true},
				},
			},
		},
		Sequences: []keystonev1alpha1.DesiredSequence{
			{Name: "counter_seq", DataType: "integer", IncrementBy: 10},
		},
	}
	plan, err := Diff(obs, desired)
	if err != nil {
		t.Fatalf("Diff: %v", err)
	}

	found := false
	for _, s := range plan.Statements {
		if strings.Contains(s, "CREATE SEQUENCE") && strings.Contains(s, "counter_seq") {
			found = true
			if !strings.Contains(s, "INCREMENT BY 10") {
				t.Errorf("missing INCREMENT BY 10, got %q", s)
			}
		}
	}
	if !found {
		t.Errorf("sequence CREATE not found; statements: %v", plan.Statements)
	}
}

func TestDiff_Views(t *testing.T) {
	obs := &drift.Snapshot{
		Schema: "app",
		Tables: []drift.TableShape{
			{Name: "users", Kind: "BASE TABLE", Columns: []drift.ColumnShape{
				{Name: "id", Ordinal: 1, DataType: "uuid", Nullable: false},
				{Name: "active", Ordinal: 2, DataType: "boolean", Nullable: false},
			}},
		},
	}
	desired := &keystonev1alpha1.SchemaDefinitionSpec{
		SchemaRef: "app",
		Tables: []keystonev1alpha1.DesiredTable{
			{
				Name: "users",
				Columns: []keystonev1alpha1.DesiredColumn{
					{Name: "id", Type: "uuid", Nullable: false},
					{Name: "active", Type: "boolean", Nullable: false},
				},
			},
		},
		Views: []keystonev1alpha1.DesiredView{
			{Name: "active_users", Query: "SELECT * FROM users WHERE active = true", Replace: true},
		},
	}
	plan, err := Diff(obs, desired)
	if err != nil {
		t.Fatalf("Diff: %v", err)
	}

	found := false
	for _, s := range plan.Statements {
		if strings.Contains(s, "CREATE OR REPLACE VIEW") && strings.Contains(s, "active_users") {
			found = true
		}
	}
	if !found {
		t.Errorf("view CREATE not found; statements: %v", plan.Statements)
	}
}

func TestDiff_Functions(t *testing.T) {
	obs := &drift.Snapshot{Schema: "app"}
	desired := &keystonev1alpha1.SchemaDefinitionSpec{
		SchemaRef: "app",
		Tables: []keystonev1alpha1.DesiredTable{
			{
				Name: "events",
				Columns: []keystonev1alpha1.DesiredColumn{
					{Name: "id", Type: "uuid", Nullable: false, PrimaryKey: true},
				},
			},
		},
		Functions: []keystonev1alpha1.DesiredFunction{
			{
				Name:    "notify_event",
				Args:    "p_event_id uuid",
				Returns: "void",
				Body:    "\nBEGIN\n  PERFORM pg_notify('events', p_event_id::text);\nEND;\n",
				Replace: true,
			},
		},
	}
	plan, err := Diff(obs, desired)
	if err != nil {
		t.Fatalf("Diff: %v", err)
	}

	found := false
	for _, s := range plan.Statements {
		if strings.Contains(s, "CREATE OR REPLACE FUNCTION") && strings.Contains(s, "notify_event") {
			found = true
			if !strings.Contains(s, "LANGUAGE plpgsql") {
				t.Errorf("missing LANGUAGE plpgsql, got %q", s)
			}
		}
	}
	if !found {
		t.Errorf("function CREATE not found; statements: %v", plan.Statements)
	}
}

func TestDiff_ReverseStatements_Aligned(t *testing.T) {
	obs := &drift.Snapshot{Schema: "app"}
	desired := &keystonev1alpha1.SchemaDefinitionSpec{
		SchemaRef: "app",
		Tables: []keystonev1alpha1.DesiredTable{
			{
				Name: "items",
				Columns: []keystonev1alpha1.DesiredColumn{
					{Name: "id", Type: "uuid", Nullable: false, PrimaryKey: true},
				},
			},
		},
	}
	plan, err := Diff(obs, desired)
	if err != nil {
		t.Fatalf("Diff: %v", err)
	}
	if len(plan.Statements) != len(plan.ReverseStatements) {
		t.Errorf("Statements (%d) and ReverseStatements (%d) must be aligned",
			len(plan.Statements), len(plan.ReverseStatements))
	}
}

func TestDiff_FullSnapshotIndexDiff(t *testing.T) {
	obs := &drift.Snapshot{
		Schema: "app",
		Tables: []drift.TableShape{
			{
				Name: "users",
				Kind: "BASE TABLE",
				Columns: []drift.ColumnShape{
					{Name: "id", Ordinal: 1, DataType: "uuid", Nullable: false},
					{Name: "email", Ordinal: 2, DataType: "text", Nullable: false},
				},
			},
		},
		Indexes: []drift.ObjectDDL{
			{Name: "idx_old_email", Table: "users", Type: "index",
				Definition: "CREATE INDEX idx_old_email ON app.users USING btree (email)"},
		},
	}
	desired := &keystonev1alpha1.SchemaDefinitionSpec{
		SchemaRef:        "app",
		AllowDestructive: true,
		Tables: []keystonev1alpha1.DesiredTable{
			{
				Name: "users",
				Columns: []keystonev1alpha1.DesiredColumn{
					{Name: "id", Type: "uuid", Nullable: false},
					{Name: "email", Type: "text", Nullable: false},
				},
				// No indexes → idx_old_email should be dropped.
			},
		},
	}
	plan, err := Diff(obs, desired)
	if err != nil {
		t.Fatalf("Diff: %v", err)
	}

	found := false
	for _, s := range plan.Statements {
		if strings.Contains(s, "DROP INDEX CONCURRENTLY") && strings.Contains(s, "idx_old_email") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected DROP INDEX CONCURRENTLY for obsolete index; got: %v", plan.Statements)
	}
}

func TestDiff_FKDropWhenNotDesired(t *testing.T) {
	obs := &drift.Snapshot{
		Schema: "app",
		Tables: []drift.TableShape{
			{
				Name: "orders",
				Kind: "BASE TABLE",
				Columns: []drift.ColumnShape{
					{Name: "id", Ordinal: 1, DataType: "uuid", Nullable: false},
					{Name: "user_id", Ordinal: 2, DataType: "uuid", Nullable: false},
				},
			},
			{
				Name: "users",
				Kind: "BASE TABLE",
				Columns: []drift.ColumnShape{
					{Name: "id", Ordinal: 1, DataType: "uuid", Nullable: false},
				},
			},
		},
		Constraints: []drift.ObjectDDL{
			{Name: "orders_user_fk", Table: "orders", Type: "FOREIGN KEY",
				Definition: "FOREIGN KEY (user_id) REFERENCES users(id)"},
		},
	}
	desired := &keystonev1alpha1.SchemaDefinitionSpec{
		SchemaRef:        "app",
		AllowDestructive: true,
		Tables: []keystonev1alpha1.DesiredTable{
			{
				Name: "orders",
				Columns: []keystonev1alpha1.DesiredColumn{
					{Name: "id", Type: "uuid", Nullable: false},
					{Name: "user_id", Type: "uuid", Nullable: false},
				},
				// No FKs → should drop orders_user_fk
			},
			{
				Name: "users",
				Columns: []keystonev1alpha1.DesiredColumn{
					{Name: "id", Type: "uuid", Nullable: false},
				},
			},
		},
	}
	plan, err := Diff(obs, desired)
	if err != nil {
		t.Fatalf("Diff: %v", err)
	}

	found := false
	for _, s := range plan.Statements {
		if strings.Contains(s, "DROP CONSTRAINT") && strings.Contains(s, "orders_user_fk") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected DROP CONSTRAINT for obsolete FK; got: %v", plan.Statements)
	}
}

func TestTopoSort_SelfReferential(t *testing.T) {
	tables := []keystonev1alpha1.DesiredTable{
		{
			Name: "categories",
			Columns: []keystonev1alpha1.DesiredColumn{
				{Name: "id", Type: "uuid"},
				{Name: "parent_id", Type: "uuid"},
			},
			ForeignKeys: []keystonev1alpha1.DesiredForeignKey{
				{Name: "fk_parent", Columns: []string{"parent_id"},
					ReferencesTable: "categories", ReferencesColumns: []string{"id"}},
			},
		},
	}
	result, hasCycle := topoSortTables(tables)
	if len(result) != 1 || result[0] != "categories" {
		t.Errorf("self-referential table should appear once: %v", result)
	}
	if hasCycle {
		t.Error("self-referential FK should not be treated as a cycle")
	}
}

func TestDiff_ViewSkippedInObservedTables(t *testing.T) {
	obs := &drift.Snapshot{
		Schema: "app",
		Tables: []drift.TableShape{
			{Name: "users", Kind: "BASE TABLE", Columns: []drift.ColumnShape{
				{Name: "id", Ordinal: 1, DataType: "uuid"},
			}},
			{Name: "v_users", Kind: "VIEW", Columns: []drift.ColumnShape{
				{Name: "id", Ordinal: 1, DataType: "uuid"},
			}},
		},
	}
	desired := &keystonev1alpha1.SchemaDefinitionSpec{
		SchemaRef: "app",
		Tables: []keystonev1alpha1.DesiredTable{
			{Name: "users", Columns: []keystonev1alpha1.DesiredColumn{
				{Name: "id", Type: "uuid"},
			}},
		},
	}
	plan, err := Diff(obs, desired)
	if err != nil {
		t.Fatalf("Diff: %v", err)
	}
	// v_users is a VIEW, should NOT be treated as a table to DROP.
	for _, s := range plan.Statements {
		if strings.Contains(s, "v_users") {
			t.Errorf("VIEW should not be diffed as table; got: %q", s)
		}
	}
}

func TestDiff_RLSPolicy(t *testing.T) {
	obs := &drift.Snapshot{
		Schema: "app",
		Tables: []drift.TableShape{
			{Name: "documents", Kind: "BASE TABLE", Columns: []drift.ColumnShape{
				{Name: "id", Ordinal: 1, DataType: "uuid", Nullable: false},
				{Name: "tenant_id", Ordinal: 2, DataType: "uuid", Nullable: false},
			}},
		},
	}
	desired := &keystonev1alpha1.SchemaDefinitionSpec{
		SchemaRef: "app",
		Tables: []keystonev1alpha1.DesiredTable{
			{
				Name: "documents",
				Columns: []keystonev1alpha1.DesiredColumn{
					{Name: "id", Type: "uuid", Nullable: false},
					{Name: "tenant_id", Type: "uuid", Nullable: false},
				},
				EnableRLS: true,
			},
		},
		Policies: []keystonev1alpha1.DesiredPolicy{
			{
				Name:    "tenant_isolation",
				Table:   "documents",
				Command: "ALL",
				Using:   "tenant_id = current_setting('app.tenant_id')::uuid",
			},
		},
	}
	plan, err := Diff(obs, desired)
	if err != nil {
		t.Fatalf("Diff: %v", err)
	}

	hasEnableRLS := false
	hasPolicy := false
	for _, s := range plan.Statements {
		if strings.Contains(s, "ENABLE ROW LEVEL SECURITY") {
			hasEnableRLS = true
		}
		if strings.Contains(s, "CREATE POLICY") && strings.Contains(s, "tenant_isolation") {
			hasPolicy = true
		}
	}
	if !hasEnableRLS {
		t.Errorf("missing ENABLE ROW LEVEL SECURITY; statements: %v", plan.Statements)
	}
	if !hasPolicy {
		t.Errorf("missing CREATE POLICY; statements: %v", plan.Statements)
	}
}

func TestDiff_MaterializedView(t *testing.T) {
	obs := &drift.Snapshot{Schema: "analytics"}
	desired := &keystonev1alpha1.SchemaDefinitionSpec{
		SchemaRef: "analytics",
		Tables: []keystonev1alpha1.DesiredTable{
			{Name: "events", Columns: []keystonev1alpha1.DesiredColumn{
				{Name: "id", Type: "uuid", Nullable: false, PrimaryKey: true},
				{Name: "kind", Type: "text", Nullable: false},
			}},
		},
		MaterializedViews: []keystonev1alpha1.DesiredMaterializedView{
			{
				Name:  "mv_event_counts",
				Query: "SELECT kind, count(*) AS cnt FROM events GROUP BY kind",
				Indexes: []keystonev1alpha1.DesiredIndex{
					{Name: "idx_mv_event_counts_kind", Columns: []string{"kind"}, Unique: true},
				},
			},
		},
	}
	plan, err := Diff(obs, desired)
	if err != nil {
		t.Fatalf("Diff: %v", err)
	}

	hasMV := false
	hasMVIndex := false
	for _, s := range plan.Statements {
		if strings.Contains(s, "CREATE MATERIALIZED VIEW") && strings.Contains(s, "mv_event_counts") {
			hasMV = true
		}
		if strings.Contains(s, "CONCURRENTLY") && strings.Contains(s, "idx_mv_event_counts_kind") {
			hasMVIndex = true
		}
	}
	if !hasMV {
		t.Errorf("missing CREATE MATERIALIZED VIEW; statements: %v", plan.Statements)
	}
	if !hasMVIndex {
		t.Errorf("missing index on materialized view; statements: %v", plan.Statements)
	}
}

func TestDiff_Trigger(t *testing.T) {
	obs := &drift.Snapshot{
		Schema: "app",
		Tables: []drift.TableShape{
			{Name: "orders", Kind: "BASE TABLE", Columns: []drift.ColumnShape{
				{Name: "id", Ordinal: 1, DataType: "uuid", Nullable: false},
			}},
		},
	}
	desired := &keystonev1alpha1.SchemaDefinitionSpec{
		SchemaRef: "app",
		Tables: []keystonev1alpha1.DesiredTable{
			{Name: "orders", Columns: []keystonev1alpha1.DesiredColumn{
				{Name: "id", Type: "uuid", Nullable: false},
			}},
		},
		Functions: []keystonev1alpha1.DesiredFunction{
			{Name: "audit_order_changes", Args: "", Returns: "trigger", Language: "plpgsql",
				Body: "\nBEGIN\n  RETURN NEW;\nEND;\n", Replace: true},
		},
		Triggers: []keystonev1alpha1.DesiredTrigger{
			{Name: "trg_audit_orders", Table: "orders", Timing: "AFTER",
				Events: []string{"INSERT", "UPDATE"}, Function: "audit_order_changes"},
		},
	}
	plan, err := Diff(obs, desired)
	if err != nil {
		t.Fatalf("Diff: %v", err)
	}

	hasTrigger := false
	for _, s := range plan.Statements {
		if strings.Contains(s, "CREATE TRIGGER") && strings.Contains(s, "trg_audit_orders") {
			hasTrigger = true
			if !strings.Contains(s, "AFTER INSERT OR UPDATE") {
				t.Errorf("trigger should fire AFTER INSERT OR UPDATE, got: %s", s)
			}
		}
	}
	if !hasTrigger {
		t.Errorf("missing CREATE TRIGGER; statements: %v", plan.Statements)
	}
}

// TestDiff_ColumnType_ArrayResolved guards against the example-service-control-public
// 70+ false-positive type-drift warnings observed 2026-05-06: the inspector
// emits DataType="ARRAY" with UDTName="_text" for a `text[]` column, the SD
// declares Type="text[]", and the unguarded comparison fired a warning on
// every reconcile. Resolved via shared drift.ResolveColumnType canonicaliser.
func TestDiff_ColumnType_ArrayResolved(t *testing.T) {
	obs := &drift.Snapshot{
		Schema: "public",
		Tables: []drift.TableShape{
			{
				Name: "iam_login_risk_events",
				Kind: "BASE TABLE",
				Columns: []drift.ColumnShape{
					{Name: "id", Ordinal: 1, DataType: "uuid", Nullable: false},
					{Name: "tags", Ordinal: 2, DataType: "ARRAY", UDTName: "_text", Nullable: true},
				},
			},
		},
	}
	desired := &keystonev1alpha1.SchemaDefinitionSpec{
		SchemaRef: "public",
		Tables: []keystonev1alpha1.DesiredTable{
			{
				Name: "iam_login_risk_events",
				Columns: []keystonev1alpha1.DesiredColumn{
					{Name: "id", Type: "uuid", Nullable: false, PrimaryKey: true},
					{Name: "tags", Type: "text[]", Nullable: true},
				},
			},
		},
	}
	plan, err := Diff(obs, desired)
	if err != nil {
		t.Fatalf("Diff: %v", err)
	}
	for _, w := range plan.Warnings {
		if strings.Contains(w, "type drift") {
			t.Errorf("unexpected type-drift warning: %s", w)
		}
	}
	if !plan.Empty() {
		t.Errorf("expected empty plan, got %d stmts: %v", len(plan.Statements), plan.Statements)
	}
}

// TestDiff_ColumnType_UserDefinedResolved covers the second class
// information_schema.data_type label collapses: enums, composites, and
// domains all return data_type="USER-DEFINED" with the actual type name in
// udt_name. SD authors write the type name directly, so observed must
// resolve to that form.
func TestDiff_ColumnType_UserDefinedResolved(t *testing.T) {
	obs := &drift.Snapshot{
		Schema: "public",
		Tables: []drift.TableShape{
			{
				Name: "tenants",
				Kind: "BASE TABLE",
				Columns: []drift.ColumnShape{
					{Name: "id", Ordinal: 1, DataType: "uuid", Nullable: false},
					{Name: "kind", Ordinal: 2, DataType: "USER-DEFINED", UDTName: "tenant_type", Nullable: false},
				},
			},
		},
	}
	desired := &keystonev1alpha1.SchemaDefinitionSpec{
		SchemaRef: "public",
		Tables: []keystonev1alpha1.DesiredTable{
			{
				Name: "tenants",
				Columns: []keystonev1alpha1.DesiredColumn{
					{Name: "id", Type: "uuid", Nullable: false, PrimaryKey: true},
					{Name: "kind", Type: "tenant_type", Nullable: false},
				},
			},
		},
	}
	plan, err := Diff(obs, desired)
	if err != nil {
		t.Fatalf("Diff: %v", err)
	}
	for _, w := range plan.Warnings {
		if strings.Contains(w, "type drift") {
			t.Errorf("unexpected type-drift warning: %s", w)
		}
	}
	if !plan.Empty() {
		t.Errorf("expected empty plan, got %d stmts: %v", len(plan.Statements), plan.Statements)
	}
}

// TestDiff_ColumnType_RealDriftStillWarns proves the resolver path doesn't
// accidentally hide genuine type drift — int4 → bigint is still a drift.
func TestDiff_ColumnType_RealDriftStillWarns(t *testing.T) {
	obs := &drift.Snapshot{
		Schema: "public",
		Tables: []drift.TableShape{
			{
				Name: "counters",
				Kind: "BASE TABLE",
				Columns: []drift.ColumnShape{
					{Name: "n", Ordinal: 1, DataType: "integer", Nullable: false},
				},
			},
		},
	}
	desired := &keystonev1alpha1.SchemaDefinitionSpec{
		SchemaRef: "public",
		Tables: []keystonev1alpha1.DesiredTable{
			{
				Name: "counters",
				Columns: []keystonev1alpha1.DesiredColumn{
					{Name: "n", Type: "bigint", Nullable: false},
				},
			},
		},
	}
	plan, err := Diff(obs, desired)
	if err != nil {
		t.Fatalf("Diff: %v", err)
	}
	hasWarning := false
	for _, w := range plan.Warnings {
		if strings.Contains(w, "type drift") {
			hasWarning = true
			if !strings.Contains(w, "observed=integer") || !strings.Contains(w, "desired=bigint") {
				t.Errorf("warning should report integer vs bigint, got: %s", w)
			}
		}
	}
	if !hasWarning {
		t.Errorf("expected type-drift warning for integer→bigint, got: %v", plan.Warnings)
	}
}

// TestDiff_View_EmptyQuerySkipped guards against the "syntax error at
// or near `;`" failure observed 2026-05-06 on example-service-public-desired
// — a view with empty Query rendered as `CREATE OR REPLACE VIEW "x" AS ;`
// which halted the per-statement runner at the first row. The differ
// must skip emit AND surface a warning, never emit invalid SQL.
func TestDiff_View_EmptyQuerySkipped(t *testing.T) {
	cases := []struct{ name, query string }{
		{"empty-string", ""},
		{"whitespace-only", "  \n\t "},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			obs := &drift.Snapshot{Schema: "public"}
			desired := &keystonev1alpha1.SchemaDefinitionSpec{
				SchemaRef: "public",
				Views: []keystonev1alpha1.DesiredView{
					{Name: "customer_tenants", Query: c.query, Replace: true},
				},
			}
			plan, err := Diff(obs, desired)
			if err != nil {
				t.Fatalf("Diff: %v", err)
			}
			for _, s := range plan.Statements {
				if strings.Contains(s, "AS ;") || strings.Contains(s, "AS  ;") {
					t.Errorf("invalid SQL emitted: %s", s)
				}
				if strings.Contains(s, "CREATE OR REPLACE VIEW") &&
					strings.Contains(s, "customer_tenants") {
					t.Errorf("view with empty query should be skipped; got: %s", s)
				}
			}
			hasWarn := false
			for _, w := range plan.Warnings {
				if strings.Contains(w, "customer_tenants") &&
					strings.Contains(w, "empty query") {
					hasWarn = true
				}
			}
			if !hasWarn {
				t.Errorf("expected empty-query warning, got: %v", plan.Warnings)
			}
		})
	}
}
