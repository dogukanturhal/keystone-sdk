// SPDX-License-Identifier: Apache-2.0

package schemaspec

import (
	"strings"
	"testing"

	keystonev1alpha1 "github.com/dogukanturhal/keystone/api/v1alpha1"
	"github.com/dogukanturhal/keystone-sdk/go/drift"
)

func TestFromSnapshot_TablesAndColumns(t *testing.T) {
	snap := &drift.Snapshot{
		Schema: "app",
		Tables: []drift.TableShape{
			{
				Name: "users",
				Kind: "BASE TABLE",
				Columns: []drift.ColumnShape{
					{Name: "id", DataType: "uuid", Nullable: false},
					{Name: "email", DataType: "text", Nullable: false},
					{Name: "bio", DataType: "text", Nullable: true},
				},
			},
		},
		Constraints: []drift.ObjectDDL{
			{Name: "users_pkey", Table: "users", Type: "PRIMARY KEY", Definition: "PRIMARY KEY (id)"},
		},
	}
	spec := FromSnapshot(snap, Options{SchemaRef: "app-schema"})

	if spec.SchemaRef != "app-schema" {
		t.Errorf("schemaRef = %q", spec.SchemaRef)
	}
	if len(spec.Tables) != 1 {
		t.Fatalf("expected 1 table, got %d", len(spec.Tables))
	}
	tbl := spec.Tables[0]
	if tbl.Name != "users" {
		t.Errorf("table name = %q", tbl.Name)
	}
	if len(tbl.Columns) != 3 {
		t.Fatalf("expected 3 columns, got %d", len(tbl.Columns))
	}
	// Single-column PK should be inlined.
	if !tbl.Columns[0].PrimaryKey {
		t.Error("expected id column to have PrimaryKey=true")
	}
}

func TestFromSnapshot_CompositePK(t *testing.T) {
	snap := &drift.Snapshot{
		Schema: "app",
		Tables: []drift.TableShape{
			{
				Name: "order_items",
				Kind: "BASE TABLE",
				Columns: []drift.ColumnShape{
					{Name: "order_id", DataType: "uuid", Nullable: false},
					{Name: "item_id", DataType: "uuid", Nullable: false},
					{Name: "quantity", DataType: "integer", Nullable: false},
				},
			},
		},
		Constraints: []drift.ObjectDDL{
			{Name: "order_items_pkey", Table: "order_items", Type: "PRIMARY KEY",
				Definition: "PRIMARY KEY (order_id, item_id)"},
		},
	}
	spec := FromSnapshot(snap, Options{SchemaRef: "app"})
	tbl := spec.Tables[0]
	if len(tbl.PrimaryKey) != 2 {
		t.Fatalf("expected composite PK with 2 columns, got %v", tbl.PrimaryKey)
	}
	if tbl.PrimaryKey[0] != "order_id" || tbl.PrimaryKey[1] != "item_id" {
		t.Errorf("PK = %v", tbl.PrimaryKey)
	}
	// Columns should NOT have PrimaryKey=true for composite PKs.
	for _, c := range tbl.Columns {
		if c.PrimaryKey {
			t.Errorf("column %s should not have PrimaryKey=true for composite PK", c.Name)
		}
	}
}

func TestFromSnapshot_Indexes(t *testing.T) {
	snap := &drift.Snapshot{
		Schema: "app",
		Tables: []drift.TableShape{
			{
				Name: "users",
				Kind: "BASE TABLE",
				Columns: []drift.ColumnShape{
					{Name: "id", DataType: "uuid"},
					{Name: "email", DataType: "text"},
				},
			},
		},
		// A real snapshot always carries the PRIMARY KEY constraint
		// alongside the index that backs it — the inspector reads both out
		// of the catalog. The fixture must too, or it exercises a shape
		// that cannot occur and the index filter has nothing to match on.
		Constraints: []drift.ObjectDDL{
			{Name: "users_pkey", Table: "users", Type: "PRIMARY KEY",
				Definition: "PRIMARY KEY (id)"},
		},
		Indexes: []drift.ObjectDDL{
			{Name: "users_pkey", Table: "users", Type: "index",
				Definition: "CREATE UNIQUE INDEX users_pkey ON app.users USING btree (id)"},
			{Name: "idx_users_email", Table: "users", Type: "index",
				Definition: "CREATE UNIQUE INDEX idx_users_email ON app.users USING btree (email)"},
			{Name: "idx_users_active", Table: "users", Type: "index",
				Definition: "CREATE INDEX idx_users_active ON app.users USING btree (email) WHERE active = true"},
		},
	}
	spec := FromSnapshot(snap, Options{SchemaRef: "app"})
	tbl := spec.Tables[0]

	// The PK's backing index is not an independent object, so it must not
	// reappear as a standalone index.
	if len(tbl.Indexes) != 2 {
		t.Fatalf("expected 2 indexes (skipping the PK-backing index), got %d", len(tbl.Indexes))
	}

	emailIdx := tbl.Indexes[0]
	if emailIdx.Name != "idx_users_email" {
		t.Errorf("index name = %q", emailIdx.Name)
	}
	if !emailIdx.Unique {
		t.Error("expected unique index")
	}
	if emailIdx.Method != "btree" {
		t.Errorf("method = %q", emailIdx.Method)
	}

	activeIdx := tbl.Indexes[1]
	if activeIdx.Where == "" {
		t.Error("expected WHERE clause for partial index")
	}
}

func TestFromSnapshot_ForeignKeys(t *testing.T) {
	snap := &drift.Snapshot{
		Schema: "sales",
		Tables: []drift.TableShape{
			{Name: "orders", Kind: "BASE TABLE", Columns: []drift.ColumnShape{
				{Name: "id", DataType: "uuid"},
				{Name: "customer_id", DataType: "uuid"},
			}},
			{Name: "customers", Kind: "BASE TABLE", Columns: []drift.ColumnShape{
				{Name: "id", DataType: "uuid"},
			}},
		},
		Constraints: []drift.ObjectDDL{
			{Name: "orders_customer_fk", Table: "orders", Type: "FOREIGN KEY",
				Definition: "FOREIGN KEY (customer_id) REFERENCES customers(id) ON DELETE CASCADE"},
		},
	}
	spec := FromSnapshot(snap, Options{SchemaRef: "sales"})

	var ordersTbl *keystonev1alpha1.DesiredTable
	for i := range spec.Tables {
		if spec.Tables[i].Name == "orders" {
			ordersTbl = &spec.Tables[i]
			break
		}
	}
	if ordersTbl == nil {
		t.Fatal("orders table not found")
	}
	if len(ordersTbl.ForeignKeys) != 1 {
		t.Fatalf("expected 1 FK, got %d", len(ordersTbl.ForeignKeys))
	}
	fk := ordersTbl.ForeignKeys[0]
	if fk.Name != "orders_customer_fk" {
		t.Errorf("FK name = %q", fk.Name)
	}
	if fk.ReferencesTable != "customers" {
		t.Errorf("FK ref table = %q", fk.ReferencesTable)
	}
	if fk.OnDelete != "CASCADE" {
		t.Errorf("FK onDelete = %q", fk.OnDelete)
	}
}

func TestFromSnapshot_Enums(t *testing.T) {
	snap := &drift.Snapshot{
		Schema: "app",
		Tables: []drift.TableShape{
			{Name: "tickets", Kind: "BASE TABLE", Columns: []drift.ColumnShape{
				{Name: "id", DataType: "uuid"},
			}},
		},
		Enums: []drift.EnumShape{
			{Name: "priority", Labels: []string{"low", "medium", "high"}},
		},
	}
	spec := FromSnapshot(snap, Options{SchemaRef: "app"})
	if len(spec.Enums) != 1 {
		t.Fatalf("expected 1 enum, got %d", len(spec.Enums))
	}
	if spec.Enums[0].Name != "priority" {
		t.Errorf("enum name = %q", spec.Enums[0].Name)
	}
	if len(spec.Enums[0].Values) != 3 {
		t.Errorf("enum values = %v", spec.Enums[0].Values)
	}
}

func TestFromSnapshot_Sequences(t *testing.T) {
	snap := &drift.Snapshot{
		Schema: "app",
		Tables: []drift.TableShape{
			{Name: "counters", Kind: "BASE TABLE", Columns: []drift.ColumnShape{
				{Name: "id", DataType: "integer"},
			}},
		},
		Sequences: []drift.SeqShape{
			{Name: "counter_seq", DataType: "bigint", IncrementBy: 10, StartValue: 100},
		},
	}
	spec := FromSnapshot(snap, Options{SchemaRef: "app"})
	if len(spec.Sequences) != 1 {
		t.Fatalf("expected 1 sequence, got %d", len(spec.Sequences))
	}
	if spec.Sequences[0].IncrementBy != 10 {
		t.Errorf("incrementBy = %d", spec.Sequences[0].IncrementBy)
	}
}

func TestFromSnapshot_ViewsSeparated(t *testing.T) {
	snap := &drift.Snapshot{
		Schema: "app",
		Tables: []drift.TableShape{
			{Name: "users", Kind: "BASE TABLE", Columns: []drift.ColumnShape{
				{Name: "id", DataType: "uuid"},
			}},
			{Name: "active_users", Kind: "VIEW", ViewDefinition: "SELECT id FROM users", Columns: []drift.ColumnShape{
				{Name: "id", DataType: "uuid"},
			}},
		},
	}
	spec := FromSnapshot(snap, Options{SchemaRef: "app"})

	// Tables should only include BASE TABLE.
	if len(spec.Tables) != 1 {
		t.Errorf("expected 1 table, got %d", len(spec.Tables))
	}
	if spec.Tables[0].Name != "users" {
		t.Errorf("table = %q", spec.Tables[0].Name)
	}
	// Views should be in spec.Views.
	if len(spec.Views) != 1 {
		t.Fatalf("expected 1 view, got %d", len(spec.Views))
	}
	if spec.Views[0].Name != "active_users" {
		t.Errorf("view = %q", spec.Views[0].Name)
	}
}

func TestFromSnapshot_Functions(t *testing.T) {
	snap := &drift.Snapshot{
		Schema: "app",
		Tables: []drift.TableShape{
			{Name: "events", Kind: "BASE TABLE", Columns: []drift.ColumnShape{
				{Name: "id", DataType: "uuid"},
			}},
		},
		Functions: []drift.FuncShape{
			{
				Name:       "notify_event",
				Args:       "p_id uuid",
				Returns:    "void",
				Language:   "plpgsql",
				Definition: "CREATE OR REPLACE FUNCTION app.notify_event(p_id uuid) RETURNS void LANGUAGE plpgsql AS $$BEGIN PERFORM pg_notify('events', p_id::text); END;$$",
			},
		},
	}
	spec := FromSnapshot(snap, Options{SchemaRef: "app"})
	if len(spec.Functions) != 1 {
		t.Fatalf("expected 1 function, got %d", len(spec.Functions))
	}
	f := spec.Functions[0]
	if f.Name != "notify_event" {
		t.Errorf("name = %q", f.Name)
	}
	if f.Returns != "void" {
		t.Errorf("returns = %q", f.Returns)
	}
	if !strings.Contains(f.Body, "pg_notify") {
		t.Errorf("body should contain pg_notify, got %q", f.Body)
	}
}

func TestFromSnapshot_RLSAndPolicies(t *testing.T) {
	snap := &drift.Snapshot{
		Schema: "app",
		Tables: []drift.TableShape{
			{Name: "documents", Kind: "BASE TABLE", RLSEnabled: true, Columns: []drift.ColumnShape{
				{Name: "id", DataType: "uuid"},
				{Name: "tenant_id", DataType: "uuid"},
			}},
		},
		Policies: []drift.PolicyShape{
			{Name: "tenant_isolation", Table: "documents", Command: "ALL", Permissive: true,
				Using: "(tenant_id = current_setting('app.tenant')::uuid)"},
		},
	}
	spec := FromSnapshot(snap, Options{SchemaRef: "app"})
	if !spec.Tables[0].EnableRLS {
		t.Error("expected EnableRLS=true on documents")
	}
	if len(spec.Policies) != 1 {
		t.Fatalf("expected 1 policy, got %d", len(spec.Policies))
	}
	if spec.Policies[0].Name != "tenant_isolation" || spec.Policies[0].Command != "ALL" {
		t.Errorf("policy = %+v", spec.Policies[0])
	}
}

func TestFromSnapshot_NilSnapshot(t *testing.T) {
	spec := FromSnapshot(nil, Options{SchemaRef: "app"})
	if spec == nil {
		t.Fatal("FromSnapshot(nil) must return a non-nil empty spec")
	}
	if len(spec.Tables) != 0 {
		t.Errorf("expected empty spec, got %d tables", len(spec.Tables))
	}
}

func TestParseFKConstraint(t *testing.T) {
	tests := []struct {
		name, def  string
		wantTable  string
		wantDelete string
	}{
		{
			"simple", "FOREIGN KEY (customer_id) REFERENCES customers(id)",
			"customers", "NO ACTION",
		},
		{
			"cascade", "FOREIGN KEY (order_id) REFERENCES orders(id) ON DELETE CASCADE",
			"orders", "CASCADE",
		},
		{
			"set null", "FOREIGN KEY (parent_id) REFERENCES categories(id) ON DELETE SET NULL",
			"categories", "SET NULL",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fk := parseFKConstraint("fk_test", tt.def)
			if fk.refTable != tt.wantTable {
				t.Errorf("refTable = %q, want %q", fk.refTable, tt.wantTable)
			}
			if fk.onDelete != tt.wantDelete {
				t.Errorf("onDelete = %q, want %q", fk.onDelete, tt.wantDelete)
			}
		})
	}
}

func TestExtractFunctionBody(t *testing.T) {
	tests := []struct {
		input, want string
	}{
		{
			"CREATE FUNCTION f() RETURNS void LANGUAGE plpgsql AS $$BEGIN NULL; END;$$",
			"BEGIN NULL; END;",
		},
		{
			"CREATE FUNCTION f() RETURNS void AS $fn$SELECT 1$fn$",
			"SELECT 1",
		},
	}
	for _, tt := range tests {
		got := extractFunctionBody(tt.input)
		if got != tt.want {
			t.Errorf("extractFunctionBody(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestFromSnapshot_SelectorMode(t *testing.T) {
	snap := &drift.Snapshot{
		Schema: "public",
		Tables: []drift.TableShape{{
			Name:    "users",
			Kind:    "BASE TABLE",
			Columns: []drift.ColumnShape{{Name: "id", DataType: "uuid", Nullable: false}},
		}},
	}
	selector := map[string]string{
		"keystone.hexxlock.io/scope": "example-service",
		"keystone.hexxlock.io/tier":  "tenant",
	}
	spec := FromSnapshot(snap, Options{SelectorLabels: selector})
	if spec.SchemaRef != "" {
		t.Errorf("SchemaRef should be empty in selector mode, got %q (the SD webhook rejects an SD with both fields set)", spec.SchemaRef)
	}
	if spec.SchemaSelector == nil {
		t.Fatal("SchemaSelector should be non-nil in selector mode")
	}
	if spec.SchemaSelector.MatchLabels["keystone.hexxlock.io/scope"] != "example-service" {
		t.Errorf("missing or wrong scope label: %v", spec.SchemaSelector.MatchLabels)
	}
}

func TestFromSnapshot_RefMode(t *testing.T) {
	snap := &drift.Snapshot{Schema: "public"}
	spec := FromSnapshot(snap, Options{SchemaRef: "myschema"})
	if spec.SchemaRef != "myschema" {
		t.Errorf("SchemaRef = %q, want %q", spec.SchemaRef, "myschema")
	}
	if spec.SchemaSelector != nil {
		t.Errorf("SchemaSelector should be nil in ref mode")
	}
}

// FromSnapshot must record forceRLS EXPLICITLY, including as false. A
// SchemaDefinition produced by inspecting a live database is a record of what
// that database actually is, and "RLS enabled but not forced" is a state a
// database can genuinely be in. Leaving the field unset there would let it
// pick up its default of true and round-trip the table back as forced,
// describing protection the inspected database does not have.
func TestFromSnapshot_ForceRLSIsExplicit(t *testing.T) {
	mk := func(enabled, forced bool) *drift.Snapshot {
		return &drift.Snapshot{
			Schema: "app",
			Tables: []drift.TableShape{{
				Name: "documents", Kind: "BASE TABLE",
				RLSEnabled: enabled, RLSForced: &forced,
				Columns: []drift.ColumnShape{{Name: "tenant_id", DataType: "uuid"}},
			}},
		}
	}

	forced := FromSnapshot(mk(true, true), Options{SchemaRef: "app"}).Tables[0]
	if !forced.EnableRLS {
		t.Fatal("expected EnableRLS=true")
	}
	if forced.ForceRLS == nil || !*forced.ForceRLS {
		t.Errorf("expected ForceRLS=true, got %v", forced.ForceRLS)
	}

	unforced := FromSnapshot(mk(true, false), Options{SchemaRef: "app"}).Tables[0]
	if !unforced.EnableRLS {
		t.Fatal("expected EnableRLS=true")
	}
	if unforced.ForceRLS == nil {
		t.Fatal("ForceRLS must be set explicitly, not left to its default: " +
			"an unforced table would otherwise be described as forced")
	}
	if *unforced.ForceRLS {
		t.Errorf("expected ForceRLS=false for an enabled-but-unforced table")
	}

	// RLS off entirely: neither field applies.
	off := FromSnapshot(mk(false, false), Options{SchemaRef: "app"}).Tables[0]
	if off.EnableRLS {
		t.Error("expected EnableRLS=false")
	}
	if off.ForceRLS != nil {
		t.Errorf("expected ForceRLS unset when RLS is off, got %v", *off.ForceRLS)
	}
}

// A snapshot written before RLSForced was modelled never recorded the FORCE
// state, so FromSnapshot must leave the field unset rather than invent
// `false` from a nil pointer — unset means forced, and claiming a forced
// table is unforced would make the desired-state document ask for owner-side
// enforcement to be REMOVED on the next apply.
func TestFromSnapshot_ForceRLSUnsetForLegacySnapshot(t *testing.T) {
	snap := &drift.Snapshot{
		Schema: "app",
		Tables: []drift.TableShape{{
			Name: "documents", Kind: "BASE TABLE",
			RLSEnabled: true, RLSForced: nil,
			Columns: []drift.ColumnShape{{Name: "tenant_id", DataType: "uuid"}},
		}},
	}
	tbl := FromSnapshot(snap, Options{SchemaRef: "app"}).Tables[0]
	if !tbl.EnableRLS {
		t.Fatal("expected EnableRLS=true")
	}
	if tbl.ForceRLS != nil {
		t.Errorf("expected ForceRLS to stay unset for a pre-field snapshot, got %v", *tbl.ForceRLS)
	}
}
