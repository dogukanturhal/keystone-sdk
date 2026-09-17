// SPDX-License-Identifier: Apache-2.0

package schemasource

import (
	"os"
	"path/filepath"
	"testing"

	"sigs.k8s.io/yaml"

	keystonev1alpha1 "github.com/dogukanturhal/keystone/api/v1alpha1"
)

func TestParseRef(t *testing.T) {
	tests := []struct {
		in         string
		wantScheme Scheme
		wantPath   string
		wantDSN    string
		wantSchema string
		wantErr    bool
	}{
		{in: "yaml://schema.yaml", wantScheme: SchemeYAML, wantPath: "schema.yaml"},
		{in: "sql://schema.sql", wantScheme: SchemeSQL, wantPath: "schema.sql"},
		{in: "file:///abs/schema.sql", wantScheme: SchemeSQL, wantPath: "/abs/schema.sql"},
		{in: "file:///abs/schema.yaml", wantScheme: SchemeYAML, wantPath: "/abs/schema.yaml"},
		{in: "schema.sql", wantScheme: SchemeSQL, wantPath: "schema.sql"},
		{in: "schema.yml", wantScheme: SchemeYAML, wantPath: "schema.yml"},
		{
			in:         "db://postgres://u:p@host:5432/db?schema=app&sslmode=disable",
			wantScheme: SchemeDB,
			wantSchema: "app",
			wantDSN:    "postgres://u:p@host:5432/db?sslmode=disable",
		},
		{
			in:         "db://u:p@host:5432/db",
			wantScheme: SchemeDB,
			wantDSN:    "postgres://u:p@host:5432/db",
		},
		{in: "", wantErr: true},
		{in: "weird-no-extension", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			ref, err := ParseRef(tt.in)
			if (err != nil) != tt.wantErr {
				t.Fatalf("err=%v wantErr=%v", err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}
			if ref.Scheme != tt.wantScheme {
				t.Errorf("scheme=%q want %q", ref.Scheme, tt.wantScheme)
			}
			if ref.Path != tt.wantPath {
				t.Errorf("path=%q want %q", ref.Path, tt.wantPath)
			}
			if tt.wantDSN != "" && ref.DSN != tt.wantDSN {
				t.Errorf("dsn=%q want %q", ref.DSN, tt.wantDSN)
			}
			if ref.Schema != tt.wantSchema {
				t.Errorf("schema=%q want %q", ref.Schema, tt.wantSchema)
			}
		})
	}
}

func TestExtractSchemaParam(t *testing.T) {
	schema, clean, err := extractSchemaParam("postgres://u:p@h/db?schema=app&sslmode=disable")
	if err != nil {
		t.Fatal(err)
	}
	if schema != "app" {
		t.Errorf("schema=%q want app", schema)
	}
	// schema param must be stripped so PostgreSQL never sees it.
	if clean != "postgres://u:p@h/db?sslmode=disable" {
		t.Errorf("clean dsn=%q", clean)
	}

	// No schema param → DSN untouched.
	schema, clean, err = extractSchemaParam("postgres://u:p@h/db?sslmode=disable")
	if err != nil {
		t.Fatal(err)
	}
	if schema != "" || clean != "postgres://u:p@h/db?sslmode=disable" {
		t.Errorf("schema=%q clean=%q", schema, clean)
	}
}

func TestLoadSpecFile(t *testing.T) {
	want := keystonev1alpha1.SchemaDefinitionSpec{
		SchemaRef: "app-schema",
		Tables: []keystonev1alpha1.DesiredTable{
			{
				Name: "users",
				Columns: []keystonev1alpha1.DesiredColumn{
					{Name: "id", Type: "bigint", PrimaryKey: true},
					{Name: "email", Type: "text"},
				},
			},
		},
	}

	dir := t.TempDir()

	// Full CR form (apiVersion/kind/spec).
	full := map[string]any{
		"apiVersion": "keystone.hexxlock.io/v1alpha1",
		"kind":       "SchemaDefinition",
		"metadata":   map[string]string{"name": "app"},
		"spec":       want,
	}
	fullBytes, err := yaml.Marshal(full)
	if err != nil {
		t.Fatal(err)
	}
	fullPath := filepath.Join(dir, "full.yaml")
	if err := os.WriteFile(fullPath, fullBytes, 0o600); err != nil {
		t.Fatal(err)
	}

	got, err := LoadSpecFile(fullPath)
	if err != nil {
		t.Fatalf("LoadSpecFile(full): %v", err)
	}
	if got.SchemaRef != "app-schema" || len(got.Tables) != 1 || got.Tables[0].Name != "users" {
		t.Errorf("full CR parse wrong: %+v", got)
	}

	// Bare spec form.
	bareBytes, err := yaml.Marshal(want)
	if err != nil {
		t.Fatal(err)
	}
	barePath := filepath.Join(dir, "bare.yaml")
	if err := os.WriteFile(barePath, bareBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	got, err = LoadSpecFile(barePath)
	if err != nil {
		t.Fatalf("LoadSpecFile(bare): %v", err)
	}
	if len(got.Tables) != 1 || got.Tables[0].Name != "users" {
		t.Errorf("bare spec parse wrong: %+v", got)
	}
}
