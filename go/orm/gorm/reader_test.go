// SPDX-License-Identifier: AGPL-3.0-or-later

package gorm

import (
	"os"
	"path/filepath"
	"testing"

	keystonev1alpha1 "github.com/dogukanturhal/keystone/api/v1alpha1"
)

// Test fixtures — written to a temp file and parsed. This keeps the
// fixture self-contained + avoids committing test Go files that would
// otherwise compile as actual code.
const fixtureBasic = `
package models

import "time"

// Lead is a sales lead (GORM model).
type Lead struct {
	ID        string ` + "`gorm:\"primaryKey;type:uuid;default:gen_random_uuid()\"`" + `
	Email     string ` + "`gorm:\"type:text;not null;uniqueIndex\"`" + `
	Score     int    ` + "`gorm:\"type:numeric;default:0\"`" + `
	CreatedAt time.Time ` + "`gorm:\"not null\"`" + `
}
`

func TestReadFile_BasicLead(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "lead.go")
	if err := os.WriteFile(path, []byte(fixtureBasic), 0644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	spec, err := ReadFile(path, "crm")
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if spec.SchemaRef != "crm" {
		t.Errorf("SchemaRef = %q, want crm", spec.SchemaRef)
	}
	if len(spec.Tables) != 1 {
		t.Fatalf("expected 1 table, got %d", len(spec.Tables))
	}
	table := spec.Tables[0]
	if table.Name != "lead" {
		t.Errorf("table name = %q, want lead", table.Name)
	}
	if len(table.Columns) != 4 {
		t.Fatalf("expected 4 columns, got %d", len(table.Columns))
	}
	idCol := findColumn(table.Columns, "id")
	if idCol == nil {
		t.Fatal("id column not found")
	}
	if !idCol.PrimaryKey {
		t.Error("id should be PrimaryKey")
	}
	if idCol.Nullable {
		t.Error("primary key column should be NOT NULL")
	}
	if string(idCol.Type) != "uuid" {
		t.Errorf("id type = %q, want uuid", idCol.Type)
	}
	if idCol.Default != "gen_random_uuid()" {
		t.Errorf("id default = %q, want gen_random_uuid()", idCol.Default)
	}

	emailCol := findColumn(table.Columns, "email")
	if emailCol == nil || emailCol.Nullable {
		t.Errorf("email column: expected NOT NULL, got %+v", emailCol)
	}

	createdAtCol := findColumn(table.Columns, "created_at")
	if createdAtCol == nil || string(createdAtCol.Type) != "timestamptz" {
		t.Errorf("created_at: expected timestamptz inferred from time.Time, got %+v", createdAtCol)
	}

	// email should have a unique index
	foundUniq := false
	for _, idx := range table.Indexes {
		if idx.Unique && len(idx.Columns) == 1 && idx.Columns[0] == "email" {
			foundUniq = true
			break
		}
	}
	if !foundUniq {
		t.Errorf("expected unique index on email, got indexes %+v", table.Indexes)
	}
}

const fixtureCamelCase = `
package models

type HTTPError struct {
	Code    int    ` + "`gorm:\"primaryKey\"`" + `
	Message string ` + "`gorm:\"type:text\"`" + `
}
`

func TestReadFile_CamelToSnake(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "http_error.go")
	if err := os.WriteFile(path, []byte(fixtureCamelCase), 0644); err != nil {
		t.Fatalf("write: %v", err)
	}
	spec, err := ReadFile(path, "api")
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if spec.Tables[0].Name != "http_error" {
		t.Errorf("table name = %q, want http_error", spec.Tables[0].Name)
	}
}

func findColumn(cols []keystonev1alpha1.DesiredColumn, name string) *keystonev1alpha1.DesiredColumn {
	for i := range cols {
		if cols[i].Name == name {
			return &cols[i]
		}
	}
	return nil
}
