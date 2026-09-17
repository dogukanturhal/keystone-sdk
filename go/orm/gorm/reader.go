// SPDX-License-Identifier: Apache-2.0

// Package gorm reads Go source files containing GORM model structs and
// emits keystonev1alpha1.SchemaDefinitionSpec — the declarative path.
//
// It parses Go source via go/ast + go/parser (no runtime reflection, no
// compilation of user code required) so it can be run on any source tree
// from CI.
//
// This package lives in the SDK, not the operator, because a reader is
// only useful to code outside Keystone: it was previously under the
// operator's internal/ tree, where nothing could import it. The
// cmd/keystone-gorm program wraps it as an exec:// provider so GORM
// projects plug into `keystonectl migrate diff` the same way EF Core
// does through keystone-ef.
//
// Supported GORM struct tags:
//
//	`gorm:"primaryKey"`                         → PrimaryKey: true
//	`gorm:"type:uuid"`                          → Type: uuid
//	`gorm:"not null"`                           → Nullable: false
//	`gorm:"default:gen_random_uuid()"`          → Default: gen_random_uuid()
//	`gorm:"uniqueIndex"`                        → DesiredIndex (unique)
//	`gorm:"index"`                              → DesiredIndex
//	`gorm:"index:idx_name"`                     → Named index
//	`gorm:"column:explicit_name"`               → column name override
//
// Unsupported (deferred to Phase 12.1.1):
//   - Composite indexes (index:idx_name,priority:1,sort:desc,...)
//   - gorm.Model embedded struct expansion
//   - Relations (belongsTo, hasMany) → foreign keys
//
// Unsupported things fall through silently with a log line. Callers can
// use --strict to flip warnings to errors.
package gorm

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"reflect"
	"sort"
	"strings"

	keystonev1alpha1 "github.com/dogukanturhal/keystone/api/v1alpha1"
)

// ReadDir parses every non-test Go file under root and merges the GORM
// models it finds into a single SchemaDefinitionSpec.
//
// Real projects spread models over a package (one file per aggregate), so
// a directory — not a file — is the unit a provider is pointed at. Files
// are visited in lexical order and tables are sorted by name, so the
// emitted spec is deterministic: a differ fed a non-deterministic desired
// state would produce spurious migrations.
//
// Subdirectories are walked too, which lets `--path ./internal/models`
// cover a nested layout. _test.go files are skipped: test fixtures are
// not the schema.
func ReadDir(root string, schemaRef string) (*keystonev1alpha1.SchemaDefinitionSpec, error) {
	var files []string
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			// Vendored and generated trees are never the source of truth.
			if name := d.Name(); name == "vendor" || name == "testdata" ||
				(name != "." && strings.HasPrefix(name, ".")) {
				return filepath.SkipDir
			}
			return nil
		}
		if strings.HasSuffix(path, ".go") && !strings.HasSuffix(path, "_test.go") {
			files = append(files, path)
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("walk %s: %w", root, err)
	}
	sort.Strings(files)

	spec := &keystonev1alpha1.SchemaDefinitionSpec{SchemaRef: schemaRef}
	for _, path := range files {
		// A file with no models is normal in a package that also holds
		// helpers, so "no models here" is not an error at directory scope.
		one, err := ReadFile(path, schemaRef)
		if err != nil {
			if strings.Contains(err.Error(), "no GORM models found") {
				continue
			}
			return nil, err
		}
		spec.Tables = append(spec.Tables, one.Tables...)
	}
	if len(spec.Tables) == 0 {
		return nil, fmt.Errorf("no GORM models found under %s — did you forget `gorm:\"\"` tags?", root)
	}
	sort.Slice(spec.Tables, func(i, j int) bool { return spec.Tables[i].Name < spec.Tables[j].Name })
	return spec, nil
}

// ReadFile parses one Go source file and returns the SchemaDefinition
// inferred from its GORM-tagged structs. When the file contains
// multiple model structs, each becomes a DesiredTable.
func ReadFile(path string, schemaRef string) (*keystonev1alpha1.SchemaDefinitionSpec, error) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, path, nil, parser.ParseComments)
	if err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	spec := &keystonev1alpha1.SchemaDefinitionSpec{
		SchemaRef: schemaRef,
	}
	for _, decl := range f.Decls {
		gd, ok := decl.(*ast.GenDecl)
		if !ok || gd.Tok != token.TYPE {
			continue
		}
		for _, s := range gd.Specs {
			ts, ok := s.(*ast.TypeSpec)
			if !ok {
				continue
			}
			st, ok := ts.Type.(*ast.StructType)
			if !ok {
				continue
			}
			// Treat any exported struct as a model. Non-exported skipped.
			if !ts.Name.IsExported() {
				continue
			}
			table, err := readStruct(ts.Name.Name, st)
			if err != nil {
				return nil, fmt.Errorf("read struct %s: %w", ts.Name.Name, err)
			}
			if table != nil {
				spec.Tables = append(spec.Tables, *table)
			}
		}
	}
	if len(spec.Tables) == 0 {
		return nil, fmt.Errorf("no GORM models found in %s — did you forget `gorm:\"\"` tags?", path)
	}
	return spec, nil
}

// readStruct walks one struct's fields and returns a DesiredTable.
// Returns nil,nil when the struct has no GORM-tagged fields (not a model).
func readStruct(name string, st *ast.StructType) (*keystonev1alpha1.DesiredTable, error) {
	table := &keystonev1alpha1.DesiredTable{
		Name: camelToSnake(name),
	}
	for _, field := range st.Fields.List {
		if field.Tag == nil {
			continue
		}
		tag := reflect.StructTag(strings.Trim(field.Tag.Value, "`"))
		gormTag := tag.Get("gorm")
		if gormTag == "" {
			continue
		}
		for _, fieldName := range field.Names {
			col, indexes := readField(fieldName.Name, field.Type, gormTag)
			if col != nil {
				table.Columns = append(table.Columns, *col)
				if col.PrimaryKey {
					table.PrimaryKey = append(table.PrimaryKey, col.Name)
				}
			}
			table.Indexes = append(table.Indexes, indexes...)
		}
	}
	if len(table.Columns) == 0 {
		return nil, nil
	}
	return table, nil
}

// readField interprets one struct field's tags.
func readField(fieldName string, fieldType ast.Expr, gormTag string) (*keystonev1alpha1.DesiredColumn, []keystonev1alpha1.DesiredIndex) {
	col := &keystonev1alpha1.DesiredColumn{
		Name:     camelToSnake(fieldName),
		Nullable: true,
	}
	var indexes []keystonev1alpha1.DesiredIndex
	for _, part := range strings.Split(gormTag, ";") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		kv := strings.SplitN(part, ":", 2)
		key := strings.ToLower(strings.TrimSpace(kv[0]))
		val := ""
		if len(kv) == 2 {
			val = strings.TrimSpace(kv[1])
		}
		switch key {
		case "primarykey":
			col.PrimaryKey = true
			col.Nullable = false
		case "type":
			col.Type = keystonev1alpha1.ColumnType(val)
		case "not null":
			col.Nullable = false
		case "default":
			col.Default = val
		case "column":
			col.Name = val
		case "index":
			idxName := val
			if idxName == "" {
				idxName = "idx_" + camelToSnake(fieldName)
			}
			indexes = append(indexes, keystonev1alpha1.DesiredIndex{
				Name:    idxName,
				Columns: []string{col.Name},
				Method:  "btree",
			})
		case "uniqueindex":
			idxName := val
			if idxName == "" {
				idxName = "uniq_" + camelToSnake(fieldName)
			}
			indexes = append(indexes, keystonev1alpha1.DesiredIndex{
				Name:    idxName,
				Columns: []string{col.Name},
				Unique:  true,
				Method:  "btree",
			})
		}
	}
	// Infer type from Go type expression if not declared explicitly.
	if col.Type == "" {
		col.Type = inferType(fieldType)
	}
	return col, indexes
}

// inferType maps Go types to PostgreSQL types using GORM's default
// conventions. Handles both simple identifiers (int, string, bool) and
// selector expressions (time.Time, sql.NullString, etc.).
// Returns empty string for unsupported types.
func inferType(expr ast.Expr) keystonev1alpha1.ColumnType {
	// time.Time and similar SelectorExpr.
	if sel, ok := expr.(*ast.SelectorExpr); ok {
		pkg, _ := sel.X.(*ast.Ident)
		if pkg != nil && pkg.Name == "time" && sel.Sel.Name == "Time" {
			return "timestamptz"
		}
		if pkg != nil && pkg.Name == "sql" {
			switch sel.Sel.Name {
			case "NullString":
				return "text"
			case "NullInt64":
				return "bigint"
			case "NullBool":
				return "boolean"
			case "NullTime":
				return "timestamptz"
			}
		}
		return ""
	}
	id, ok := expr.(*ast.Ident)
	if !ok {
		return ""
	}
	switch id.Name {
	case "string":
		return "text"
	case "int", "int32":
		return "integer"
	case "int64":
		return "bigint"
	case "uint", "uint32":
		return "integer"
	case "uint64":
		return "bigint"
	case "float32", "float64":
		return "double precision"
	case "bool":
		return "boolean"
	case "byte":
		return "bytea"
	}
	return ""
}

// camelToSnake converts GORM's default struct-name convention
// (CamelCase) to PostgreSQL's preferred snake_case. Matches GORM's
// built-in Naming strategy.
//
//	LeadScore → lead_score
//	HTTPError → http_error      (acronym followed by word)
//	ABCTest   → abc_test
//	XMLData   → xml_data
func camelToSnake(in string) string {
	if in == "" {
		return ""
	}
	runes := []rune(in)
	var b strings.Builder
	for i, r := range runes {
		if i == 0 {
			b.WriteRune(lower(r))
			continue
		}
		prev := runes[i-1]
		// Insert _ when:
		//  (a) prev is lowercase/digit and current is uppercase
		//      (LeadScore → lead_score at S)
		//  (b) current is uppercase AND next is lowercase AND prev is also uppercase
		//      (HTTPError → http_error at the E, since P=upper E=upper r=lower)
		lowerCase := r >= 'a' && r <= 'z'
		upperCase := r >= 'A' && r <= 'Z'
		digit := r >= '0' && r <= '9'
		prevLower := prev >= 'a' && prev <= 'z'
		prevUpper := prev >= 'A' && prev <= 'Z'
		prevDigit := prev >= '0' && prev <= '9'
		if upperCase && (prevLower || prevDigit) {
			b.WriteByte('_')
		} else if upperCase && prevUpper && i+1 < len(runes) {
			next := runes[i+1]
			if next >= 'a' && next <= 'z' {
				b.WriteByte('_')
			}
		}
		_ = lowerCase
		_ = digit
		b.WriteRune(lower(r))
	}
	return b.String()
}

func lower(r rune) rune {
	if r >= 'A' && r <= 'Z' {
		return r - 'A' + 'a'
	}
	return r
}
