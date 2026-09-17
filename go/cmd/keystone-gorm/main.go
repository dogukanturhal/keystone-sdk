// SPDX-License-Identifier: Apache-2.0

// keystone-gorm — the Keystone schema provider for GORM.
//
// Prints the desired schema described by a tree of GORM model structs on
// stdout, for consumption through Keystone's exec:// source scheme:
//
//	keystonectl migrate diff add_leads \
//	    --desired 'exec://go run github.com/dogukanturhal/keystone-sdk/go/cmd/keystone-gorm@latest --path ./models' \
//	    --dev-url postgres://…/devdb --dir migrations
//
// The provider contract is the same one keystone-ef honours, because
// exec:// only knows one contract: stdout is the desired schema as
// PostgreSQL DDL, stderr is diagnostics, non-zero exit means failure.
// That uniformity is the point — Keystone learns nothing about GORM, and
// GORM projects get the same workflow .NET projects get.
//
// Models are read statically via go/ast, so no user code is compiled or
// executed and no database connection is opened.
package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"sigs.k8s.io/yaml"

	"github.com/dogukanturhal/keystone-sdk/go/authoring"
	"github.com/dogukanturhal/keystone-sdk/go/declarative"
	"github.com/dogukanturhal/keystone-sdk/go/drift"
	"github.com/dogukanturhal/keystone-sdk/go/orm/gorm"
	keystonev1alpha1 "github.com/dogukanturhal/keystone/api/v1alpha1"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "keystone-gorm: %v\n", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	fs := flag.NewFlagSet("keystone-gorm", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	var (
		path      = fs.String("path", ".", "directory (or single .go file) holding the GORM models")
		schemaRef = fs.String("schema-ref", "", "DatabaseSchema name to record in the emitted spec (yaml format only)")
		schema    = fs.String("schema", "public", "schema name the DDL is rendered for")
		format    = fs.String("format", "sql", "output format: sql (DDL, the exec:// contract) or yaml (SchemaDefinition spec)")
	)
	fs.Usage = func() {
		fmt.Fprint(os.Stderr, usage)
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return err
	}

	st, err := os.Stat(*path)
	if err != nil {
		return fmt.Errorf("read models at %s: %w", *path, err)
	}

	spec, err := readSpec(*path, *schemaRef, st.IsDir())
	if err != nil {
		return err
	}

	switch strings.ToLower(*format) {
	case "yaml":
		out, err := yaml.Marshal(spec)
		if err != nil {
			return fmt.Errorf("render spec as yaml: %w", err)
		}
		_, err = os.Stdout.Write(out)
		return err

	case "sql":
		// Diffing the desired spec against an empty schema yields exactly
		// the CREATE statements that would build it from nothing — which is
		// what a provider is asked for. Reusing the differ rather than
		// writing a second DDL renderer keeps one code path responsible for
		// how a spec becomes SQL, so providers can never drift from what
		// the operator would actually emit.
		plan, err := declarative.Diff(&drift.Snapshot{Schema: *schema}, spec)
		if err != nil {
			return fmt.Errorf("render spec as DDL: %w", err)
		}
		for _, w := range plan.Warnings {
			fmt.Fprintf(os.Stderr, "warning: %s\n", w)
		}
		if len(plan.Statements) == 0 {
			return fmt.Errorf("models produced no DDL — the structs parsed but declare no columns")
		}
		// Hand Keystone schema-relative DDL. The differ qualifies objects
		// with the target schema, but the normaliser applies provider output
		// under a scratch schema's search_path — a qualifier there would pin
		// every object to a schema that is not the one being diffed. Same
		// contract keystone-ef honours with --strip-schema.
		var b strings.Builder
		for _, s := range plan.Statements {
			s = authoring.StripSchemaQualifier(s, *schema)
			if s = strings.TrimSpace(strings.TrimRight(s, ";\n")); s == "" {
				continue
			}
			b.WriteString(s)
			b.WriteString(";\n")
		}
		_, err = os.Stdout.WriteString(b.String())
		return err

	default:
		return fmt.Errorf("unknown --format %q: want sql or yaml", *format)
	}
}

func readSpec(path, schemaRef string, isDir bool) (*keystonev1alpha1.SchemaDefinitionSpec, error) {
	if isDir {
		return gorm.ReadDir(path, schemaRef)
	}
	return gorm.ReadFile(path, schemaRef)
}

const usage = `keystone-gorm — export GORM models as Keystone schema-as-code.

Prints the desired schema as PostgreSQL DDL on stdout. Diagnostics go to
stderr, so stdout is always pipeable as pure DDL.

USAGE
  keystone-gorm [--path ./models] [--schema public] [--format sql|yaml]

KEYSTONE USAGE
  keystonectl migrate diff add_leads \
      --desired 'exec://keystone-gorm --path ./models' \
      --dev-url postgres://localhost/devdb --dir migrations

  …or, in keystone.yaml:

    desired:
      program: [keystone-gorm, --path, ./models]

OPTIONS
`
