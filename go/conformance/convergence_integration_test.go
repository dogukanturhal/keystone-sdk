// SPDX-License-Identifier: Apache-2.0

//go:build integration

package conformance

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/dogukanturhal/keystone-sdk/go/authoring"
	"github.com/dogukanturhal/keystone-sdk/go/declarative"
	"github.com/dogukanturhal/keystone-sdk/go/drift"
	"github.com/dogukanturhal/keystone-sdk/go/internal/testdb"
	"github.com/dogukanturhal/keystone-sdk/go/schemasource"
	"github.com/dogukanturhal/keystone-sdk/go/schemaspec"
)

// targetSchema is the logical schema every snapshot reports, so two
// snapshots taken from different scratch schemas are comparable.
const targetSchema = "app"

// TestConvergence is the round-trip harness.
//
// For every schema in testdata/, it asserts three properties. Each one
// catches a different class of fidelity bug, and each one corresponds to
// bugs that reached production before this existed:
//
//	P1 idempotence   Diff(observed, FromSnapshot(observed)) is empty.
//	                 Catches anything the inspector reports that the spec
//	                 does not carry — the differ then reads the absence as
//	                 "the user deleted it" and authors a DROP. This is how
//	                 the differ came to emit DROP INDEX for the index
//	                 backing a live PRIMARY KEY.
//
//	P2 reproduction  Rebuilding from the spec yields the same catalog.
//	                 Catches loss that survives P1 because the differ
//	                 matches on something coarser than it emits — a
//	                 primary key matched by column list round-tripped
//	                 under a different constraint name for exactly this
//	                 reason.
//
//	P3 convergence   Diff(rebuilt, FromSnapshot(observed)) is empty.
//	                 Catches asymmetry between what the renderer emits and
//	                 what the inspector reads back, which is what makes a
//	                 migration re-author itself on every run.
//
// The corpus is the regression suite: every historical `fix(differ)`
// commit is a file here, so the class stops being rediscovered in
// production drift reports.
func TestConvergence(t *testing.T) {
	pool := testdb.Pool(t)
	ctx := context.Background()

	files, err := filepath.Glob(filepath.Join("testdata", "*.sql"))
	if err != nil {
		t.Fatalf("glob testdata: %v", err)
	}
	if len(files) == 0 {
		t.Fatal("no corpus files in testdata/ — the harness would pass vacuously")
	}

	for _, path := range files {
		name := strings.TrimSuffix(filepath.Base(path), ".sql")
		t.Run(name, func(t *testing.T) {
			// Safe to run in parallel: every entry is materialised into its
			// own scratch schema, and the inspector scopes each object type
			// — extensions included — to the schema being inspected. When
			// extensions were reported database-wide this suite failed on a
			// different subset every run, which is how that bug was found.
			t.Parallel()

			ddl, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("read corpus: %v", err)
			}

			// Establish the observed state by applying the corpus DDL to a
			// throwaway schema and reading it back with the production
			// inspector — the same path a real `--desired sql://` takes.
			observed, err := schemasource.SnapshotFromDDL(ctx, pool, string(ddl), targetSchema)
			if err != nil {
				t.Fatalf("materialise corpus: %v", err)
			}
			spec := schemaspec.FromSnapshot(observed, schemaspec.Options{SchemaRef: targetSchema})

			// --- P1: idempotence -------------------------------------
			plan, err := declarative.Diff(observed, spec)
			if err != nil {
				t.Fatalf("P1 diff: %v", err)
			}
			if !plan.Empty() {
				t.Errorf("P1 idempotence: a schema diffed against a spec derived from itself "+
					"must need no changes, got %d statement(s):\n%s",
					len(plan.Statements), indent(plan.Statements))
			}

			// --- P2: reproduction ------------------------------------
			//
			// Render through the same authoring path keystonectl uses, so
			// the harness covers statement ordering, schema-relative
			// rewriting and the up/down split rather than only the raw
			// differ output.
			empty := &drift.Snapshot{Schema: targetSchema}
			createPlan, err := declarative.Diff(empty, spec)
			if err != nil {
				t.Fatalf("P2 create-diff: %v", err)
			}
			bundle := authoring.RenderUpDown(createPlan, authoring.Options{
				Name:        "conformance",
				Version:     "001",
				Schema:      targetSchema,
				StripSchema: targetSchema,
				GeneratedBy: "conformance harness",
			})
			rebuilt, err := schemasource.SnapshotFromFiles(ctx, pool,
				map[string]string{bundle.UpFile: bundle.Up}, targetSchema)
			if err != nil {
				t.Fatalf("P2 apply generated DDL: %v\n--- generated ---\n%s", err, bundle.Up)
			}
			if d := snapshotDiff(observed, rebuilt); d != "" {
				t.Errorf("P2 reproduction: rebuilding from the generated DDL produced a "+
					"different schema:\n%s\n--- generated ---\n%s", d, bundle.Up)
			}

			// --- P3: convergence -------------------------------------
			converge, err := declarative.Diff(rebuilt, spec)
			if err != nil {
				t.Fatalf("P3 diff: %v", err)
			}
			if !converge.Empty() {
				t.Errorf("P3 convergence: re-diffing the rebuilt schema must be a no-op, "+
					"got %d statement(s):\n%s",
					len(converge.Statements), indent(converge.Statements))
			}
		})
	}
}

// snapshotDiff returns a human-readable description of the first
// structural differences between two snapshots, or "" when they match.
//
// Compared as canonical JSON rather than by hash: a hash mismatch tells
// you something is wrong and nothing about what, and this harness exists
// to be actionable when it fires.
func snapshotDiff(want, got *drift.Snapshot) string {
	wantJSON, err := json.MarshalIndent(want, "", "  ")
	if err != nil {
		return "marshal want: " + err.Error()
	}
	gotJSON, err := json.MarshalIndent(got, "", "  ")
	if err != nil {
		return "marshal got: " + err.Error()
	}
	if string(wantJSON) == string(gotJSON) {
		return ""
	}

	wantLines := strings.Split(string(wantJSON), "\n")
	gotLines := strings.Split(string(gotJSON), "\n")
	var b strings.Builder
	shown := 0
	for i := 0; i < len(wantLines) || i < len(gotLines); i++ {
		w, g := "", ""
		if i < len(wantLines) {
			w = wantLines[i]
		}
		if i < len(gotLines) {
			g = gotLines[i]
		}
		if w == g {
			continue
		}
		b.WriteString("  original: " + strings.TrimSpace(w) + "\n")
		b.WriteString("  rebuilt:  " + strings.TrimSpace(g) + "\n")
		shown++
		if shown >= 12 {
			b.WriteString("  … further differences elided\n")
			break
		}
	}
	return b.String()
}

func indent(stmts []string) string {
	var b strings.Builder
	for _, s := range stmts {
		b.WriteString("    " + strings.ReplaceAll(strings.TrimSpace(s), "\n", "\n    ") + "\n")
	}
	return b.String()
}
