// SPDX-License-Identifier: AGPL-3.0-or-later

package analyze

import (
	"context"
	"fmt"
	"math/rand"
	"strings"
	"testing"
)

// Phase S11 — analyzer benchmarks.
//
// Two cohorts:
//
//  1. BenchmarkPerAnalyzer_* — one sub-benchmark per analyzer against a
//     10_000-line synthetic SQL body. Measures per-rule throughput and
//     allocation cost in isolation.
//  2. BenchmarkDefaultRegistry_Run — aggregate wall-clock through the
//     full DefaultRegistry(), same input. This is the number users feel
//     when a MigrationBundle is admitted.
//
// All benchmarks call b.ReportAllocs so `go test -benchmem` prints
// bytes + allocs per op; output is stable across runs given the
// deterministic PRNG seed.
//
// Run locally with:
//
//	make bench
//
// or directly:
//
//	GOWORK=off go test -bench=. -benchmem -count=5 -run=^$ ./internal/migration/analyze/...

const (
	benchSeed     = int64(20260416)
	benchNumLines = 10_000
)

// syntheticSQL builds a deterministic SQL body intermixing every
// statement shape the analyzers care about (CREATE TABLE, ALTER TABLE,
// CREATE INDEX, GRANT, TRUNCATE, DROP) so the per-analyzer benchmarks
// exercise both hit and miss paths rather than one-sided happy-path
// scanning.
func syntheticSQL(lines int) string {
	r := rand.New(rand.NewSource(benchSeed))
	patterns := []string{
		"CREATE TABLE IF NOT EXISTS t_%d (id BIGINT PRIMARY KEY, name TEXT NOT NULL DEFAULT '', created_at TIMESTAMPTZ NOT NULL DEFAULT NOW());",
		"ALTER TABLE t_%d ADD COLUMN col_%d TEXT DEFAULT '';",
		"CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_t_%d_name ON t_%d (name);",
		"CREATE INDEX idx_t_%d_created ON t_%d (created_at);", // triggers prefer-concurrent
		"GRANT SELECT, INSERT ON t_%d TO app_role;",
		"ALTER TABLE t_%d ALTER COLUMN name TYPE VARCHAR(255);", // triggers no-alter-column-type-in-place
		"ALTER TABLE t_%d DROP COLUMN col_%d;",                  // triggers no-drop-column
		"DROP TABLE IF EXISTS old_%d;",                          // triggers no-drop-table
		"TRUNCATE TABLE t_%d;",                                  // triggers no-truncate
		"GRANT ALL ON t_%d TO app_role;",                        // triggers no-grant-all
		"SET LOCAL statement_timeout = '30s';",
		"-- regular comment line with no DDL",
	}
	var b strings.Builder
	b.Grow(lines * 80)
	b.WriteString("-- Phase S11 benchmark fixture (deterministic PRNG)\n")
	for i := 0; i < lines; i++ {
		p := patterns[r.Intn(len(patterns))]
		// Format with up to 2 ints — harmless to supply extras; fmt
		// collapses trailing %!d when unused. Safer: build the args
		// deterministically.
		switch strings.Count(p, "%d") {
		case 0:
			b.WriteString(p)
		case 1:
			fmt.Fprintf(&b, p, i)
		case 2:
			fmt.Fprintf(&b, p, i, i)
		}
		b.WriteByte('\n')
	}
	return b.String()
}

// newBenchMigration builds the Migration object every benchmark uses.
// Building it once outside the b.N loop is important — we want to
// measure Analyzer.Check, not string construction.
func newBenchMigration() *Migration {
	body := syntheticSQL(benchNumLines)
	return &Migration{
		BundleName:   "bench-bundle",
		Version:      "v1",
		TargetSchema: "public",
		Files:        []FileBody{{Name: "bench.up.sql", Body: body}},
	}
}

// BenchmarkPerAnalyzer_* measures the isolated cost of each analyzer in
// DefaultRegistry() against the shared 10k-line fixture. Use benchstat
// (golang.org/x/perf/cmd/benchstat) across -count=5 runs to get stable
// deltas when tuning a rule.
func BenchmarkPerAnalyzer(b *testing.B) {
	m := newBenchMigration()
	reg := DefaultRegistry()
	ctx := context.Background()
	for _, a := range reg.analyzers {
		a := a
		b.Run(a.ID(), func(b *testing.B) {
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if _, err := a.Check(ctx, m); err != nil {
					b.Fatalf("%s: %v", a.ID(), err)
				}
			}
		})
	}
}

// BenchmarkDefaultRegistry_Run measures the end-to-end cost of running
// every analyzer in DefaultRegistry() against the synthetic bundle —
// the path MigrationBundleReconciler takes during admission.
func BenchmarkDefaultRegistry_Run(b *testing.B) {
	m := newBenchMigration()
	reg := DefaultRegistry()
	ctx := context.Background()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		findings, err := reg.Run(ctx, m)
		if err != nil {
			b.Fatalf("registry.Run: %v", err)
		}
		if len(findings) == 0 {
			b.Fatalf("expected findings on synthetic bundle; got 0 — fixture regression?")
		}
	}
}

// BenchmarkDefaultRegistry_Run_ThroughputLines reports findings per
// second normalized against the fixture size — useful when comparing
// across machines. Computed as b.N * benchNumLines / elapsed.
// `go test` exposes this as a custom metric on each benchmark line.
func BenchmarkDefaultRegistry_Run_Throughput(b *testing.B) {
	m := newBenchMigration()
	reg := DefaultRegistry()
	ctx := context.Background()
	b.ReportAllocs()
	b.ResetTimer()
	var totalFindings int64
	for i := 0; i < b.N; i++ {
		findings, err := reg.Run(ctx, m)
		if err != nil {
			b.Fatalf("run: %v", err)
		}
		totalFindings += int64(len(findings))
	}
	b.StopTimer()
	// Report custom metrics so benchstat can surface them.
	b.ReportMetric(float64(benchNumLines*b.N)/b.Elapsed().Seconds(), "lines/s")
	b.ReportMetric(float64(totalFindings)/b.Elapsed().Seconds(), "findings/s")
}
