// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 HexxLock

package keystone_test

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"

	ks "github.com/dogukanturhal/keystone-sdk/go/keystone"
)

// ExampleApply demonstrates the typical CI test flow: feed in an
// ordered list of SQL files, call Apply, verify success. The
// runner handles bookkeeping (schema_migrations table) + per-file
// transactions automatically.
func ExampleApply() {
	ctx := context.Background()

	// Caller owns the pool — spin up via testcontainers, dev instance,
	// or whatever Postgres the test harness provides.
	pool, _ := pgxpool.New(ctx, "postgres://app:secret@localhost:5432/app?sslmode=disable")
	defer pool.Close()

	_, err := ks.Apply(ctx, pool, ks.ApplyOptions{
		Schema:  "public",
		Version: "v1",
		Files: []ks.SQLFile{
			{Name: "001_init.up.sql", Body: `
				CREATE TABLE IF NOT EXISTS items (
					id uuid PRIMARY KEY,
					name text NOT NULL
				);
			`},
		},
	})
	if err != nil {
		fmt.Println("apply failed:", err)
		return
	}
	fmt.Println("applied")
	// Output would be: applied
}

// ExampleLint demonstrates the zero-dependency lint flow — no
// database needed, pure string-in / findings-out. Useful as a
// pre-commit check in CI.
func ExampleLint() {
	findings, _ := ks.Lint(context.Background(), "my-app", "v2",
		[]ks.SQLFile{
			{Name: "002_users.up.sql", Body: "DROP TABLE users;"},
		})
	for _, f := range findings {
		fmt.Printf("%s [%s] %s\n", f.Severity, f.Rule, f.Message)
	}
}

// ExampleInspect demonstrates reading the live schema shape — tables,
// columns, indexes, constraints.
func ExampleInspect() {
	ctx := context.Background()
	pool, _ := pgxpool.New(ctx, "postgres://app:secret@localhost:5432/app?sslmode=disable")
	defer pool.Close()

	snap, err := ks.Inspect(ctx, pool, "public")
	if err != nil {
		fmt.Println("inspect failed:", err)
		return
	}
	for _, t := range snap.Tables {
		fmt.Printf("%s (%d columns)\n", t.Name, len(t.Columns))
	}
}
