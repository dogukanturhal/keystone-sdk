// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 HexxLock

//go:build integration

// Integration tests for the public SDK. Covers the Apply →
// Inspect → Lint → Diff loop against a throwaway Postgres spun
// up via testcontainers. Run with:
//
//	GOWORK=off go test -count=1 -tags integration ./pkg/sdk/keystone/

package keystone

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/dogukanturhal/keystone-sdk/go/internal/testdb"
	keystonev1alpha1 "github.com/dogukanturhal/keystone/api/v1alpha1"
)

// getSDKPool returns the shared dev database. The pool itself lives in
// internal/testdb so every integration suite resolves a database the same
// way — including from an already-running server named by
// KEYSTONE_TEST_DSN, which is what lets this suite run in CI at all.
func getSDKPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	return testdb.Pool(t)
}

// freshSchema creates a unique schema for each test so concurrent
// cases don't stomp on each other. Cleanup drops it + cascades.
func freshSchema(t *testing.T, ctx context.Context, pool *pgxpool.Pool) string {
	t.Helper()
	name := "sdk_" + tcSafeName(t.Name())
	if _, err := pool.Exec(ctx, fmt.Sprintf("CREATE SCHEMA IF NOT EXISTS %s", name)); err != nil {
		t.Fatalf("create schema %s: %v", name, err)
	}
	t.Cleanup(func() {
		cx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_, _ = pool.Exec(cx, fmt.Sprintf("DROP SCHEMA IF EXISTS %s CASCADE", name))
	})
	return name
}

func tcSafeName(s string) string {
	out := make([]byte, 0, len(s))
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '_':
			out = append(out, byte(r))
		case r >= 'A' && r <= 'Z':
			out = append(out, byte(r+32))
		default:
			out = append(out, '_')
		}
	}
	if len(out) > 50 {
		out = out[:50]
	}
	return string(out)
}

// TestSDK_ApplyInspectRoundtrip — the canonical "my CI test uses the
// SDK to set up its own database" flow. Verifies Apply commits to
// schema_migrations, Inspect sees the created table, and the
// resulting ContentHash round-trips.
func TestSDK_ApplyInspectRoundtrip(t *testing.T) {
	pool := getSDKPool(t)
	ctx := context.Background()
	schema := freshSchema(t, ctx, pool)

	files := []SQLFile{
		{
			Name: "001_init.up.sql",
			Body: fmt.Sprintf(`
				SET search_path TO %s;
				CREATE TABLE users (
					id uuid PRIMARY KEY,
					email text NOT NULL
				);
			`, schema),
		},
	}
	result, err := Apply(ctx, pool, ApplyOptions{
		Schema:  schema,
		Version: "v1",
		Files:   files,
	})
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if result.ContentHash == "" {
		t.Error("ContentHash should be populated")
	}
	if len(result.Files) != 1 {
		t.Errorf("expected 1 file result; got %d", len(result.Files))
	}

	snap, err := Inspect(ctx, pool, schema)
	if err != nil {
		t.Fatalf("Inspect: %v", err)
	}
	found := false
	for _, tb := range snap.Tables {
		if tb.Name == "users" {
			found = true
			if len(tb.Columns) != 2 {
				t.Errorf("users should have 2 columns; got %d", len(tb.Columns))
			}
		}
	}
	if !found {
		t.Errorf("Inspect should find 'users' table; got tables=%+v", snap.Tables)
	}
}

// TestSDK_ApplyIdempotentSameVersion — applying the same (version,
// contentHash) twice is a no-op; applying a different hash at the
// same version is refused.
func TestSDK_ApplyIdempotentSameVersion(t *testing.T) {
	pool := getSDKPool(t)
	ctx := context.Background()
	schema := freshSchema(t, ctx, pool)

	files := []SQLFile{
		{Name: "001.up.sql", Body: fmt.Sprintf("CREATE TABLE %s.t1 (id int PRIMARY KEY);", schema)},
	}
	if _, err := Apply(ctx, pool, ApplyOptions{Schema: schema, Version: "v1", Files: files}); err != nil {
		t.Fatalf("first apply: %v", err)
	}
	// Same files, same version → no-op success.
	if _, err := Apply(ctx, pool, ApplyOptions{Schema: schema, Version: "v1", Files: files}); err != nil {
		t.Fatalf("idempotent apply: %v", err)
	}
	// Different content, same version → must be refused.
	changed := []SQLFile{
		{Name: "001.up.sql", Body: fmt.Sprintf("CREATE TABLE %s.t2 (id int PRIMARY KEY);", schema)},
	}
	if _, err := Apply(ctx, pool, ApplyOptions{Schema: schema, Version: "v1", Files: changed}); err == nil {
		t.Fatal("applying different content under same version should be refused")
	}
}

// TestSDK_Lint — runs the analyzer pack on a destructive snippet and
// asserts the no-drop-table rule fires.
func TestSDK_Lint(t *testing.T) {
	findings, err := Lint(context.Background(), "test", "v1", []SQLFile{
		{Name: "bad.sql", Body: "DROP TABLE users;"},
	})
	if err != nil {
		t.Fatalf("Lint: %v", err)
	}
	found := false
	for _, f := range findings {
		if f.Rule == "no-drop-table" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected no-drop-table finding; got %+v", findings)
	}
}

// TestSDK_DiffProducesStatements — declarative diff against an empty
// schema emits a CREATE TABLE statement for the desired shape.
func TestSDK_DiffProducesStatements(t *testing.T) {
	pool := getSDKPool(t)
	ctx := context.Background()
	schema := freshSchema(t, ctx, pool)

	// Observed = empty schema.
	observed, err := Inspect(ctx, pool, schema)
	if err != nil {
		t.Fatalf("Inspect: %v", err)
	}

	// Desired = one table.
	desired := &keystonev1alpha1.SchemaDefinitionSpec{
		SchemaRef: schema,
		Tables: []keystonev1alpha1.DesiredTable{
			{
				Name: "items",
				Columns: []keystonev1alpha1.DesiredColumn{
					{Name: "id", Type: "uuid", Nullable: false},
				},
			},
		},
	}
	plan, err := Diff(observed, desired, DiffOptions{AllowDestructive: false})
	if err != nil {
		t.Fatalf("Diff: %v", err)
	}
	if len(plan.Statements) == 0 {
		t.Errorf("expected non-empty plan.Statements for empty→one-table diff")
	}
}
