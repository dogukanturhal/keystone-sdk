// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 HexxLock

package keystone

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/dogukanturhal/keystone-sdk/go/analyze"
	"github.com/dogukanturhal/keystone-sdk/go/declarative"
	"github.com/dogukanturhal/keystone-sdk/go/drift"
	"github.com/dogukanturhal/keystone-sdk/go/migration"
	keystonev1alpha1 "github.com/dogukanturhal/keystone/api/v1alpha1"
)

// SQLFile is one migration file the SDK ingests. The file order is the
// caller's responsibility; the runner applies files in the slice
// order. Name is displayed in lint diagnostics and stored on the
// tracking row, so use something traceable (e.g. `001_init.up.sql`).
type SQLFile struct {
	// Name is displayed in diagnostics and stored in the tracking
	// table. Typically a filename like "001_init.up.sql".
	Name string
	// Body is the SQL text. Runner wraps the whole file in a single
	// transaction, so multiple statements are fine.
	Body string
}

// ApplyOptions bundles the arguments Apply needs to run a versioned
// migration against a caller-supplied *pgxpool.Pool. The pool's
// connection MUST belong to the target database; the runner issues
// SET search_path to target Schema per-statement.
type ApplyOptions struct {
	// Schema is the PG schema the runner operates against. Identifier-
	// validated before any DDL is issued; must match ^[a-z_][a-z0-9_]*$.
	Schema string

	// Version is the migration version. Recorded in the tracking
	// table (schema_migrations by default) along with a content
	// hash. Applying twice with the same (Version, ContentHash) pair
	// is a no-op; (Version, different ContentHash) is refused with
	// a clear error.
	Version string

	// Files is the ordered slice of SQL files the runner applies.
	// Each file is its own transaction — a failure rolls back the
	// failing file but leaves prior files committed.
	Files []SQLFile

	// TrackingTable overrides the default "schema_migrations" table
	// name. Useful when adopting Keystone in a database that already
	// uses the default name for a different tool (golang-migrate).
	// Empty string = DefaultTrackingTable.
	TrackingTable string

	// OwnerRole, when non-empty, makes the runner SET LOCAL ROLE to
	// this PG role inside the migration transaction. Tables created by
	// the migration will then be owned by OwnerRole instead of the
	// connection's authenticated user. Required for the canonical
	// owner/_app role-split pattern where the runtime _app role
	// inherits SELECT/INSERT/UPDATE/DELETE via inRoles: [_owner] —
	// without SET LOCAL ROLE the migration's CREATE TABLE leaves
	// objects owned by the migration user (`keystone_admin`) and the
	// inheritance gives _app nothing.
	//
	// The pool's user MUST be a member of OwnerRole (PG SET ROLE
	// requirement). Empty preserves backwards-compatible behavior:
	// no SET LOCAL ROLE, tables inherit the connection user.
	OwnerRole string
}

// ApplyResult reports what actually ran, duration, and the content
// hash the runner recorded. ContentHash is stable across identical
// file contents and is the primary anti-replay token.
type ApplyResult struct {
	// Version mirrors the input for the caller's convenience.
	Version string
	// ContentHash is the SHA-256 recorded in the tracking table.
	ContentHash string
	// TotalDurationMS is wall-clock time across all files.
	TotalDurationMS int64
	// Files lists per-file timings in apply order.
	Files []FileResult
}

// FileResult is one SQL file's execution outcome.
type FileResult struct {
	// File is the SQLFile.Name.
	File string
	// Index is the 1-based position in Files.
	Index int32
	// DurationMS is wall-clock time for this file's transaction.
	DurationMS int64
	// RowsAffected is the pgx command tag's RowsAffected. -1 for
	// statements without a row count (most DDL).
	RowsAffected int64
}

// Apply runs the given migration against pool. It opens the tracking
// table if absent, refuses on (Version, different ContentHash), and
// commits per-file. Returns the per-file result slice on success.
//
// The pool is NOT closed by Apply — callers own lifecycle.
func Apply(ctx context.Context, pool *pgxpool.Pool, opts ApplyOptions) (*ApplyResult, error) {
	if pool == nil {
		return nil, fmt.Errorf("keystone sdk: Apply requires a non-nil pool")
	}
	if opts.Schema == "" {
		return nil, fmt.Errorf("keystone sdk: ApplyOptions.Schema is required")
	}
	if opts.Version == "" {
		return nil, fmt.Errorf("keystone sdk: ApplyOptions.Version is required")
	}
	if len(opts.Files) == 0 {
		return nil, fmt.Errorf("keystone sdk: ApplyOptions.Files is empty")
	}

	tracking := opts.TrackingTable
	if tracking == "" {
		tracking = migration.DefaultTrackingTable
	}

	runner, err := migration.NewRunner(pool, opts.Schema, tracking, opts.OwnerRole)
	if err != nil {
		return nil, fmt.Errorf("keystone sdk: new runner: %w", err)
	}
	if err := runner.EnsureBookkeeping(ctx); err != nil {
		return nil, fmt.Errorf("keystone sdk: ensure bookkeeping: %w", err)
	}

	src := toResolvedSource(opts.Files)

	// Idempotency gate: if the version is already applied with the
	// same ContentHash, short-circuit to a no-op success. Refuse on
	// same-version / different-hash (anti-replay). Mirrors the
	// MigrationExecution controller's logic so SDK + operator behave
	// identically under retries.
	applied, prior, err := runner.IsApplied(ctx, opts.Version)
	if err != nil {
		return nil, fmt.Errorf("keystone sdk: check applied: %w", err)
	}
	if applied {
		if prior.ContentHash != src.ContentHash {
			return nil, fmt.Errorf(
				"keystone sdk: version %q already applied with contentHash %q; "+
					"new content hashes to %q — bump Version to ship changed SQL",
				opts.Version, prior.ContentHash, src.ContentHash)
		}
		return &ApplyResult{
			Version:     opts.Version,
			ContentHash: src.ContentHash,
			// No new per-file runs; caller can distinguish by an
			// empty Files slice.
		}, nil
	}

	result, err := runner.Apply(ctx, opts.Version, src.ContentHash, src)
	if err != nil {
		return nil, fmt.Errorf("keystone sdk: apply: %w", err)
	}

	files := make([]FileResult, 0, len(result.Files))
	for _, f := range result.Files {
		files = append(files, FileResult{
			File: f.File, Index: f.Index,
			DurationMS: f.DurationMS, RowsAffected: f.RowsAffected,
		})
	}
	return &ApplyResult{
		Version:         opts.Version,
		ContentHash:     src.ContentHash,
		TotalDurationMS: result.TotalDurationMS,
		Files:           files,
	}, nil
}

// LintFinding is one analyzer result. Severity is one of
// "error" / "warning" / "notice".
type LintFinding struct {
	Rule     string
	Severity string
	File     string
	Line     int32
	Message  string
}

// Lint runs Keystone's analyzer pack (52+ rules) against the given
// SQL files and returns findings. Bundle / Version / Schema are used
// for finding provenance; pass whatever identifiers your workflow
// uses. Nil pool — Lint is a pure Go function, no database needed.
func Lint(ctx context.Context, bundle, version string, files []SQLFile) ([]LintFinding, error) {
	body := make([]analyze.FileBody, 0, len(files))
	for _, f := range files {
		body = append(body, analyze.FileBody{Name: f.Name, Body: f.Body})
	}
	raw, err := analyze.DefaultRegistry().Run(ctx, &analyze.Migration{
		BundleName: bundle,
		Version:    version,
		Files:      body,
	})
	if err != nil && len(raw) == 0 {
		return nil, fmt.Errorf("keystone sdk: lint: %w", err)
	}
	out := make([]LintFinding, 0, len(raw))
	for _, f := range raw {
		out = append(out, LintFinding{
			Rule:     f.Rule,
			Severity: string(f.Severity),
			File:     f.File,
			Line:     f.Line,
			Message:  f.Message,
		})
	}
	return out, nil
}

// Snapshot is the introspected structural shape of a live schema.
// Tables are ordered by name; columns are ordered by ordinal.
type Snapshot struct {
	Schema      string
	Tables      []Table
	Indexes     []ObjectDDL
	Constraints []ObjectDDL
}

// Table is one base table or view.
type Table struct {
	Name    string
	Kind    string // "BASE TABLE", "VIEW", etc.
	Columns []Column
}

// Column is one column's shape.
type Column struct {
	Name     string
	Ordinal  int
	DataType string
	UDTName  string
	Nullable bool
	Default  string
}

// ObjectDDL is the generic (name, table, type, definition) shape used
// for indexes and constraints.
type ObjectDDL struct {
	Name       string
	Table      string
	Type       string
	Definition string
}

// Inspect returns the live structural snapshot for the given schema.
// Runs read-only queries against information_schema / pg_catalog.
func Inspect(ctx context.Context, pool *pgxpool.Pool, schema string) (*Snapshot, error) {
	if pool == nil {
		return nil, fmt.Errorf("keystone sdk: Inspect requires a non-nil pool")
	}
	raw, err := drift.NewInspector(pool).Inspect(ctx, schema)
	if err != nil {
		return nil, fmt.Errorf("keystone sdk: inspect: %w", err)
	}
	out := &Snapshot{Schema: raw.Schema}
	for _, t := range raw.Tables {
		st := Table{Name: t.Name, Kind: t.Kind}
		for _, c := range t.Columns {
			st.Columns = append(st.Columns, Column{
				Name: c.Name, Ordinal: c.Ordinal,
				DataType: c.DataType, UDTName: c.UDTName,
				Nullable: c.Nullable, Default: c.Default,
			})
		}
		out.Tables = append(out.Tables, st)
	}
	for _, ix := range raw.Indexes {
		out.Indexes = append(out.Indexes, ObjectDDL{
			Name: ix.Name, Table: ix.Table, Type: ix.Type, Definition: ix.Definition,
		})
	}
	for _, c := range raw.Constraints {
		out.Constraints = append(out.Constraints, ObjectDDL{
			Name: c.Name, Table: c.Table, Type: c.Type, Definition: c.Definition,
		})
	}
	return out, nil
}

// DiffPlan is the output of Diff — the SQL the caller would need to
// run against Observed to converge on Desired. Destructive ops
// (DROP COLUMN, DROP TABLE) are flagged separately so tools can gate
// on them; they are NOT emitted into Statements unless AllowDestructive
// is true in DiffOptions.
type DiffPlan struct {
	Statements     []string
	Warnings       []string
	DestructiveOps int
}

// DiffOptions configures the declarative differ.
type DiffOptions struct {
	// AllowDestructive controls whether DROP statements appear in
	// Plan.Statements. Default false — destructive ops are counted
	// but not emitted, giving callers a chance to prompt the operator.
	AllowDestructive bool
}

// Diff computes the statements needed to reach desired state from the
// observed snapshot. Observed typically comes from Inspect; Desired is
// authored as a SchemaDefinitionSpec (same shape as `keystonectl
// inspect` output). A non-nil error with an embedded
// declarative.ErrDestructiveRefused reports that the diff would
// require DROP statements and AllowDestructive was false — callers
// can inspect Plan.DestructiveOps to decide whether to retry with the
// opt-in.
func Diff(observed *Snapshot, desired *keystonev1alpha1.SchemaDefinitionSpec, opts DiffOptions) (*DiffPlan, error) {
	if observed == nil {
		return nil, fmt.Errorf("keystone sdk: Diff requires a non-nil observed snapshot")
	}
	if desired == nil {
		return nil, fmt.Errorf("keystone sdk: Diff requires a non-nil desired spec")
	}
	// Deep-copy the caller's desired spec so we don't mutate their
	// pointer. The differ reads desired.AllowDestructive as the
	// authoritative gate.
	desiredCopy := desired.DeepCopy()
	desiredCopy.AllowDestructive = opts.AllowDestructive

	raw := driftSnapshotFromSDK(observed)
	plan, err := declarative.Diff(raw, desiredCopy)
	out := &DiffPlan{
		Warnings:       nil,
		DestructiveOps: 0,
	}
	if plan != nil {
		out.Statements = plan.Statements
		out.Warnings = plan.Warnings
		out.DestructiveOps = plan.DestructiveOps
	}
	if err != nil {
		return out, fmt.Errorf("keystone sdk: diff: %w", err)
	}
	return out, nil
}

// -- internal helpers (not exported) ----------------------------------

// toResolvedSource converts the SDK's SQLFile slice to the internal
// migration.ResolvedSource the runner consumes. ContentHash is
// computed from deterministic (name, body) iteration.
func toResolvedSource(files []SQLFile) *migration.ResolvedSource {
	fileMap := make(map[string]string, len(files))
	names := make([]string, 0, len(files))
	for _, f := range files {
		fileMap[f.Name] = f.Body
		names = append(names, f.Name)
	}
	return &migration.ResolvedSource{
		Files:       fileMap,
		Names:       names,
		ContentHash: migration.HashFiles(fileMap, names),
	}
}

// driftSnapshotFromSDK is the inverse of Inspect's translator — takes
// the SDK's typed Snapshot and rebuilds the internal drift.Snapshot
// for the differ. Enables Diff(sdk.Inspect(...), desired) without
// exposing internal types in the SDK's public surface.
func driftSnapshotFromSDK(s *Snapshot) *drift.Snapshot {
	out := &drift.Snapshot{Schema: s.Schema}
	for _, t := range s.Tables {
		dt := drift.TableShape{Name: t.Name, Kind: t.Kind}
		for _, c := range t.Columns {
			dt.Columns = append(dt.Columns, drift.ColumnShape{
				Name: c.Name, Ordinal: c.Ordinal,
				DataType: c.DataType, UDTName: c.UDTName,
				Nullable: c.Nullable, Default: c.Default,
			})
		}
		out.Tables = append(out.Tables, dt)
	}
	for _, ix := range s.Indexes {
		out.Indexes = append(out.Indexes, drift.ObjectDDL{
			Name: ix.Name, Table: ix.Table, Type: ix.Type, Definition: ix.Definition,
		})
	}
	for _, c := range s.Constraints {
		out.Constraints = append(out.Constraints, drift.ObjectDDL{
			Name: c.Name, Table: c.Table, Type: c.Type, Definition: c.Definition,
		})
	}
	return out
}
