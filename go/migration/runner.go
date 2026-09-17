// SPDX-License-Identifier: AGPL-3.0-or-later

package migration

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	pg "github.com/dogukanturhal/keystone-sdk/go/sqlquote"
)

// reConcurrently matches the CONCURRENTLY keyword used by CREATE/DROP INDEX
// CONCURRENTLY and REINDEX … CONCURRENTLY. PostgreSQL refuses these inside
// a transaction block (SQLSTATE 25001). When any source file contains the
// keyword, Apply switches to autocommit mode for that bundle.
var reConcurrently = regexp.MustCompile(`(?i)\bCONCURRENTLY\b`)

// migrationsTableDDLTemplate creates the tracking table inside the target
// schema. Format is compatible with golang-migrate's standard layout:
// (version TEXT PRIMARY KEY, dirty BOOLEAN, applied_at TIMESTAMPTZ).
// Plus a content_hash column so we can detect bundles that try to swap
// SQL behind an already-applied version (defence in depth — admission
// catches this first; this is the runtime backstop).
//
// Two %s placeholders: schema and tracking-table name. Both are
// identifier-validated + quoted by the caller.
const migrationsTableDDLTemplate = `
CREATE TABLE IF NOT EXISTS %s.%s (
	version       TEXT PRIMARY KEY,
	content_hash  TEXT NOT NULL,
	applied_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
	applied_by    TEXT NOT NULL DEFAULT current_user,
	duration_ms   BIGINT NOT NULL,
	dirty         BOOLEAN NOT NULL DEFAULT FALSE
);

COMMENT ON TABLE %s.%s IS
	'Maintained by Keystone (keystone.hexxlock.io). Do not edit manually.';
`

// DefaultTrackingTable is the golang-migrate-compatible default.
const DefaultTrackingTable = "schema_migrations"

// AppliedMigration describes one row in schema_migrations.
type AppliedMigration struct {
	Version     string
	ContentHash string
	AppliedAt   time.Time
	DurationMS  int64
	Dirty       bool
}

// FileResult is returned per file applied. Used by the controller to
// populate MigrationExecution.status.applied.
type FileResult struct {
	File         string
	Index        int32
	DurationMS   int64
	RowsAffected int64
}

// Runner applies SQL files inside a transaction against a target schema.
type Runner struct {
	pool          *pgxpool.Pool
	schema        string
	trackingTable string
	// ownerRole, when non-empty, is the PostgreSQL role the Runner will
	// SET LOCAL ROLE to inside the migration transaction before executing
	// migration SQL. This makes every CREATE TABLE/SEQUENCE/etc. in the
	// migration attribute ownership to <ownerRole> rather than to the
	// connection's authenticated user (typically `keystone_admin`).
	//
	// Why this matters: the canonical owner/_app role-split pattern (see
	// the GitOps repository cluster-*.yaml managed.roles) relies on `_app`
	// holding `inRoles: [_owner]` with `inherit: true`. That inheritance
	// gives `_app` automatic privileges on objects OWNED by `_owner` —
	// but only if `_owner` is actually the owner. Without SET LOCAL ROLE,
	// migration SQL creates tables owned by the migration user, leaving
	// `_app` permission-denied at runtime ("ERROR: permission denied for
	// table X (SQLSTATE 42501)").
	//
	// Empty ownerRole preserves backwards-compatible behaviour: no SET
	// LOCAL ROLE issued, tables inherit the connection's role. This is
	// the right behavior for non-tenant-scoped databases (e.g. the
	// keystone bookkeeping schema itself).
	//
	// The connection's role MUST be a member of ownerRole (PostgreSQL
	// SET ROLE requirement); the platform pattern bakes this in via
	// `keystone_admin.inRoles: [example_<svc>_owner, …]` on each
	// managed Cluster.
	ownerRole string
}

// NewRunner binds the runner to a pool already connected to the target
// database. The schema MUST exist (the SchemaController guarantees that).
// trackingTable defaults to DefaultTrackingTable when empty. ownerRole,
// when non-empty, is set via SET LOCAL ROLE inside each migration
// transaction — see Runner.ownerRole godoc above for the full rationale.
func NewRunner(pool *pgxpool.Pool, schema, trackingTable, ownerRole string) (*Runner, error) {
	if err := pg.ValidateIdentifier("schema", schema); err != nil {
		return nil, err
	}
	if trackingTable == "" {
		trackingTable = DefaultTrackingTable
	}
	if err := pg.ValidateIdentifier("trackingTable", trackingTable); err != nil {
		return nil, err
	}
	if ownerRole != "" {
		if err := pg.ValidateIdentifier("ownerRole", ownerRole); err != nil {
			return nil, err
		}
	}
	return &Runner{
		pool:          pool,
		schema:        schema,
		trackingTable: trackingTable,
		ownerRole:     ownerRole,
	}, nil
}

// EnsureBookkeeping creates the tracking table if missing. Idempotent.
func (r *Runner) EnsureBookkeeping(ctx context.Context) error {
	stmt := fmt.Sprintf(migrationsTableDDLTemplate,
		pg.QuoteIdentifier(r.schema),
		pg.QuoteIdentifier(r.trackingTable),
		pg.QuoteIdentifier(r.schema),
		pg.QuoteIdentifier(r.trackingTable),
	)
	if _, err := r.pool.Exec(ctx, stmt); err != nil {
		return fmt.Errorf("create tracking table %s.%s: %w",
			r.schema, r.trackingTable, err)
	}
	return nil
}

// IsApplied reports whether the version is recorded in schema_migrations.
// Returns the recorded ContentHash so the caller can compare against the
// current source's hash and detect tampering.
func (r *Runner) IsApplied(ctx context.Context, version string) (bool, *AppliedMigration, error) {
	q := fmt.Sprintf(
		`SELECT version, content_hash, applied_at, duration_ms, dirty
		   FROM %s.%s
		  WHERE version = $1`,
		pg.QuoteIdentifier(r.schema),
		pg.QuoteIdentifier(r.trackingTable),
	)
	var m AppliedMigration
	err := r.pool.QueryRow(ctx, q, version).Scan(
		&m.Version, &m.ContentHash, &m.AppliedAt, &m.DurationMS, &m.Dirty,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil, nil
	}
	if err != nil {
		return false, nil, fmt.Errorf("read schema_migrations: %w", err)
	}
	return true, &m, nil
}

// ListApplied returns every row from the tracking table, ordered by
// applied_at. Empty on a freshly-created tracking table. Used by the
// SchemaSnapshotReconciler to freeze the migration history.
func (r *Runner) ListApplied(ctx context.Context) ([]AppliedMigration, error) {
	q := fmt.Sprintf(
		`SELECT version, content_hash, applied_at, duration_ms, dirty
		   FROM %s.%s
		  ORDER BY applied_at ASC, version ASC`,
		pg.QuoteIdentifier(r.schema),
		pg.QuoteIdentifier(r.trackingTable),
	)
	rows, err := r.pool.Query(ctx, q)
	if err != nil {
		return nil, fmt.Errorf("query schema_migrations: %w", err)
	}
	defer rows.Close()

	var out []AppliedMigration
	for rows.Next() {
		var m AppliedMigration
		if err := rows.Scan(&m.Version, &m.ContentHash, &m.AppliedAt, &m.DurationMS, &m.Dirty); err != nil {
			return nil, fmt.Errorf("scan schema_migrations: %w", err)
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

// Record upserts the (version, contentHash) row into the tracking table
// WITHOUT executing any migration SQL. This is the adoption-baseline
// primitive (ADR 0008 in the keystone repo): the schema's current state
// is declared as already-applied so subsequent incremental migrations
// build on top of it. Identical semantics to `flyway baseline`,
// Liquibase `changelog-sync`, and `atlas migrate apply --baseline` —
// the tier-1 vendor consensus for adopting a migrator on a database
// that already exists.
//
// duration_ms is recorded as 0: no SQL ran. applied_by defaults to
// current_user via the tracking-table DDL, so the audit row still
// names the recording identity. No SET LOCAL ROLE is needed — the
// tracking table is owned by the connection user (see the Apply
// docstring), and Record never touches user objects.
//
// Callers remain responsible for EnsureBookkeeping, mirroring the
// Apply contract. The upsert keeps a retry after a recorded-but-
// status-not-patched crash idempotent.
func (r *Runner) Record(ctx context.Context, version, contentHash string) error {
	insertSQL := fmt.Sprintf(
		`INSERT INTO %s.%s (version, content_hash, duration_ms)
		 VALUES ($1, $2, 0)
		 ON CONFLICT (version) DO UPDATE SET
		    content_hash = EXCLUDED.content_hash,
		    duration_ms  = EXCLUDED.duration_ms,
		    applied_at   = NOW()`,
		pg.QuoteIdentifier(r.schema),
		pg.QuoteIdentifier(r.trackingTable),
	)
	if _, err := r.pool.Exec(ctx, insertSQL, version, contentHash); err != nil {
		return fmt.Errorf("record version %q: %w", version, err)
	}
	return nil
}

// ApplyResult is the aggregate outcome of an Apply call.
type ApplyResult struct {
	Files           []FileResult
	TotalDurationMS int64
	FailedFile      string // empty on success
	FailedIndex     int32
	FailureMsg      string
}

// Apply runs every (file, statement) inside one transaction. If any
// statement fails, the transaction rolls back and FailedFile/FailedIndex
// pinpoint the error. On success, the version is recorded in
// schema_migrations and the transaction commits.
//
// SQL statements within a file are executed via pgx's simple protocol
// (one Exec per file passes the entire content through libpq's simple
// query protocol, which permits multiple statements). The trade-off: no
// parameter binding inside the migration — which is correct, migrations
// are static SQL.
//
// CONCURRENTLY exception: PostgreSQL refuses CREATE/DROP INDEX
// CONCURRENTLY and REINDEX … CONCURRENTLY inside a transaction block. If
// any source file contains the keyword, Apply switches to a no-tx path
// that pins one connection from the pool and runs each file in autocommit
// mode. The schema_migrations row is upserted on the same connection
// after; UPSERT semantics make a partial-failure retry idempotent.
func (r *Runner) Apply(
	ctx context.Context,
	version, contentHash string,
	source *ResolvedSource,
) (*ApplyResult, error) {
	res := &ApplyResult{}
	start := time.Now()

	if needsNoTx(source) {
		return r.applyNoTx(ctx, version, contentHash, source, res, start)
	}

	tx, err := r.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	// Defer rollback as the safety net; the success path explicitly Commits
	// so this rollback is a no-op there.
	defer func() { _ = tx.Rollback(ctx) }()

	// Set search_path so unqualified objects in the migration land in
	// the right schema. The pool's default search_path doesn't apply
	// here because pgx connects to the database, not the schema.
	//
	// public is appended, not substituted: the target schema stays first, so
	// every object the migration creates still lands there. Without public on
	// the path, types provided by an extension are invisible — extensions are
	// installed per-database into their own schema, so a migration declaring a
	// postgis geography or a citext column fails with
	// 42704 type "geography" does not exist even though the extension is
	// installed. That bites hardest when normalising a desired schema into a
	// scratch schema, where nothing else is on the path at all.
	if _, err := tx.Exec(ctx,
		fmt.Sprintf(`SET LOCAL search_path TO %s, public`, pg.QuoteIdentifier(r.schema)),
	); err != nil {
		return nil, fmt.Errorf("set search_path: %w", err)
	}

	// SET LOCAL ROLE to the schema owner so CREATE TABLE etc. attribute
	// ownership to <ownerRole> rather than the connection user
	// (`keystone_admin`). Skipped when ownerRole is empty (legacy
	// callers, keystone's own bookkeeping schema). See Runner.ownerRole
	// godoc for the full rationale + caller contract.
	if r.ownerRole != "" {
		if _, err := tx.Exec(ctx,
			fmt.Sprintf(`SET LOCAL ROLE %s`, pg.QuoteIdentifier(r.ownerRole)),
		); err != nil {
			return nil, fmt.Errorf("set role to %q: %w", r.ownerRole, err)
		}
	}

	for idx, name := range source.Names {
		fileStart := time.Now()
		tag, err := tx.Exec(ctx, source.Files[name],
			pgx.QueryExecModeSimpleProtocol)
		if err != nil {
			res.FailedFile = name
			res.FailedIndex = int32(idx + 1)
			res.FailureMsg = err.Error()
			return res, fmt.Errorf("apply %s: %w", name, err)
		}
		res.Files = append(res.Files, FileResult{
			File:         name,
			Index:        int32(idx + 1),
			DurationMS:   time.Since(fileStart).Milliseconds(),
			RowsAffected: tag.RowsAffected(),
		})
	}

	// Record the version. Upsert with ON CONFLICT so a retry after a
	// committed-but-status-not-patched scenario doesn't double-insert.
	//
	// The tracking table (`keystone_schema_migrations`) is owned by the
	// connection user (`keystone_admin`) — NOT by `<ownerRole>`. The
	// SET LOCAL ROLE earlier in this tx scopes the role to <ownerRole>
	// so CREATE TABLE attributes ownership correctly, but that role
	// doesn't (and shouldn't) have INSERT privilege on the tracking
	// table itself. Reset role to the connection user before the
	// upsert so PG resolves the privilege against `keystone_admin`.
	//
	// `SET LOCAL ROLE NONE` reverts to the session_user (= the role
	// that authenticated the connection); SET LOCAL means it's
	// automatically scoped to this transaction and any subsequent
	// statements in the same tx will run as the connection user. No
	// risk of leaking back into the pool because SET LOCAL clears at
	// COMMIT/ROLLBACK regardless.
	if r.ownerRole != "" {
		if _, err := tx.Exec(ctx, `SET LOCAL ROLE NONE`); err != nil {
			return res, fmt.Errorf("reset role before tracking insert: %w", err)
		}
	}
	insertSQL := fmt.Sprintf(
		`INSERT INTO %s.%s (version, content_hash, duration_ms)
		 VALUES ($1, $2, $3)
		 ON CONFLICT (version) DO UPDATE SET
		    content_hash = EXCLUDED.content_hash,
		    duration_ms  = EXCLUDED.duration_ms,
		    applied_at   = NOW()`,
		pg.QuoteIdentifier(r.schema),
		pg.QuoteIdentifier(r.trackingTable),
	)
	totalMS := time.Since(start).Milliseconds()
	if _, err := tx.Exec(ctx, insertSQL, version, contentHash, totalMS); err != nil {
		return res, fmt.Errorf("record version %q: %w", version, err)
	}

	if err := tx.Commit(ctx); err != nil {
		return res, fmt.Errorf("commit: %w", err)
	}
	res.TotalDurationMS = totalMS
	return res, nil
}

// needsNoTx reports whether the source contains any CONCURRENTLY
// statement. PG refuses CREATE/DROP INDEX CONCURRENTLY and REINDEX …
// CONCURRENTLY inside a transaction; when present anywhere in the bundle
// the runner switches to autocommit mode for the whole apply.
func needsNoTx(source *ResolvedSource) bool {
	for _, name := range source.Names {
		if reConcurrently.MatchString(source.Files[name]) {
			return true
		}
	}
	return false
}

// applyNoTx executes the bundle without wrapping it in a transaction, on
// a single pinned connection from the pool. Required for CONCURRENTLY
// statements; safe for everything else because each statement carries its
// own implicit tx via PG's autocommit. The schema_migrations row is
// upserted on the same connection after the bundle; UPSERT semantics make
// retry-after-partial-failure idempotent.
func (r *Runner) applyNoTx(
	ctx context.Context,
	version, contentHash string,
	source *ResolvedSource,
	res *ApplyResult,
	start time.Time,
) (*ApplyResult, error) {
	conn, err := r.pool.Acquire(ctx)
	if err != nil {
		return nil, fmt.Errorf("acquire conn: %w", err)
	}
	defer conn.Release()

	if _, err := conn.Exec(ctx,
		fmt.Sprintf(`SET search_path TO %s`, pg.QuoteIdentifier(r.schema)),
	); err != nil {
		return nil, fmt.Errorf("set search_path: %w", err)
	}
	defer func() {
		// Best-effort reset so the pooled connection doesn't leak the
		// migration's search_path back to other users.
		_, _ = conn.Exec(context.Background(), `RESET search_path`)
	}()

	// Pin the session role to the schema owner so CREATE TABLE
	// CONCURRENTLY etc. attribute ownership to <ownerRole>. Use SET ROLE
	// (session-scoped, NOT SET LOCAL — no enclosing tx here). Earlier
	// versions of this function used SET SESSION AUTHORIZATION, but
	// PG requires superuser for that statement; keystone_admin only
	// has createdb + createrole (intentionally — bounded blast radius
	// in line with the role's threat model). SET ROLE works for any
	// role the connection user is a member of, which keystone_admin is
	// for every `<svc>_owner` via the managed.roles inRoles wiring in
	// cluster-example-app-pg.yaml. Reset on defer so the pool
	// connection doesn't leak the impersonation back to the next user.
	if r.ownerRole != "" {
		if _, err := conn.Exec(ctx,
			fmt.Sprintf(`SET ROLE %s`, pg.QuoteIdentifier(r.ownerRole)),
		); err != nil {
			return nil, fmt.Errorf("set role to %q: %w", r.ownerRole, err)
		}
		defer func() {
			_, _ = conn.Exec(context.Background(), `RESET ROLE`)
		}()
	}

	for idx, name := range source.Names {
		fileStart := time.Now()
		// PG's simple-query protocol wraps multi-statement Exec calls in
		// an implicit transaction. CONCURRENTLY refuses to run inside any
		// transaction, implicit or explicit, so each statement must be
		// dispatched in its own round-trip.
		stmts := splitSQLStatements(source.Files[name])
		var rowsAffected int64
		for _, stmt := range stmts {
			tag, err := conn.Exec(ctx, stmt, pgx.QueryExecModeSimpleProtocol)
			if err != nil {
				res.FailedFile = name
				res.FailedIndex = int32(idx + 1)
				res.FailureMsg = err.Error()
				return res, fmt.Errorf("apply %s: %w", name, err)
			}
			rowsAffected += tag.RowsAffected()
		}
		res.Files = append(res.Files, FileResult{
			File:         name,
			Index:        int32(idx + 1),
			DurationMS:   time.Since(fileStart).Milliseconds(),
			RowsAffected: rowsAffected,
		})
	}

	// Reset the session role to the connection user before the
	// tracking-table upsert. The SET ROLE earlier in this function
	// impersonates <ownerRole> so CONCURRENTLY-flavoured CREATE TABLE
	// etc. attribute ownership correctly, but the
	// `keystone_schema_migrations` table is owned by `keystone_admin`
	// (the connection user) — and the impersonated role does not (and
	// shouldn't) have INSERT privilege on it. Mirrors the tx-mode fix
	// in Apply() above.
	if r.ownerRole != "" {
		if _, err := conn.Exec(ctx, `RESET ROLE`); err != nil {
			return res, fmt.Errorf("reset role before tracking insert: %w", err)
		}
	}
	insertSQL := fmt.Sprintf(
		`INSERT INTO %s.%s (version, content_hash, duration_ms)
		 VALUES ($1, $2, $3)
		 ON CONFLICT (version) DO UPDATE SET
		    content_hash = EXCLUDED.content_hash,
		    duration_ms  = EXCLUDED.duration_ms,
		    applied_at   = NOW()`,
		pg.QuoteIdentifier(r.schema),
		pg.QuoteIdentifier(r.trackingTable),
	)
	totalMS := time.Since(start).Milliseconds()
	if _, err := conn.Exec(ctx, insertSQL, version, contentHash, totalMS); err != nil {
		return res, fmt.Errorf("record version %q: %w", version, err)
	}
	res.TotalDurationMS = totalMS
	return res, nil
}
