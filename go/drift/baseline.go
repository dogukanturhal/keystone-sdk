// SPDX-License-Identifier: AGPL-3.0-or-later

package drift

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	pg "github.com/dogukanturhal/keystone-sdk/go/sqlquote"
)

// baselineTableDDL creates the keystone_baselines table inside a target
// schema. One row per (schema, kind) — kind is always "structure" today;
// reserved for future kinds like "rls" or "permissions".
const baselineTableDDL = `
CREATE TABLE IF NOT EXISTS %s.keystone_baselines (
	kind          TEXT PRIMARY KEY,
	hash          TEXT NOT NULL,
	source        TEXT NOT NULL,  -- e.g. "migration:bundle/v42" or "drift-acceptance"
	recorded_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
	recorded_by   TEXT NOT NULL DEFAULT current_user
);
COMMENT ON TABLE %s.keystone_baselines IS
	'Maintained by Keystone DriftController (keystone.hexxlock.io). Do not edit manually.';
`

// Baseline is one recorded baseline row.
type Baseline struct {
	Kind       string
	Hash       string
	Source     string
	RecordedAt time.Time
}

// BaselineKind identifies what aspect of the schema the baseline tracks.
// Today only "structure"; "rls" and "permissions" reserved for future.
type BaselineKind string

const (
	BaselineKindStructure BaselineKind = "structure"
)

// SnapshotKind is the second row in keystone_baselines: the canonical
// snapshot serialised as JSON, used by the DriftController to compute
// per-object findings (Phase 5.1). The structure-hash row remains the
// fast-path; the snapshot row is read only when drift is detected and
// findings need to be populated.
const SnapshotKind BaselineKind = "snapshot-json"

// EnsureBaselineTable is idempotent.
func EnsureBaselineTable(ctx context.Context, pool *pgxpool.Pool, schema string) error {
	if err := pg.ValidateIdentifier("schema", schema); err != nil {
		return err
	}
	stmt := fmt.Sprintf(baselineTableDDL,
		pg.QuoteIdentifier(schema),
		pg.QuoteIdentifier(schema),
	)
	if _, err := pool.Exec(ctx, stmt); err != nil {
		return fmt.Errorf("create keystone_baselines: %w", err)
	}
	return nil
}

// ReadBaseline returns the recorded baseline for the given kind, or nil
// if none exists.
func ReadBaseline(ctx context.Context, pool *pgxpool.Pool, schema string, kind BaselineKind) (*Baseline, error) {
	if err := pg.ValidateIdentifier("schema", schema); err != nil {
		return nil, err
	}
	q := fmt.Sprintf(
		`SELECT kind, hash, source, recorded_at
		   FROM %s.keystone_baselines
		  WHERE kind = $1`,
		pg.QuoteIdentifier(schema),
	)
	var b Baseline
	err := pool.QueryRow(ctx, q, string(kind)).Scan(&b.Kind, &b.Hash, &b.Source, &b.RecordedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read baseline: %w", err)
	}
	return &b, nil
}

// WriteBaseline upserts the baseline. Source documents *why* the
// baseline was set (which migration applied, or operator acceptance).
func WriteBaseline(ctx context.Context, pool *pgxpool.Pool, schema string, kind BaselineKind, hash, source string) error {
	if err := pg.ValidateIdentifier("schema", schema); err != nil {
		return err
	}
	stmt := fmt.Sprintf(
		`INSERT INTO %s.keystone_baselines (kind, hash, source)
		 VALUES ($1, $2, $3)
		 ON CONFLICT (kind) DO UPDATE
		    SET hash = EXCLUDED.hash,
		        source = EXCLUDED.source,
		        recorded_at = NOW(),
		        recorded_by = current_user`,
		pg.QuoteIdentifier(schema),
	)
	if _, err := pool.Exec(ctx, stmt, string(kind), hash, source); err != nil {
		return fmt.Errorf("write baseline: %w", err)
	}
	return nil
}
