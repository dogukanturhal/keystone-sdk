// SPDX-License-Identifier: AGPL-3.0-or-later

package drift

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	pg "github.com/dogukanturhal/keystone-sdk/go/sqlquote"
)

// snapshotTableDDL extends keystone_baselines (which only stores hashes)
// with a JSONB column for the canonical snapshot. The DriftController
// writes the snapshot when it accepts a baseline and reads it when
// drift is detected to compute structured findings.
//
// Co-located with the existing baseline table to avoid adding another
// per-schema bookkeeping table.
const snapshotTableDDL = `
ALTER TABLE %s.keystone_baselines
	ADD COLUMN IF NOT EXISTS snapshot JSONB;
`

// EnsureSnapshotColumn is a one-shot idempotent migration that adds the
// snapshot JSONB column to keystone_baselines. Called every reconcile
// — the IF NOT EXISTS makes it cheap.
func EnsureSnapshotColumn(ctx context.Context, pool *pgxpool.Pool, schema string) error {
	if err := pg.ValidateIdentifier("schema", schema); err != nil {
		return err
	}
	stmt := fmt.Sprintf(snapshotTableDDL, pg.QuoteIdentifier(schema))
	if _, err := pool.Exec(ctx, stmt); err != nil {
		return fmt.Errorf("alter keystone_baselines add snapshot: %w", err)
	}
	return nil
}

// ReadSnapshot returns the prior snapshot JSON, or nil if none recorded.
func ReadSnapshot(ctx context.Context, pool *pgxpool.Pool, schema string) (*Snapshot, error) {
	if err := pg.ValidateIdentifier("schema", schema); err != nil {
		return nil, err
	}
	q := fmt.Sprintf(
		`SELECT snapshot FROM %s.keystone_baselines WHERE kind = 'structure'`,
		pg.QuoteIdentifier(schema),
	)
	var raw []byte
	err := pool.QueryRow(ctx, q).Scan(&raw)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read snapshot: %w", err)
	}
	if len(raw) == 0 {
		return nil, nil
	}
	var snap Snapshot
	if err := json.Unmarshal(raw, &snap); err != nil {
		return nil, fmt.Errorf("unmarshal snapshot: %w", err)
	}
	return &snap, nil
}

// WriteSnapshot stores the canonical JSON alongside the existing
// hash row. Called from DriftController after WriteBaseline so the
// hash and snapshot stay in sync.
func WriteSnapshot(ctx context.Context, pool *pgxpool.Pool, schema string, snap *Snapshot) error {
	if err := pg.ValidateIdentifier("schema", schema); err != nil {
		return err
	}
	enc, err := json.Marshal(snap)
	if err != nil {
		return fmt.Errorf("marshal snapshot: %w", err)
	}
	stmt := fmt.Sprintf(
		`UPDATE %s.keystone_baselines SET snapshot = $1 WHERE kind = 'structure'`,
		pg.QuoteIdentifier(schema),
	)
	if _, err := pool.Exec(ctx, stmt, enc); err != nil {
		return fmt.Errorf("write snapshot: %w", err)
	}
	return nil
}
