// SPDX-License-Identifier: AGPL-3.0-or-later

package analyze

import (
	"context"
	"testing"

	keystonev1alpha1 "github.com/dogukanturhal/keystone/api/v1alpha1"
)

func TestRequireDownMigration_WarnsWhenAbsent(t *testing.T) {
	a := &RequireDownMigration{}
	m := &Migration{
		BundleName: "billing-v1",
		Version:    "001",
		Strategy:   string(keystonev1alpha1.StrategyVersioned),
		Files: []FileBody{
			{Name: "001.up.sql", Body: "CREATE TABLE invoices (id uuid PRIMARY KEY)"},
		},
		HasDownSource: false,
	}
	findings, err := a.Check(context.Background(), m)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Severity != keystonev1alpha1.LintLevelWarning {
		t.Errorf("expected warning, got %q", findings[0].Severity)
	}
	if findings[0].Rule != "require-down-migration" {
		t.Errorf("expected rule require-down-migration, got %q", findings[0].Rule)
	}
}

func TestRequireDownMigration_SilentWhenPresent(t *testing.T) {
	a := &RequireDownMigration{}
	m := &Migration{
		BundleName: "billing-v1",
		Version:    "001",
		Strategy:   string(keystonev1alpha1.StrategyVersioned),
		Files: []FileBody{
			{Name: "001.up.sql", Body: "CREATE TABLE invoices (id uuid PRIMARY KEY)"},
		},
		HasDownSource: true,
	}
	findings, err := a.Check(context.Background(), m)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings when down source is present, got %d", len(findings))
	}
}

func TestRequireDownMigration_SkipsPgroll(t *testing.T) {
	a := &RequireDownMigration{}
	m := &Migration{
		BundleName:    "billing-v1",
		Version:       "001",
		Strategy:      string(keystonev1alpha1.StrategyPgrollExpandContract),
		HasDownSource: false,
		// pgroll has built-in abort handlers, no down source needed.
	}
	findings, err := a.Check(context.Background(), m)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for pgroll strategy, got %d", len(findings))
	}
}

func TestRequireDownMigration_SkipsNoFiles(t *testing.T) {
	a := &RequireDownMigration{}
	m := &Migration{
		BundleName:    "billing-v1",
		Version:       "001",
		Strategy:      string(keystonev1alpha1.StrategyVersioned),
		HasDownSource: false,
		Files:         nil, // no files = operation-based
	}
	findings, err := a.Check(context.Background(), m)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for no-file bundle, got %d", len(findings))
	}
}

func TestRequireDownMigration_DefaultStrategyTreatedAsVersioned(t *testing.T) {
	a := &RequireDownMigration{}
	m := &Migration{
		BundleName: "billing-v1",
		Version:    "001",
		Strategy:   "", // empty = default = versioned
		Files: []FileBody{
			{Name: "001.up.sql", Body: "ALTER TABLE users ADD COLUMN email text"},
		},
		HasDownSource: false,
	}
	findings, err := a.Check(context.Background(), m)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 {
		t.Errorf("expected 1 warning for empty strategy (=versioned), got %d", len(findings))
	}
}
