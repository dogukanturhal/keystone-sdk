// SPDX-License-Identifier: AGPL-3.0-or-later

package analyze

import (
	"context"
	"testing"

	keystonev1alpha1 "github.com/dogukanturhal/keystone/api/v1alpha1"
)

func TestDefaultRegistry_CoreRules(t *testing.T) {
	cases := []struct {
		name     string
		sql      string
		wantRule string
	}{
		{"drop table", "DROP TABLE users;", "no-drop-table"},
		{"drop column", "ALTER TABLE users DROP COLUMN email;", "no-drop-column"},
		{"alter column type", "ALTER TABLE users ALTER COLUMN age TYPE bigint;", "no-alter-column-type-in-place"},
		{"truncate", "TRUNCATE users;", "no-truncate"},
		{"grant all", "GRANT ALL ON users TO api;", "no-grant-all"},
		{"add not null no default", "ALTER TABLE users ADD COLUMN phone varchar NOT NULL;", "no-add-required-field-without-default"},
		{"non-concurrent index", "CREATE INDEX idx_users_email ON users (email);", "prefer-concurrent-index-creation"},
		{"concurrent in tx",
			"BEGIN;\nCREATE INDEX CONCURRENTLY idx_foo ON bar (x);\nCOMMIT;",
			"no-transaction-around-concurrent-index"},
	}
	reg := DefaultRegistry()
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			findings, err := reg.Run(context.Background(), &Migration{
				BundleName:   "test",
				Version:      "v1",
				TargetSchema: "public",
				Files:        []FileBody{{Name: "test.up.sql", Body: tc.sql}},
			})
			if err != nil {
				t.Fatalf("registry.Run err: %v", err)
			}
			found := false
			for _, f := range findings {
				if f.Rule == tc.wantRule {
					found = true
					break
				}
			}
			if !found {
				var seen []string
				for _, f := range findings {
					seen = append(seen, f.Rule)
				}
				t.Errorf("expected rule %q in findings; got %v", tc.wantRule, seen)
			}
		})
	}
}

// TestConcurrentIndexAcceptable confirms CREATE INDEX CONCURRENTLY
// outside a transaction is NOT flagged by
// prefer-concurrent-index-creation (the rule we're avoiding
// false-positive on).
func TestConcurrentIndexAcceptable(t *testing.T) {
	reg := DefaultRegistry()
	findings, _ := reg.Run(context.Background(), &Migration{
		Files: []FileBody{{Name: "ok.up.sql", Body: "CREATE INDEX CONCURRENTLY idx_foo ON bar (x);"}},
	})
	for _, f := range findings {
		if f.Rule == "prefer-concurrent-index-creation" {
			t.Errorf("false positive: %v", f)
		}
	}
}

// TestNoFalsePositiveOnDoBlockBegin guards the regex precision fix for
// the no-transaction-around-concurrent-index rule. Differ-emitted bundles
// regularly include `DO $$ BEGIN IF NOT EXISTS (...) THEN ... END IF; END
// $$;` blocks for idempotent FK creation. The PL/pgSQL `BEGIN` inside the
// DO block is a block opener, not transaction control — and Postgres
// happily runs CONCURRENTLY alongside such a block inside the runner's
// per-file tx. Pre-fix, the rule was firing false-positive on every
// such bundle and blocking apply.
func TestNoFalsePositiveOnDoBlockBegin(t *testing.T) {
	reg := DefaultRegistry()
	sql := `
DO $$ BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'fk_x'
    ) THEN
        ALTER TABLE "public"."t" ADD CONSTRAINT "fk_x" FOREIGN KEY ("a") REFERENCES "public"."u" ("b");
    END IF;
END $$;

CREATE INDEX CONCURRENTLY idx_foo ON bar (x);
`
	findings, err := reg.Run(context.Background(), &Migration{
		Files: []FileBody{{Name: "do-plus-concurrent.up.sql", Body: sql}},
	})
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	for _, f := range findings {
		if f.Rule == "no-transaction-around-concurrent-index" {
			t.Errorf("false positive on DO-block + CONCURRENTLY combo: %+v", f)
		}
	}
}

func TestCleanMigration(t *testing.T) {
	reg := DefaultRegistry()
	sql := `
-- Phase 11 test: a clean, safe migration
SET LOCAL statement_timeout = '30s';
CREATE TABLE leads (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX CONCURRENTLY idx_leads_email ON leads (email);
GRANT SELECT, INSERT ON leads TO api_role;
`
	findings, err := reg.Run(context.Background(), &Migration{
		Files: []FileBody{{Name: "clean.up.sql", Body: sql}},
	})
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	// Expect ZERO error-severity findings.
	for _, f := range findings {
		if f.Severity == keystonev1alpha1.LintLevelError {
			t.Errorf("clean migration produced error finding: %+v", f)
		}
	}
}
