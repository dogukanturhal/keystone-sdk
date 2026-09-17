// SPDX-License-Identifier: AGPL-3.0-or-later

package analyze

import (
	"context"
	"strings"
	"testing"
)

// TestA2Rules_Fire is the table of expected-firing cases. Each entry
// contains SQL designed to trigger exactly one rule; the assertion is
// that the rule's ID appears in the finding set. "Clean" counterparts
// live in TestA2Rules_Clean — mix of the patterns each rule should
// ignore, to catch accidental over-firing.
func TestA2Rules_Fire(t *testing.T) {
	cases := []struct {
		name     string
		sql      string
		wantRule string
	}{
		// -- Lock-heavy --
		{"fk without not valid",
			"ALTER TABLE orders ADD CONSTRAINT fk_customer FOREIGN KEY (customer_id) REFERENCES customers(id);",
			"no-add-fk-without-not-valid"},
		{"check without not valid",
			"ALTER TABLE orders ADD CONSTRAINT pos_total CHECK (total > 0);",
			"no-add-check-without-not-valid"},
		{"direct unique constraint",
			"ALTER TABLE users ADD CONSTRAINT uq_email UNIQUE (email);",
			"no-unique-constraint-direct"},
		{"set not null direct",
			"ALTER TABLE users ALTER COLUMN email SET NOT NULL;",
			"no-set-not-null-direct"},
		{"vacuum full",
			"VACUUM FULL users;",
			"no-vacuum-full"},
		{"cluster",
			"CLUSTER users USING idx_users_email;",
			"no-cluster"},
		{"reindex without concurrently",
			"REINDEX TABLE users;",
			"no-reindex-without-concurrently"},
		{"drop index without concurrently",
			"DROP INDEX idx_users_email;",
			"no-drop-index-without-concurrently"},
		{"lock table",
			"LOCK TABLE users IN ACCESS EXCLUSIVE MODE;",
			"no-lock-table-explicit"},

		// -- Backward compatibility --
		{"rename column",
			"ALTER TABLE users RENAME COLUMN email TO email_address;",
			"no-rename-column"},
		{"rename constraint",
			"ALTER TABLE users RENAME CONSTRAINT old_name TO new_name;",
			"no-rename-constraint"},
		{"drop view",
			"DROP VIEW user_summary;",
			"no-drop-view"},
		{"drop function",
			"DROP FUNCTION normalize_email(text);",
			"no-drop-function"},
		{"drop sequence",
			"DROP SEQUENCE users_id_seq;",
			"no-drop-sequence"},

		// -- DML safety --
		{"update no where",
			"UPDATE users SET active = true;",
			"no-update-without-where"},
		{"delete no where",
			"DELETE FROM users;",
			"no-delete-without-where"},
		{"insert select no where",
			"INSERT INTO users_archive SELECT id, email FROM users;",
			"no-insert-select-without-where"},
		{"disable trigger all",
			"ALTER TABLE users DISABLE TRIGGER ALL;",
			"no-disable-triggers-all"},

		// -- Transaction / session --
		{"commit inline",
			"INSERT INTO t VALUES (1);\nCOMMIT;\nINSERT INTO t VALUES (2);",
			"no-commit-in-migration"},
		{"rollback inline",
			"INSERT INTO t VALUES (1);\nROLLBACK;",
			"no-rollback-in-migration"},
		{"set session_replication_role",
			"SET session_replication_role = replica;",
			"no-set-session-replication-role"},
		{"set constraints all deferred",
			"SET CONSTRAINTS ALL DEFERRED;",
			"no-set-constraints-deferred"},

		// -- Type conventions --
		{"varchar unbounded",
			"CREATE TABLE t (id int, name VARCHAR);",
			"no-varchar-without-limit"},
		{"json not jsonb",
			"CREATE TABLE t (id int, payload JSON);",
			"prefer-jsonb-over-json"},
		{"numeric unbounded",
			"CREATE TABLE t (id int, amount NUMERIC);",
			"no-numeric-without-precision"},
		{"create table no if not exists",
			"CREATE TABLE users (id int PRIMARY KEY);",
			"require-if-not-exists-on-create-table"},
		{"uuid v1",
			"CREATE TABLE t (id uuid DEFAULT uuid_generate_v1());",
			"no-uuid-generate-v1"},

		// -- Naming --
		{"long identifier",
			// 61-char table name trips 60-char default threshold.
			"CREATE TABLE " + strings.Repeat("x", 61) + " (id int);",
			"max-identifier-length"},
		{"pg_ prefix",
			"CREATE TABLE pg_my_audit (id int);",
			"no-pg-prefix-identifier"},
	}

	reg := DefaultRegistry()
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			findings, err := reg.Run(context.Background(), &Migration{
				BundleName:   "a2-test",
				Version:      "v1",
				TargetSchema: "app",
				Files:        []FileBody{{Name: "m.up.sql", Body: tc.sql}},
			})
			if err != nil {
				t.Fatalf("registry error: %v", err)
			}
			for _, f := range findings {
				if f.Rule == tc.wantRule {
					return
				}
			}
			var ruleIDs []string
			for _, f := range findings {
				ruleIDs = append(ruleIDs, f.Rule)
			}
			t.Fatalf("expected rule %q to fire; got %v", tc.wantRule, ruleIDs)
		})
	}
}

// TestA2Rules_Clean verifies rules do NOT fire on their canonical
// counterexample. Keeps over-firing regressions visible.
func TestA2Rules_Clean(t *testing.T) {
	cases := []struct {
		name           string
		sql            string
		mustNotFireOne string
	}{
		{"fk with not valid",
			"ALTER TABLE orders ADD CONSTRAINT fk FOREIGN KEY (customer_id) REFERENCES customers(id) NOT VALID;",
			"no-add-fk-without-not-valid"},
		{"check with not valid",
			"ALTER TABLE orders ADD CONSTRAINT c CHECK (total > 0) NOT VALID;",
			"no-add-check-without-not-valid"},
		{"unique via using index",
			"CREATE UNIQUE INDEX CONCURRENTLY uq_email ON users(email);\nALTER TABLE users ADD CONSTRAINT uq UNIQUE USING INDEX uq_email;",
			"no-unique-constraint-direct"},
		{"set not null after check not valid",
			"ALTER TABLE users ADD CONSTRAINT c CHECK (email IS NOT NULL) NOT VALID;\nALTER TABLE users VALIDATE CONSTRAINT c;\nALTER TABLE users ALTER COLUMN email SET NOT NULL;",
			"no-set-not-null-direct"},
		{"reindex concurrently",
			"REINDEX TABLE CONCURRENTLY users;",
			"no-reindex-without-concurrently"},
		{"drop index concurrently",
			"DROP INDEX CONCURRENTLY idx_users_email;",
			"no-drop-index-without-concurrently"},
		{"update with where",
			"UPDATE users SET active = true WHERE id = 42;",
			"no-update-without-where"},
		{"delete with where",
			"DELETE FROM users WHERE id = 42;",
			"no-delete-without-where"},
		{"insert select with where",
			"INSERT INTO users_archive SELECT id, email FROM users WHERE archived_at IS NOT NULL;",
			"no-insert-select-without-where"},
		{"varchar bounded",
			"CREATE TABLE IF NOT EXISTS t (id int PRIMARY KEY, name VARCHAR(255));",
			"no-varchar-without-limit"},
		{"jsonb",
			"CREATE TABLE IF NOT EXISTS t (id int PRIMARY KEY, payload JSONB);",
			"prefer-jsonb-over-json"},
		{"numeric bounded",
			"CREATE TABLE IF NOT EXISTS t (id int PRIMARY KEY, amount NUMERIC(12,2));",
			"no-numeric-without-precision"},
		{"create table if not exists",
			"CREATE TABLE IF NOT EXISTS users (id int PRIMARY KEY);",
			"require-if-not-exists-on-create-table"},
		{"gen_random_uuid",
			"CREATE TABLE IF NOT EXISTS t (id uuid DEFAULT gen_random_uuid() PRIMARY KEY);",
			"no-uuid-generate-v1"},
		{"short identifier",
			"CREATE TABLE IF NOT EXISTS users (id int PRIMARY KEY);",
			"max-identifier-length"},
		{"non-pg prefix",
			"CREATE TABLE IF NOT EXISTS app_audit (id int PRIMARY KEY);",
			"no-pg-prefix-identifier"},
	}

	reg := DefaultRegistry()
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			findings, err := reg.Run(context.Background(), &Migration{
				BundleName:   "a2-clean",
				Version:      "v1",
				TargetSchema: "app",
				Files:        []FileBody{{Name: "m.up.sql", Body: tc.sql}},
			})
			if err != nil {
				t.Fatalf("registry error: %v", err)
			}
			for _, f := range findings {
				if f.Rule == tc.mustNotFireOne {
					t.Fatalf("rule %q fired unexpectedly on clean SQL: %s", tc.mustNotFireOne, f.Message)
				}
			}
		})
	}
}

// TestDefaultRegistrySize locks the registered analyzer count. Adding
// or removing rules should be a deliberate change visible in MR diffs.
func TestDefaultRegistrySize(t *testing.T) {
	got := len(DefaultRegistry().analyzers)
	const want = 53
	if got != want {
		t.Fatalf("DefaultRegistry has %d analyzers; expected %d. "+
			"If you added or removed rules, update this test and the comment in analyzer.go.",
			got, want)
	}
}

// TestDefaultRegistryUniqueIDs catches copy-paste accidents where two
// rule types return the same ID(). Duplicate IDs make findings
// ambiguous and break disabledAnalyzers policy gating.
func TestDefaultRegistryUniqueIDs(t *testing.T) {
	seen := make(map[string]bool)
	for _, a := range DefaultRegistry().analyzers {
		id := a.ID()
		if id == "" {
			t.Errorf("analyzer %T has empty ID", a)
			continue
		}
		if seen[id] {
			t.Errorf("duplicate rule ID %q", id)
		}
		seen[id] = true
	}
}
