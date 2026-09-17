// SPDX-License-Identifier: AGPL-3.0-or-later

package analyze

import (
	"context"
	"strings"
	"testing"

	keystonev1alpha1 "github.com/dogukanturhal/keystone/api/v1alpha1"
)

// TestStatementVerb_BasicVerbs covers the happy path: each PG statement
// reports its leading keyword.
func TestStatementVerb_BasicVerbs(t *testing.T) {
	body := `SELECT 1;
UPDATE accounts SET active = true WHERE id = 1;
DELETE FROM sessions WHERE expires_at < now();
TRUNCATE TABLE logs;
GRANT SELECT ON TABLE t TO role;
ALTER TABLE t ADD COLUMN c int;`

	tests := []struct {
		needle string
		want   string
	}{
		{"SELECT 1", "SELECT"},
		{"UPDATE accounts", "UPDATE"},
		{"DELETE FROM sessions", "DELETE"},
		{"TRUNCATE TABLE", "TRUNCATE"},
		{"GRANT SELECT", "GRANT"},
		{"ALTER TABLE", "ALTER"},
	}
	for _, tc := range tests {
		idx := strings.Index(body, tc.needle)
		if idx < 0 {
			t.Fatalf("needle %q not in body", tc.needle)
		}
		got := statementVerb(body, idx)
		if got != tc.want {
			t.Errorf("statementVerb at %q: got %q, want %q", tc.needle, got, tc.want)
		}
	}
}

// TestStatementVerb_GrantWithKeywordPrivileges is the regression test
// for the 2026-05-12 example-service migration 234 false-positive. The
// statement-verb of "TRUNCATE" inside `GRANT … TRUNCATE …` must be
// "GRANT", not "TRUNCATE".
func TestStatementVerb_GrantWithKeywordPrivileges(t *testing.T) {
	body := `GRANT SELECT, INSERT, UPDATE, DELETE, TRUNCATE, REFERENCES, TRIGGER
  ON TABLES TO example_service_app;`

	for _, kw := range []string{"SELECT", "INSERT", "UPDATE", "DELETE", "TRUNCATE", "REFERENCES", "TRIGGER"} {
		idx := strings.Index(body, kw)
		if idx < 0 {
			t.Fatalf("keyword %q not in body", kw)
		}
		got := statementVerb(body, idx)
		if got != "GRANT" {
			t.Errorf("verb at keyword %q inside GRANT clause: got %q, want \"GRANT\"", kw, got)
		}
	}
}

// TestStatementVerb_DollarQuotedBlocks ensures content inside a DO $$ …
// $$ block isn't treated as separate top-level statements. Otherwise a
// `TRUNCATE` mentioned in a PL/pgSQL string would falsely report
// verb=TRUNCATE instead of staying within the enclosing DO block.
func TestStatementVerb_DollarQuotedBlocks(t *testing.T) {
	body := `DO $$
BEGIN
  RAISE NOTICE 'TRUNCATE is a privilege keyword';
END $$;`

	idx := strings.Index(body, "TRUNCATE")
	if idx < 0 {
		t.Fatal("needle TRUNCATE not in body")
	}
	got := statementVerb(body, idx)
	if got != "DO" {
		t.Errorf("verb at TRUNCATE inside DO block: got %q, want \"DO\"", got)
	}
}

// TestStatementVerb_StringLiteralKeywords covers the case where a SQL
// keyword appears inside a string literal — must not change the
// containing statement's verb.
func TestStatementVerb_StringLiteralKeywords(t *testing.T) {
	body := `INSERT INTO audit_log (action) VALUES ('TRUNCATE was attempted');`

	idx := strings.Index(body, "TRUNCATE")
	if idx < 0 {
		t.Fatal("needle TRUNCATE not in body")
	}
	got := statementVerb(body, idx)
	if got != "INSERT" {
		t.Errorf("verb at TRUNCATE inside string literal: got %q, want \"INSERT\"", got)
	}
}

// TestStatementVerb_LineComments ensures `-- TRUNCATE …` comments don't
// change the containing statement's verb.
func TestStatementVerb_LineComments(t *testing.T) {
	body := `-- TRUNCATE TABLE log; (this is just documentation)
SELECT count(*) FROM users;`

	idx := strings.Index(body, "TRUNCATE")
	if idx < 0 {
		t.Fatal("needle TRUNCATE not in body")
	}
	// Inside a comment, statementVerb returns "" because the offset
	// falls in the masked comment region, not in any statement body.
	got := statementVerb(body, idx)
	if got != "" {
		t.Errorf("verb at TRUNCATE inside line comment: got %q, want \"\"", got)
	}
}

// -- Regression tests for the affected rules ----------------------------

// TestNoTruncate_NoFalsePositiveOnGrant asserts the no-truncate rule
// does NOT fire on the live example-service migration 234 pattern.
func TestNoTruncate_NoFalsePositiveOnGrant(t *testing.T) {
	m := &Migration{Files: []FileBody{{
		Name: "234_grant_keystone_admin_default_privileges_to_example_service_app.up.sql",
		Body: `ALTER DEFAULT PRIVILEGES FOR ROLE keystone_admin IN SCHEMA public
  GRANT SELECT, INSERT, UPDATE, DELETE, TRUNCATE, REFERENCES, TRIGGER
  ON TABLES TO example_service_app;`,
	}}}
	rule := &NoTruncate{}
	out, err := rule.Check(context.Background(), m)
	if err != nil {
		t.Fatalf("Check err: %v", err)
	}
	if len(out) != 0 {
		t.Errorf("expected 0 findings; got %d: %+v", len(out), out)
	}
}

// TestNoTruncate_FiresOnRealTruncate confirms the rule still fires for
// a legitimate top-level TRUNCATE.
func TestNoTruncate_FiresOnRealTruncate(t *testing.T) {
	m := &Migration{Files: []FileBody{{
		Name: "purge.up.sql",
		Body: `TRUNCATE TABLE session_log;`,
	}}}
	rule := &NoTruncate{}
	out, err := rule.Check(context.Background(), m)
	if err != nil {
		t.Fatalf("Check err: %v", err)
	}
	if len(out) != 1 {
		t.Fatalf("expected 1 finding; got %d: %+v", len(out), out)
	}
	if out[0].Severity != keystonev1alpha1.LintLevelError {
		t.Errorf("severity: got %q, want LintLevelError", out[0].Severity)
	}
}

// TestNoUpdateWithoutWhere_NoFalsePositiveOnGrant is the matching
// regression test for the UPDATE-as-privilege false positive.
func TestNoUpdateWithoutWhere_NoFalsePositiveOnGrant(t *testing.T) {
	m := &Migration{Files: []FileBody{{
		Name: "234_grant_keystone_admin_default_privileges_to_example_service_app.up.sql",
		Body: `GRANT SELECT, INSERT, UPDATE, DELETE
  ON TABLE iam_oauth_logout_outbox TO example_service_app;`,
	}}}
	rule := &NoUpdateWithoutWhere{}
	out, err := rule.Check(context.Background(), m)
	if err != nil {
		t.Fatalf("Check err: %v", err)
	}
	if len(out) != 0 {
		t.Errorf("expected 0 findings; got %d: %+v", len(out), out)
	}
}

// TestNoUpdateWithoutWhere_FiresOnRealBareUpdate confirms the rule
// still catches a missing WHERE on an actual UPDATE statement.
func TestNoUpdateWithoutWhere_FiresOnRealBareUpdate(t *testing.T) {
	m := &Migration{Files: []FileBody{{
		Name: "bare_update.up.sql",
		Body: `UPDATE users SET locked = true;`,
	}}}
	rule := &NoUpdateWithoutWhere{}
	out, err := rule.Check(context.Background(), m)
	if err != nil {
		t.Fatalf("Check err: %v", err)
	}
	if len(out) != 1 {
		t.Fatalf("expected 1 finding; got %d: %+v", len(out), out)
	}
}

// TestNoUpdateWithoutWhere_StillSilentWithWhere — sanity.
func TestNoUpdateWithoutWhere_StillSilentWithWhere(t *testing.T) {
	m := &Migration{Files: []FileBody{{
		Name: "guarded_update.up.sql",
		Body: `UPDATE users SET locked = true WHERE id = 42;`,
	}}}
	rule := &NoUpdateWithoutWhere{}
	out, err := rule.Check(context.Background(), m)
	if err != nil {
		t.Fatalf("Check err: %v", err)
	}
	if len(out) != 0 {
		t.Errorf("expected 0 findings; got %d: %+v", len(out), out)
	}
}
