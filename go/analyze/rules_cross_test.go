// SPDX-License-Identifier: AGPL-3.0-or-later

package analyze

import (
	"context"
	"strings"
	"testing"

	keystonev1alpha1 "github.com/dogukanturhal/keystone/api/v1alpha1"
)

func TestBreakingChangeDetector_DropColumnSameBundle(t *testing.T) {
	a := &BreakingChangeDetector{}
	m := &Migration{
		Files: []FileBody{
			{
				Name: "001_create.up.sql",
				Body: `CREATE TABLE users (
					id uuid PRIMARY KEY,
					email text NOT NULL,
					legacy_name text
				);`,
			},
			{
				Name: "002_drop_legacy.up.sql",
				Body: `ALTER TABLE users DROP COLUMN legacy_name;`,
			},
		},
	}
	findings, err := a.Check(context.Background(), m)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("want 1 finding, got %d: %+v", len(findings), findings)
	}
	f := findings[0]
	if f.Rule != "cross-migration-breaking-change" {
		t.Errorf("rule=%q", f.Rule)
	}
	if f.Severity != keystonev1alpha1.LintLevelError {
		t.Errorf("severity=%v, want error", f.Severity)
	}
	if f.File != "002_drop_legacy.up.sql" {
		t.Errorf("file=%q", f.File)
	}
	if !strings.Contains(f.Message, "DROP COLUMN legacy_name") {
		t.Errorf("message missing specifics: %q", f.Message)
	}
}

func TestBreakingChangeDetector_DropColumnCreatedNotInBundle(t *testing.T) {
	// The column was NOT created in this bundle — so dropping it is
	// still a concern, but it's the job of no-drop-column (per-file),
	// not the cross-migration analyzer. No finding here.
	a := &BreakingChangeDetector{}
	m := &Migration{
		Files: []FileBody{
			{
				Name: "001_drop.up.sql",
				Body: `ALTER TABLE existing_users DROP COLUMN old_col;`,
			},
		},
	}
	findings, err := a.Check(context.Background(), m)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("want 0 findings (table not bundle-local); got %+v", findings)
	}
}

func TestBreakingChangeDetector_RenameColumnSameBundle(t *testing.T) {
	a := &BreakingChangeDetector{}
	m := &Migration{
		Files: []FileBody{
			{
				Name: "001_create.up.sql",
				Body: `CREATE TABLE orders (id uuid PRIMARY KEY, amt numeric(10,2));`,
			},
			{
				Name: "002_rename.up.sql",
				Body: `ALTER TABLE orders RENAME COLUMN amt TO amount;`,
			},
		},
	}
	findings, err := a.Check(context.Background(), m)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("want 1 finding, got %d: %+v", len(findings), findings)
	}
	if !strings.Contains(findings[0].Message, "RENAME COLUMN amt TO amount") {
		t.Errorf("message missing specifics: %q", findings[0].Message)
	}
}

func TestBreakingChangeDetector_AlterColumnTypeSameBundle(t *testing.T) {
	a := &BreakingChangeDetector{}
	m := &Migration{
		Files: []FileBody{
			{
				Name: "001_create.up.sql",
				Body: `CREATE TABLE widgets (id uuid PRIMARY KEY, code varchar(10));`,
			},
			{
				Name: "002_retype.up.sql",
				Body: `ALTER TABLE widgets ALTER COLUMN code TYPE text;`,
			},
		},
	}
	findings, err := a.Check(context.Background(), m)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("want 1 finding, got %d: %+v", len(findings), findings)
	}
	if !strings.Contains(findings[0].Message, "ALTER COLUMN code TYPE") {
		t.Errorf("message: %q", findings[0].Message)
	}
}

func TestBreakingChangeDetector_DropTableSameBundle(t *testing.T) {
	a := &BreakingChangeDetector{}
	m := &Migration{
		Files: []FileBody{
			{
				Name: "001_create.up.sql",
				Body: `CREATE TABLE tmp_metrics (id bigint PRIMARY KEY);`,
			},
			{
				Name: "002_drop.up.sql",
				Body: `DROP TABLE tmp_metrics;`,
			},
		},
	}
	findings, err := a.Check(context.Background(), m)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("want 1 finding, got %d: %+v", len(findings), findings)
	}
	if !strings.Contains(findings[0].Message, "DROP TABLE tmp_metrics") {
		t.Errorf("message: %q", findings[0].Message)
	}
}

func TestBreakingChangeDetector_AddThenDropColumnSameBundle(t *testing.T) {
	// Column added by ALTER (not CREATE) and then dropped in same bundle
	// — still a breaking change for any client between the two commits.
	a := &BreakingChangeDetector{}
	m := &Migration{
		Files: []FileBody{
			{
				Name: "001_create.up.sql",
				Body: `CREATE TABLE accounts (id uuid PRIMARY KEY, email text);`,
			},
			{
				Name: "002_add.up.sql",
				Body: `ALTER TABLE accounts ADD COLUMN phone text;`,
			},
			{
				Name: "003_drop.up.sql",
				Body: `ALTER TABLE accounts DROP COLUMN phone;`,
			},
		},
	}
	findings, err := a.Check(context.Background(), m)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("want 1 finding, got %d: %+v", len(findings), findings)
	}
	if findings[0].File != "003_drop.up.sql" {
		t.Errorf("expected finding in 003, got %+v", findings[0])
	}
}

func TestBreakingChangeDetector_CleanBundleNoFindings(t *testing.T) {
	// A clean bundle — only additive changes — produces no findings.
	a := &BreakingChangeDetector{}
	m := &Migration{
		Files: []FileBody{
			{
				Name: "001_create.up.sql",
				Body: `CREATE TABLE users (id uuid PRIMARY KEY, email text);`,
			},
			{
				Name: "002_index.up.sql",
				Body: `CREATE INDEX CONCURRENTLY idx_users_email ON users(email);`,
			},
			{
				Name: "003_add.up.sql",
				Body: `ALTER TABLE users ADD COLUMN created_at timestamptz DEFAULT now();`,
			},
		},
	}
	findings, err := a.Check(context.Background(), m)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("want 0 findings on clean bundle; got %+v", findings)
	}
}

func TestBreakingChangeDetector_RegisteredInDefaultRegistry(t *testing.T) {
	reg := DefaultRegistry()
	findings, _ := reg.Run(context.Background(), &Migration{
		Files: []FileBody{
			{
				Name: "001_break.up.sql",
				Body: `CREATE TABLE foo (id uuid PRIMARY KEY, bar text);
				ALTER TABLE foo DROP COLUMN bar;`,
			},
		},
	})
	hit := false
	for _, f := range findings {
		if f.Rule == "cross-migration-breaking-change" {
			hit = true
			break
		}
	}
	if !hit {
		t.Errorf("BreakingChangeDetector not present in DefaultRegistry output; got %+v", findings)
	}
}

// The ALTER TABLE regexes make COLUMN optional, because PostgreSQL does, so
// every table-level subcommand that is not a column operation has to be
// excluded explicitly. Widening an enumerated CHECK — drop the constraint,
// re-add it over a larger value set — is the idiom that exposed this: the ADD
// registered a phantom column named "constraint" and the DROP then reported it
// as a column the same bundle had introduced.
func TestBreakingChangeDetector_ConstraintSubcommandsAreNotColumns(t *testing.T) {
	a := &BreakingChangeDetector{}
	for name, body := range map[string]string{
		"widen check (drop then add)": `ALTER TABLE app_passwords DROP CONSTRAINT IF EXISTS app_passwords_scope_check;
ALTER TABLE app_passwords ADD CONSTRAINT app_passwords_scope_check
    CHECK (scope IS NULL OR scope IN ('smtp', 'imap', 'pop3'));`,
		"widen check (add then drop, table in bundle)": `CREATE TABLE quarantine (id uuid, status text);
ALTER TABLE quarantine ADD CONSTRAINT quarantine_status_check
    CHECK (status IN ('held','released'));
ALTER TABLE quarantine DROP CONSTRAINT quarantine_status_check;`,
		"other table-level ADD subcommands": `CREATE TABLE t (a text, b text);
ALTER TABLE t ADD PRIMARY KEY (a);
ALTER TABLE t ADD UNIQUE (b);
ALTER TABLE t ADD FOREIGN KEY (a) REFERENCES u (id);
ALTER TABLE t ADD CHECK (a <> '');
ALTER TABLE t ADD EXCLUDE USING gist (a WITH =);`,
		"rename constraint": `CREATE TABLE t (id int);
ALTER TABLE t RENAME CONSTRAINT t_old_check TO t_new_check;`,
	} {
		m := &Migration{Files: []FileBody{{Name: "001.up.sql", Body: body}}}
		findings, err := a.Check(context.Background(), m)
		if err != nil {
			t.Fatalf("%s: unexpected err: %v", name, err)
		}
		if len(findings) != 0 {
			t.Errorf("%s: want no findings, got %d: %+v", name, len(findings), findings)
		}
	}
}

// The exclusion must stay narrow: constraint churn in the same file may not
// mask a column drop sitting next to it.
func TestBreakingChangeDetector_ColumnDropStillFiresBesideConstraintTraffic(t *testing.T) {
	a := &BreakingChangeDetector{}
	m := &Migration{Files: []FileBody{{
		Name: "001.up.sql",
		Body: `CREATE TABLE t (id int, email text);
ALTER TABLE t DROP CONSTRAINT IF EXISTS t_email_check;
ALTER TABLE t DROP COLUMN email;`,
	}}}
	findings, err := a.Check(context.Background(), m)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("want 1 finding, got %d: %+v", len(findings), findings)
	}
	if !strings.Contains(findings[0].Message, "DROP COLUMN email") {
		t.Errorf("message missing specifics: %q", findings[0].Message)
	}
}
