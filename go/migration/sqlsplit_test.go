// SPDX-License-Identifier: AGPL-3.0-or-later

package migration

import (
	"strings"
	"testing"
)

func TestSplitSQLStatements(t *testing.T) {
	cases := []struct {
		name string
		sql  string
		want []string
	}{
		{"empty", "", nil},
		{"single", "SELECT 1;", []string{"SELECT 1;"}},
		{"two simple", "SELECT 1; SELECT 2;", []string{"SELECT 1;", "SELECT 2;"}},
		{"trailing whitespace stripped", "  SELECT 1;\n  SELECT 2;\n  ", []string{"SELECT 1;", "SELECT 2;"}},
		{"no trailing semicolon kept", "SELECT 1", []string{"SELECT 1"}},
		{
			"semicolon inside string literal",
			"SELECT 'a;b'; SELECT 2;",
			[]string{"SELECT 'a;b';", "SELECT 2;"},
		},
		{
			"escaped single-quote inside literal",
			"SELECT 'it''s ok; really'; SELECT 2;",
			[]string{"SELECT 'it''s ok; really';", "SELECT 2;"},
		},
		{
			"semicolon inside identifier quotes",
			`SELECT "weird;name" FROM t; SELECT 2;`,
			[]string{`SELECT "weird;name" FROM t;`, "SELECT 2;"},
		},
		{
			"line comment with semicolon",
			"SELECT 1; -- a; b;\nSELECT 2;",
			[]string{"SELECT 1;", "-- a; b;\nSELECT 2;"},
		},
		{
			"block comment with semicolon",
			"SELECT 1; /* a; b */ SELECT 2;",
			[]string{"SELECT 1;", "/* a; b */ SELECT 2;"},
		},
		{
			"dollar-quoted bare",
			"DO $$ BEGIN PERFORM 1; END $$; SELECT 2;",
			[]string{"DO $$ BEGIN PERFORM 1; END $$;", "SELECT 2;"},
		},
		{
			"dollar-quoted with tag",
			"DO $body$ BEGIN PERFORM 1; END $body$; SELECT 2;",
			[]string{"DO $body$ BEGIN PERFORM 1; END $body$;", "SELECT 2;"},
		},
		{
			"declarative diff style",
			strings.TrimSpace(`
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_iam_tenants_plan ON public.iam_tenants (plan);

DROP TABLE IF EXISTS public.iam_refresh_tokens;
`),
			[]string{
				"CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_iam_tenants_plan ON public.iam_tenants (plan);",
				"DROP TABLE IF EXISTS public.iam_refresh_tokens;",
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := splitSQLStatements(tc.sql)
			if len(got) != len(tc.want) {
				t.Fatalf("len mismatch: got %d %#v, want %d %#v", len(got), got, len(tc.want), tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Errorf("stmt[%d] = %q, want %q", i, got[i], tc.want[i])
				}
			}
		})
	}
}
