// SPDX-License-Identifier: AGPL-3.0-or-later

package migration

import "testing"

func TestNeedsNoTx(t *testing.T) {
	cases := []struct {
		name string
		sql  string
		want bool
	}{
		{"plain create index", "CREATE INDEX idx ON t(col);", false},
		{"create index concurrently", "CREATE INDEX CONCURRENTLY idx ON t(col);", true},
		{"create unique index concurrently", "CREATE UNIQUE INDEX CONCURRENTLY idx ON t(col);", true},
		{"drop index concurrently", "DROP INDEX CONCURRENTLY idx;", true},
		{"reindex concurrently", "REINDEX TABLE CONCURRENTLY t;", true},
		{"lower case keyword", "create index concurrently idx on t(col);", true},
		{"mixed case", "Create Index Concurrently idx ON t(col);", true},
		{"keyword inside identifier no match", "CREATE INDEX idx_concurrentlyxyz ON t(col);", false},
		{"comment only no match", "-- CREATE INDEX CONCURRENTLY idx ON t(col);\nCREATE TABLE t (id INT);", true}, // conservative: matches anywhere
		{"empty", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			src := &ResolvedSource{
				Names: []string{"001.sql"},
				Files: map[string]string{"001.sql": tc.sql},
			}
			if got := needsNoTx(src); got != tc.want {
				t.Errorf("needsNoTx(%q) = %v, want %v", tc.sql, got, tc.want)
			}
		})
	}
}
