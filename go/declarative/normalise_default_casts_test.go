// SPDX-License-Identifier: AGPL-3.0-or-later

package declarative

import "testing"

// Cluster-observed live behaviour as of 2026-05-20:
//
// Master-data, notification-service, and storage-api SDs all loop
// forever on ALTER COLUMN ... SET DEFAULT '' because PG canonicalises
// every literal default through pg_get_expr() with an explicit type
// cast attached (`''::text`, `''::character varying`, `'{}'::jsonb`,
// `'{}'::integer[]`, ...). YAML defaults are bare. Without
// canonicalisation, the differ emits no-op rewrites every reconcile.
// Pin the equivalences here so a future regression in
// stripLiteralTypeCasts / skipTypeCast produces a build break.

func TestDefaultsEqual_LiteralTypeCastsStripped(t *testing.T) {
	cases := []struct {
		name      string
		desired   string
		observed  string
		wantEqual bool
	}{
		// The bug from master-data-public-desired:
		{
			name:      "empty-string-vs-text-cast",
			desired:   "''",
			observed:  "''::text",
			wantEqual: true,
		},
		// notification-service-public-desired
		{
			name:      "empty-string-vs-character-varying-cast",
			desired:   "''",
			observed:  "''::character varying",
			wantEqual: true,
		},
		// Non-empty quoted literals must canonicalise too — the
		// `'pending_deletion'::character varying` form appears in
		// many enum-style columns.
		{
			name:      "non-empty-string-vs-varchar-cast",
			desired:   "'synced'",
			observed:  "'synced'::character varying",
			wantEqual: true,
		},
		{
			name:      "different-strings-still-unequal",
			desired:   "'synced'",
			observed:  "'pending'::character varying",
			wantEqual: false,
		},
		// jsonb default {} — notification-service-public-desired
		// has multiple `notification_*.config = '{}'::jsonb`.
		{
			name:      "empty-jsonb",
			desired:   "'{}'",
			observed:  "'{}'::jsonb",
			wantEqual: true,
		},
		// Array casts. PG canonicalises `'{}'::integer[]` for
		// notification_quiet_hours.days_of_week, `'{}'::text[]` for
		// notification_api_keys.scopes, etc.
		{
			name:      "empty-integer-array",
			desired:   "'{}'",
			observed:  "'{}'::integer[]",
			wantEqual: true,
		},
		{
			name:      "empty-text-array",
			desired:   "'{}'",
			observed:  "'{}'::text[]",
			wantEqual: true,
		},
		// Double-cast (rare but possible in nested expressions): the
		// stripper should chew through to a bare literal.
		{
			name:      "varchar-then-text-cast",
			desired:   "'foo'",
			observed:  "'foo'::character varying",
			wantEqual: true,
		},
		// Numeric literal casts. `0::integer` and friends appear in
		// hand-edited tables where someone wrote the default with an
		// explicit cast then PG echoed the cast back.
		{
			name:      "bare-zero-vs-integer-cast",
			desired:   "0",
			observed:  "0::integer",
			wantEqual: true,
		},
		{
			name:      "bare-decimal-vs-numeric-cast",
			desired:   "1.5",
			observed:  "1.5::numeric",
			wantEqual: true,
		},
		// Functions are NOT affected — they continue to round-trip
		// without canonical-form drift.
		{
			name:      "function-call-now",
			desired:   "now()",
			observed:  "now()",
			wantEqual: true,
		},
		// Cast embedded inside a string literal is payload, not
		// syntax. Must be preserved verbatim.
		{
			name:      "quoted-string-containing-cast-text",
			desired:   "'foo::text'",
			observed:  "'foo::text'",
			wantEqual: true,
		},
		// Single-quote escape (PG-canonical `''` for embedded quote)
		// must not terminate the literal early.
		{
			name:      "embedded-single-quote-escape",
			desired:   "'it''s'",
			observed:  "'it''s'::character varying",
			wantEqual: true,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := defaultsEqual(c.desired, c.observed)
			if got != c.wantEqual {
				t.Errorf("defaultsEqual(%q, %q) = %v, want %v\n  normaliseDefault(desired)=%q\n  normaliseDefault(observed)=%q",
					c.desired, c.observed, got, c.wantEqual,
					normaliseDefault(c.desired), normaliseDefault(c.observed))
			}
		})
	}
}

func TestStripLiteralTypeCasts(t *testing.T) {
	cases := []struct {
		name string
		in   string
		out  string
	}{
		{"bare", "''", "''"},
		{"text-cast", "''::text", "''"},
		{"character-varying-cast", "''::character varying", "''"},
		{"non-empty-varchar", "'foo'::character varying", "'foo'"},
		{"jsonb-cast", "'{}'::jsonb", "'{}'"},
		{"integer-array", "'{}'::integer[]", "'{}'"},
		{"text-array", "'{}'::text[]", "'{}'"},
		{"numeric-bare-cast", "0::integer", "0"},
		{"decimal-cast", "1.5::numeric", "1.5"},
		{"function-untouched", "now()", "now()"},
		{"public-prefix-untouched", "public.uuid_generate_v4()", "public.uuid_generate_v4()"},
		{"quoted-cast-text-payload", "'foo::text'", "'foo::text'"},
		{"embedded-quote-escape", "'it''s'::text", "'it''s'"},
		// Negative case: an identifier that's not a type-cast
		// continuation must NOT be eaten.
		{"non-cast-followed-by-letters", "'a' b", "'a' b"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := stripLiteralTypeCasts(c.in)
			if got != c.out {
				t.Errorf("stripLiteralTypeCasts(%q) = %q, want %q", c.in, got, c.out)
			}
		})
	}
}
