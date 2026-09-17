// SPDX-License-Identifier: AGPL-3.0-or-later

package declarative

import "testing"

// TestNormaliseArrayCasts_FalconIdLoginRiskHighRiskWhereClause covers
// the exact strings observed 2026-05-06 on
// idx_iam_login_risk_events_high_risk in
// example-service-tenant-desired. Pre-fix the differ saw permanent drift
// between SD-declared (cast distribution) and PG-stored (per-element
// cast) forms, re-emitting the same DROP/CREATE bundle on every
// reconcile and driving keystone-operator into OOM-loop.
func TestNormaliseArrayCasts_FalconIdLoginRiskHighRiskWhereClause(t *testing.T) {
	// What the SD declares — outer-cast form (`(ARRAY[...])::TYPE[]`):
	rendered := `CREATE INDEX idx_iam_login_risk_events_high_risk ` +
		`ON public.iam_login_risk_events USING btree (created_at DESC) ` +
		`WHERE ((level)::text = ANY ((ARRAY['high'::character varying, ` +
		`'critical'::character varying])::text[]))`
	// What pg_get_indexdef returns — per-element cast form:
	observed := `CREATE INDEX idx_iam_login_risk_events_high_risk ` +
		`ON public.iam_login_risk_events USING btree (created_at DESC) ` +
		`WHERE ((level)::text = ANY (ARRAY[('high'::character varying)::text, ` +
		`('critical'::character varying)::text]))`

	if !indexDDLMatch(observed, rendered) {
		t.Errorf("indexDDLMatch should be true for semantically identical "+
			"WHERE-clause forms, got false\n  rendered: %s\n  observed: %s\n  norm-rendered: %q\n  norm-observed: %q",
			rendered, observed,
			normaliseDDL(rendered), normaliseDDL(observed))
	}
}

func TestNormaliseArrayCasts_DistributesOuterCast(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{
			name: "two-element-character-varying-to-text-array",
			in:   `(array['high'::character varying, 'critical'::character varying])::text[]`,
			want: `array[('high'::character varying)::text, ('critical'::character varying)::text]`,
		},
		{
			name: "single-element",
			in:   `(array['only'::character varying])::text[]`,
			want: `array[('only'::character varying)::text]`,
		},
		{
			name: "three-element-int-array-to-bigint",
			in:   `(array[1::integer, 2::integer, 3::integer])::bigint[]`,
			want: `array[(1::integer)::bigint, (2::integer)::bigint, (3::integer)::bigint]`,
		},
		{
			name: "embedded-in-where-predicate",
			in:   `(level)::text = any ((array['a'::varchar, 'b'::varchar])::text[])`,
			want: `(level)::text = any (array[('a'::varchar)::text, ('b'::varchar)::text])`,
		},
		{
			name: "already-canonical-per-element-form-is-noop",
			in:   `array[('high'::character varying)::text, ('critical'::character varying)::text]`,
			want: `array[('high'::character varying)::text, ('critical'::character varying)::text]`,
		},
		{
			name: "non-array-text-untouched",
			in:   `where (status)::text = 'active'`,
			want: `where (status)::text = 'active'`,
		},
		{
			name: "quoted-literal-containing-array-syntax-not-rewritten",
			in:   `where note = '(array[1,2])::int[]'`,
			want: `where note = '(array[1,2])::int[]'`,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := normaliseArrayCasts(c.in)
			if got != c.want {
				t.Errorf("normaliseArrayCasts:\n  in:   %q\n  got:  %q\n  want: %q", c.in, got, c.want)
			}
		})
	}
}

func TestNormaliseArrayCasts_Idempotent(t *testing.T) {
	// Running twice must equal running once — both forms are stable
	// fixed points after a single application.
	inputs := []string{
		`(array['a'::varchar, 'b'::varchar])::text[]`,
		`array[('a'::varchar)::text, ('b'::varchar)::text]`,
		`where (level)::text = any ((array['high'::character varying])::text[])`,
		`create index i on t using btree (a) where (status)::text = 'active'`,
	}
	for _, in := range inputs {
		t.Run(in, func(t *testing.T) {
			once := normaliseArrayCasts(in)
			twice := normaliseArrayCasts(once)
			if once != twice {
				t.Errorf("not idempotent:\n  in:    %q\n  once:  %q\n  twice: %q", in, once, twice)
			}
		})
	}
}

func TestMatchBracket_QuotedLiteralAware(t *testing.T) {
	cases := []struct {
		s     string
		start int
		want  int
	}{
		{`[1, 2, 3]`, 0, 8},
		{`[1, 'a]b', 2]`, 0, 12},
		{`[[1,2], [3,4]]`, 0, 13},
		{`[unbalanced`, 0, -1},
	}
	for _, c := range cases {
		got := matchBracket(c.s, c.start)
		if got != c.want {
			t.Errorf("matchBracket(%q, %d) = %d, want %d", c.s, c.start, got, c.want)
		}
	}
}

func TestSplitTopLevelArrayItems_RespectsBracketDepth(t *testing.T) {
	cases := []struct {
		in   string
		want []string
	}{
		{`'a', 'b'`, []string{`'a'`, ` 'b'`}},
		{`(1,2), (3,4)`, []string{`(1,2)`, ` (3,4)`}},
		{`[1,2], [3,4]`, []string{`[1,2]`, ` [3,4]`}},
		{`'comma,inside', plain`, []string{`'comma,inside'`, ` plain`}},
	}
	for _, c := range cases {
		got := splitTopLevelArrayItems(c.in)
		if len(got) != len(c.want) {
			t.Errorf("splitTopLevelArrayItems(%q) len=%d want=%d (got=%v)",
				c.in, len(got), len(c.want), got)
			continue
		}
		for i := range got {
			if got[i] != c.want[i] {
				t.Errorf("splitTopLevelArrayItems(%q)[%d] = %q want %q", c.in, i, got[i], c.want[i])
			}
		}
	}
}
