package declarative

import "testing"

// Both bugs were discovered live on 2026-05-19 with example-service and
// integration-hub-cfg SchemaDefinitions silently looping forever on
// bundle re-emission. The tests below pin the equivalence so a future
// regression in either canonicaliser produces a build break instead
// of a fragmentation alert + audit-stream flood.

func TestDefaultsEqual_PublicSchemaPrefixStripped(t *testing.T) {
	cases := []struct {
		name             string
		desired          string
		observed         string
		wantEqual        bool
	}{
		{
			name:      "qualified-vs-unqualified",
			desired:   "public.uuid_generate_v4()",
			observed:  "uuid_generate_v4()",
			wantEqual: true,
		},
		{
			name:      "both-unqualified",
			desired:   "uuid_generate_v4()",
			observed:  "uuid_generate_v4()",
			wantEqual: true,
		},
		{
			name:      "both-qualified",
			desired:   "public.uuid_generate_v4()",
			observed:  "public.uuid_generate_v4()",
			wantEqual: true,
		},
		{
			name:      "non-public-schema-stays-qualified",
			desired:   "keystone.next_seq()",
			observed:  "next_seq()",
			wantEqual: false,
		},
		{
			name:      "different-functions-not-equal",
			desired:   "uuid_generate_v4()",
			observed:  "uuid_generate_v1mc()",
			wantEqual: false,
		},
		{
			name:      "now-vs-now-trivial",
			desired:   "now()",
			observed:  "now()",
			wantEqual: true,
		},
		{
			name:      "case-and-whitespace-insensitive",
			desired:   "  Public.UUID_Generate_V4()  ",
			observed:  "uuid_generate_v4()",
			wantEqual: true,
		},
		{
			name:      "string-literal-with-public.x-preserved",
			desired:   "'public.something'",
			observed:  "'public.something'",
			wantEqual: true,
		},
		{
			name:      "quoted-public.foo-bareword-not-stripped",
			desired:   "'public.foo'",
			observed:  "'foo'",
			wantEqual: false,
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

func TestStripVarcharTextCastEquality(t *testing.T) {
	cases := []struct {
		name  string
		in    string
		out   string
	}{
		{
			name: "varchar-equals-literal-canonicalised-form",
			in:   "where ((activation_status)::text = ('pending_deletion'::character varying)::text)",
			out:  "where (activation_status = 'pending_deletion'::character varying)",
		},
		{
			name: "natural-form-untouched",
			in:   "where (activation_status = 'pending_deletion'::character varying)",
			out:  "where (activation_status = 'pending_deletion'::character varying)",
		},
		{
			name: "less-than-comparison-also-rewritten",
			in:   "(rank)::text < ('z'::character varying)::text",
			out:  "rank < 'z'::character varying",
		},
		{
			name: "not-equal-comparison",
			in:   "(status)::text <> ('inactive'::character varying)::text",
			out:  "status <> 'inactive'::character varying",
		},
		{
			name: "quoted-literal-skipped",
			in:   "'(foo)::text = (bar)::text'",
			out:  "'(foo)::text = (bar)::text'",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := stripVarcharTextCastEquality(c.in)
			if got != c.out {
				t.Errorf("stripVarcharTextCastEquality:\n  in:   %s\n  got:  %s\n  want: %s", c.in, got, c.out)
			}
		})
	}
}

func TestNormaliseDDL_PartialIndexVarcharEquality(t *testing.T) {
	// End-to-end: this is the loop that bit example-service-public-desired
	// (idx_iam_users_pending_deletion). Both forms must converge.
	rendered := `CREATE INDEX CONCURRENTLY IF NOT EXISTS "idx_iam_users_pending_deletion" ON "public"."iam_users" USING btree ("deletion_grace_period_ends_at") WHERE (activation_status = 'pending_deletion'::character varying)`
	observed := `CREATE INDEX idx_iam_users_pending_deletion ON public.iam_users USING btree (deletion_grace_period_ends_at) WHERE ((activation_status)::text = ('pending_deletion'::character varying)::text)`

	if !indexDDLMatch(observed, rendered) {
		t.Errorf("loop-bug regression — partial-index WHERE varchar cast canonicalisation must converge:\n  observed: %s\n  rendered: %s\n  normaliseDDL(observed)=%s\n  normaliseDDL(rendered)=%s",
			observed, rendered, normaliseDDL(observed), normaliseDDL(rendered))
	}
}
