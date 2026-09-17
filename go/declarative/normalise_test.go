// SPDX-License-Identifier: AGPL-3.0-or-later

package declarative

import "testing"

func TestNormaliseDDL_StripIdentifierQuotes(t *testing.T) {
	cases := []struct {
		name     string
		observed string
		rendered string
		want     bool
	}{
		{
			name:     "simple-quoted-vs-unquoted-equivalent",
			observed: "CREATE INDEX idx_arc_status ON public.access_review_campaigns USING btree (status)",
			rendered: `CREATE INDEX "idx_arc_status" ON "public"."access_review_campaigns" USING btree ("status")`,
			want:     true,
		},
		{
			name:     "multi-column-with-quotes",
			observed: "CREATE INDEX idx_orders_created ON public.orders USING btree (tenant_id, created_at DESC)",
			rendered: `CREATE INDEX "idx_orders_created" ON "public"."orders" USING btree ("tenant_id", "created_at" DESC)`,
			want:     true,
		},
		{
			name:     "predicate-with-string-literal-not-stripped",
			observed: "CREATE INDEX idx_active ON public.t USING btree (id) WHERE status = 'active'",
			rendered: `CREATE INDEX "idx_active" ON "public"."t" USING btree ("id") WHERE status = 'active'`,
			want:     true,
		},
		{
			name:     "different-columns-still-diff",
			observed: "CREATE INDEX i ON public.t USING btree (a)",
			rendered: `CREATE INDEX "i" ON "public"."t" USING btree ("b")`,
			want:     false,
		},
		{
			name:     "mixed-case-identifier-stays-quoted-but-normalises-equal-after-tolower",
			observed: `CREATE INDEX "MyIndex" ON public.t USING btree (a)`,
			rendered: `CREATE INDEX "myindex" ON "public"."t" USING btree ("a")`,
			want:     true,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := indexDDLMatch(c.observed, c.rendered)
			if got != c.want {
				t.Errorf("indexDDLMatch:\n  observed: %s\n  rendered: %s\n  got=%v want=%v\n  norm-obs: %q\n  norm-ren: %q",
					c.observed, c.rendered, got, c.want,
					normaliseDDL(c.observed), normaliseDDL(c.rendered))
			}
		})
	}
}

func TestStripBareIdentifierQuotes_PredicateLiteralsPreserved(t *testing.T) {
	in := `where (status)::text = any (array['high'::character varying, 'critical'::character varying])`
	got := stripBareIdentifierQuotes(in)
	if got != in {
		t.Errorf("predicate literals modified:\n  in:  %q\n  out: %q", in, got)
	}
}

func TestIsBareLowerIdentifier(t *testing.T) {
	cases := map[string]bool{
		"idx_arc_status":        true,
		"_underscore_start":     true,
		"a":                     true,
		"":                      false,
		"123_starts_with_digit": false,
		"has-dash":              false,
		"MixedCase":             false,
		"has space":             false,
		"has.dot":               false,
	}
	for in, want := range cases {
		if got := isBareLowerIdentifier(in); got != want {
			t.Errorf("isBareLowerIdentifier(%q) = %v, want %v", in, got, want)
		}
	}
}
