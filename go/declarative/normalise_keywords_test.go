// SPDX-License-Identifier: AGPL-3.0-or-later

package declarative

import "testing"

func TestNormaliseDDL_StripIfNotExists(t *testing.T) {
	a := normaliseDDL(`CREATE INDEX IF NOT EXISTS idx_x ON public.t USING btree (a)`)
	b := normaliseDDL(`CREATE INDEX idx_x ON public.t USING btree (a)`)
	if a != b {
		t.Errorf("IF NOT EXISTS strip:\n a=%q\n b=%q", a, b)
	}
}

func TestNormaliseDDL_StripConcurrently(t *testing.T) {
	a := normaliseDDL(`CREATE INDEX CONCURRENTLY idx_x ON public.t USING btree (a)`)
	b := normaliseDDL(`CREATE INDEX idx_x ON public.t USING btree (a)`)
	if a != b {
		t.Errorf("CONCURRENTLY strip:\n a=%q\n b=%q", a, b)
	}
}

func TestNormaliseDDL_StripUniqueConcurrently(t *testing.T) {
	a := normaliseDDL(`CREATE UNIQUE INDEX CONCURRENTLY idx_x ON public.t USING btree (a)`)
	b := normaliseDDL(`CREATE UNIQUE INDEX idx_x ON public.t USING btree (a)`)
	if a != b {
		t.Errorf("UNIQUE CONCURRENTLY strip:\n a=%q\n b=%q", a, b)
	}
}

func TestNormaliseDDL_StripOnOnly(t *testing.T) {
	a := normaliseDDL(`CREATE INDEX idx_x ON ONLY public.t USING btree (a)`)
	b := normaliseDDL(`CREATE INDEX idx_x ON public.t USING btree (a)`)
	if a != b {
		t.Errorf("ON ONLY strip:\n a=%q\n b=%q", a, b)
	}
}

func TestNormaliseDDL_PartitionedTableEnd2End(t *testing.T) {
	observed := `CREATE INDEX idx_audit_log_part_action ON ONLY public.iam_audit_log_partitioned USING btree (action, created_at DESC)`
	rendered := `CREATE INDEX CONCURRENTLY IF NOT EXISTS "idx_audit_log_part_action" ON "public"."iam_audit_log_partitioned" USING btree ("action", "created_at" DESC)`
	if !indexDDLMatch(observed, rendered) {
		t.Errorf("partitioned-table indexes should match:\n  obs: %q\n  ren: %q\n  norm-obs: %q\n  norm-ren: %q",
			observed, rendered, normaliseDDL(observed), normaliseDDL(rendered))
	}
}

func TestNormaliseDDL_CoalesceUniqueIndexEnd2End(t *testing.T) {
	observed := `CREATE UNIQUE INDEX iam_idp_routing_rules_composite_unique ON public.iam_idp_routing_rules USING btree (tenant_id, rule_type, COALESCE(rule_value, ''::character varying))`
	rendered := `CREATE UNIQUE INDEX CONCURRENTLY IF NOT EXISTS "iam_idp_routing_rules_composite_unique" ON "public"."iam_idp_routing_rules" USING btree ("tenant_id", "rule_type", (COALESCE(rule_value, ''::character varying)))`
	if !indexDDLMatch(observed, rendered) {
		t.Errorf("COALESCE-expression indexes should match:\n  obs: %q\n  ren: %q\n  norm-obs: %q\n  norm-ren: %q",
			observed, rendered, normaliseDDL(observed), normaliseDDL(rendered))
	}
}

func TestStripRedundantExpressionParens(t *testing.T) {
	cases := []struct {
		name     string
		in, want string
	}{
		{
			name: "single-coalesce",
			in:   `btree (a, (coalesce(rule_value, '')))`,
			want: `btree (a, coalesce(rule_value, ''))`,
		},
		{
			name: "leaves-arithmetic-parens-alone",
			in:   `btree ((a + b))`,
			want: `btree ((a + b))`, // no func call inside; left intact
		},
		{
			name: "non-redundant-paren-stays",
			in:   `btree (coalesce(a, b))`,
			want: `btree (coalesce(a, b))`,
		},
		{
			name: "nested-coalesce-in-where",
			in:   `where (status) = 'active'`,
			want: `where (status) = 'active'`,
		},
		{
			name: "preserves-quoted-string-literal-with-parens",
			// list context (preceded by `,`) so the strip runs and we
			// can verify quoted-literal scanning protects the inner
			// `'(...)'` text from being treated as paren structure.
			in:   `btree (a, (coalesce(x, '(quoted parens)')))`,
			want: `btree (a, coalesce(x, '(quoted parens)'))`,
		},
		{
			name: "standalone-not-in-list-context-untouched",
			// position 0 is start-of-string, no preceding `,` or `(`,
			// so nothing is stripped — preserves predicate parens etc.
			in:   `(coalesce(a, b))`,
			want: `(coalesce(a, b))`,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := stripRedundantExpressionParens(c.in)
			if got != c.want {
				t.Errorf("\n  in=%q\n got=%q\nwant=%q", c.in, got, c.want)
			}
		})
	}
}
