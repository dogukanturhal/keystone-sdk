// SPDX-License-Identifier: Apache-2.0

package declarative

import "testing"

// Verified live 2026-05-19 against bundle
// `workflow-engine-public-desired-d5d8ae16f68c` SQL: 8 partial-index
// DROP+CREATE pairs were the differ false-positive shape closed by
// normaliseWhereClauseCanonical. These tests pin the live YAML vs
// pg_get_indexdef pairs as regressions.

func TestNormaliseDDL_PartialIndexIsNotNull(t *testing.T) {
	rendered := `CREATE INDEX CONCURRENTLY IF NOT EXISTS "idx_workflow_instances_resume_at" ON "public"."workflow_instances" USING btree ("resume_at") WHERE resume_at IS NOT NULL`
	observed := `CREATE INDEX idx_workflow_instances_resume_at ON public.workflow_instances USING btree (resume_at) WHERE (resume_at IS NOT NULL)`
	if !indexDDLMatch(observed, rendered) {
		t.Errorf("loop-bug regression — partial-index WHERE outer-paren must converge:\n  observed: %s\n  rendered: %s\n  normaliseDDL(observed)=%s\n  normaliseDDL(rendered)=%s",
			observed, rendered, normaliseDDL(observed), normaliseDDL(rendered))
	}
}

func TestNormaliseDDL_PartialIndexTriggerTypeAnd(t *testing.T) {
	// idx_workflow_triggers_schedule_next_run — the multi-comparison
	// AND clause with column-side + literal-side `::text` casts and
	// per-comparison parens.
	rendered := `CREATE INDEX CONCURRENTLY IF NOT EXISTS "idx_workflow_triggers_schedule_next_run" ON "public"."workflow_triggers" USING btree ("schedule_next_run") WHERE trigger_type = 'schedule' AND is_active = true AND schedule_enabled = true`
	observed := `CREATE INDEX idx_workflow_triggers_schedule_next_run ON public.workflow_triggers USING btree (schedule_next_run) WHERE (((trigger_type)::text = 'schedule'::text) AND (is_active = true) AND (schedule_enabled = true))`
	if !indexDDLMatch(observed, rendered) {
		t.Errorf("multi-comparison AND WHERE canonicalisation must converge:\n  normaliseDDL(observed)=%s\n  normaliseDDL(rendered)=%s",
			normaliseDDL(observed), normaliseDDL(rendered))
	}
}

func TestStripTextCastFromLiteral(t *testing.T) {
	cases := []struct {
		in, out string
	}{
		{`col = 'value'::text`, `col = 'value'`},
		{`a = 'x'::text and b = 'y'::text`, `a = 'x' and b = 'y'`},
		{`col = 'value'`, `col = 'value'`},                                             // no cast — unchanged
		{`a = 'literal with ::text inside'::text`, `a = 'literal with ::text inside'`}, // strip only on close-quote
		{`col is not null`, `col is not null`},
	}
	for _, c := range cases {
		got := stripTextCastFromLiteral(c.in)
		if got != c.out {
			t.Errorf("stripTextCastFromLiteral(%q) = %q, want %q", c.in, got, c.out)
		}
	}
}

func TestStripInnerParens(t *testing.T) {
	cases := []struct {
		in, out string
	}{
		{`(a = 1) and (b = 2)`, `a = 1 and b = 2`},
		{`((a = 1) and (b = 2))`, `a = 1 and b = 2`},
		{`a = 1 and b is not null`, `a = 1 and b is not null`}, // no parens — unchanged
		{`(((nested)))`, `nested`},
		{`a = 'has (paren) in literal' and b = 1`, `a = 'has (paren) in literal' and b = 1`}, // quotes preserved
	}
	for _, c := range cases {
		got := stripInnerParens(c.in)
		if got != c.out {
			t.Errorf("stripInnerParens(%q) = %q, want %q", c.in, got, c.out)
		}
	}
}

// TestNormaliseDDL_PartialIndexInAnyArray pins the regression closed on
// 2026-06-14: marketing.ix_outbox_events_status_next_retry_at. The spec
// authored `WHERE status IN ('pending', 'failed')`; PG stored — and
// pg_get_indexdef read back — the rewritten canonical form
// `WHERE ((status)::text = ANY ((ARRAY['pending'::character varying,
// 'failed'::character varying])::text[]))`. Without IN/ANY
// canonicalisation the differ re-emits DROP+CREATE INDEX forever and the
// SchemaDefinition never reaches Ready.
func TestNormaliseDDL_PartialIndexInAnyArray(t *testing.T) {
	rendered := `CREATE INDEX CONCURRENTLY IF NOT EXISTS "ix_outbox_events_status_next_retry_at" ON "marketing"."outbox_events" USING btree ("status", "next_retry_at") WHERE status IN ('pending', 'failed')`
	observed := `CREATE INDEX ix_outbox_events_status_next_retry_at ON marketing.outbox_events USING btree (status, next_retry_at) WHERE ((status)::text = ANY ((ARRAY['pending'::character varying, 'failed'::character varying])::text[]))`
	if !indexDDLMatch(observed, rendered) {
		t.Errorf("IN/ANY(ARRAY) partial-index WHERE must converge:\n  normaliseDDL(observed)=%s\n  normaliseDDL(rendered)=%s",
			normaliseDDL(observed), normaliseDDL(rendered))
	}
}

// Integer IN-list (no per-literal casts, no column cast).
func TestNormaliseDDL_PartialIndexInAnyArrayInt(t *testing.T) {
	rendered := `CREATE INDEX "ix_x" ON "s"."t" USING btree ("a") WHERE kind IN (1, 2, 3)`
	observed := `CREATE INDEX ix_x ON s.t USING btree (a) WHERE (kind = ANY (ARRAY[1, 2, 3]))`
	if !indexDDLMatch(observed, rendered) {
		t.Errorf("integer IN/ANY must converge:\n  normaliseDDL(observed)=%s\n  normaliseDDL(rendered)=%s",
			normaliseDDL(observed), normaliseDDL(rendered))
	}
}

// Negative control: a genuinely different IN-list must NOT match, so the
// canonicalisation can't mask real predicate drift.
func TestNormaliseDDL_PartialIndexInAnyArrayNegative(t *testing.T) {
	observed := `CREATE INDEX ix ON marketing.outbox_events USING btree (status) WHERE ((status)::text = ANY ((ARRAY['pending'::character varying, 'failed'::character varying])::text[]))`
	different := `CREATE INDEX "ix" ON "marketing"."outbox_events" USING btree ("status") WHERE status IN ('pending', 'sent')`
	if indexDDLMatch(observed, different) {
		t.Errorf("different IN-list must NOT be treated equal (would mask real drift):\n  normaliseDDL(observed)=%s\n  normaliseDDL(different)=%s",
			normaliseDDL(observed), normaliseDDL(different))
	}
}

func TestNormaliseInAnyArray(t *testing.T) {
	cases := []struct{ in, out string }{
		{`status = any (array['a', 'b'])`, `status in ('a', 'b')`}, // items preserved verbatim
		{`status = any array['a', 'b']`, `status in ('a', 'b')`},   // paren-less
		{`kind = any (array[1, 2, 3])`, `kind in (1, 2, 3)`},
		{`x = y`, `x = y`},                                         // no ANY — unchanged
		{`a = any (foo)`, `a = any (foo)`},                         // not an array literal — unchanged
		{`note = 'x = any array[1]'`, `note = 'x = any array[1]'`}, // inside literal — preserved
	}
	for _, c := range cases {
		// upstream callers lowercase + strip bare-ident quotes first; the
		// inputs here are already in that shape.
		if got := normaliseInAnyArray(c.in); got != c.out {
			t.Errorf("normaliseInAnyArray(%q) = %q, want %q", c.in, got, c.out)
		}
	}
}

func TestStripTextCastFromLiteral_VarcharChain(t *testing.T) {
	cases := []struct{ in, out string }{
		{`col = 'value'::character varying`, `col = 'value'`},
		{`col = 'value'::varchar`, `col = 'value'`},
		{`col = 'value'::bpchar`, `col = 'value'`},
		{`in ('a'::character varying::text, 'b'::character varying::text)`, `in ('a', 'b')`}, // double-cast chain
		{`col = 'value'::text`, `col = 'value'`},                                             // unchanged behaviour for ::text
	}
	for _, c := range cases {
		if got := stripTextCastFromLiteral(c.in); got != c.out {
			t.Errorf("stripTextCastFromLiteral(%q) = %q, want %q", c.in, got, c.out)
		}
	}
}

// TestNormaliseDDL_PartialIndexNotInAllArray pins the real-world
// production defect that froze the payment-gateway schema-migration
// gate on 2026-09-21: the spec authored
// `WHERE status NOT IN ('completed', 'abandoned', 'dead',
// 'needs_reconciliation')`; PG stored — and pg_get_indexdef read
// back — the rewritten canonical `<> ALL (ARRAY[...])` form with a
// per-element `::character varying` cast and no `::text` suffix on
// the elements. Without NOT IN / <> ALL canonicalisation the differ
// planned DROP INDEX + CREATE INDEX every reconcile; DROP INDEX is
// destructive, the destructive gate refused it, and NO
// MigrationBundle was emitted at all for the schema — freezing every
// other pending change behind it.
func TestNormaliseDDL_PartialIndexNotInAllArray(t *testing.T) {
	rendered := `CREATE INDEX CONCURRENTLY IF NOT EXISTS "idx_payment_gateway_status_reconcile" ON "public"."payment_events" USING btree ("status") WHERE status NOT IN ('completed', 'abandoned', 'dead', 'needs_reconciliation')`
	observed := `CREATE INDEX idx_payment_gateway_status_reconcile ON public.payment_events USING btree (status) WHERE ((status)::text <> ALL ((ARRAY['completed'::character varying, 'abandoned'::character varying, 'dead'::character varying, 'needs_reconciliation'::character varying])::text[]))`
	if !indexDDLMatch(observed, rendered) {
		t.Errorf("NOT IN / <> ALL(ARRAY) partial-index WHERE must converge:\n  normaliseDDL(observed)=%s\n  normaliseDDL(rendered)=%s",
			normaliseDDL(observed), normaliseDDL(rendered))
	}
}

// Positive IN / = ANY control with the same ::character varying
// (no ::text suffix) element-cast shape as the NOT IN production
// case above, to confirm the positive direction also converges
// under that specific cast shape.
func TestNormaliseDDL_PartialIndexInAnyArray_VarcharNoTextSuffix(t *testing.T) {
	rendered := `CREATE INDEX "ix_status" ON "public"."payment_events" USING btree ("status") WHERE status IN ('completed', 'abandoned')`
	observed := `CREATE INDEX ix_status ON public.payment_events USING btree (status) WHERE ((status)::text = ANY ((ARRAY['completed'::character varying, 'abandoned'::character varying])::text[]))`
	if !indexDDLMatch(observed, rendered) {
		t.Errorf("IN / = ANY(ARRAY) with bare ::character varying elements must converge:\n  normaliseDDL(observed)=%s\n  normaliseDDL(rendered)=%s",
			normaliseDDL(observed), normaliseDDL(rendered))
	}
}

// Single-element NOT IN list.
func TestNormaliseDDL_PartialIndexNotInAllArray_SingleElement(t *testing.T) {
	rendered := `CREATE INDEX "ix" ON "s"."t" USING btree ("a") WHERE status NOT IN ('completed')`
	observed := `CREATE INDEX ix ON s.t USING btree (a) WHERE ((status)::text <> ALL ((ARRAY['completed'::character varying])::text[]))`
	if !indexDDLMatch(observed, rendered) {
		t.Errorf("single-element NOT IN / <> ALL must converge:\n  normaliseDDL(observed)=%s\n  normaliseDDL(rendered)=%s",
			normaliseDDL(observed), normaliseDDL(rendered))
	}
}

// Literal elements containing a comma and a `::` sequence must
// survive verbatim — the scanner must not mistake quoted-literal
// payload for list-item or cast syntax.
func TestNormaliseDDL_PartialIndexNotInAllArray_LiteralsWithCommaAndCast(t *testing.T) {
	rendered := `CREATE INDEX "ix" ON "s"."t" USING btree ("a") WHERE status NOT IN ('a, b', 'x::y')`
	observed := `CREATE INDEX ix ON s.t USING btree (a) WHERE ((status)::text <> ALL ((ARRAY['a, b'::character varying, 'x::y'::character varying])::text[]))`
	if !indexDDLMatch(observed, rendered) {
		t.Errorf("literals containing comma/:: must survive verbatim and still converge:\n  normaliseDDL(observed)=%s\n  normaliseDDL(rendered)=%s",
			normaliseDDL(observed), normaliseDDL(rendered))
	}
}

// Negative control: a genuinely different NOT IN list (one element
// changed) must NOT compare equal — canonicalisation must not mask
// real predicate drift.
func TestNormaliseDDL_PartialIndexNotInAllArrayNegative_DifferentElement(t *testing.T) {
	observed := `CREATE INDEX ix ON public.payment_events USING btree (status) WHERE ((status)::text <> ALL ((ARRAY['completed'::character varying, 'abandoned'::character varying])::text[]))`
	different := `CREATE INDEX "ix" ON "public"."payment_events" USING btree ("status") WHERE status NOT IN ('completed', 'cancelled')`
	if indexDDLMatch(observed, different) {
		t.Errorf("a different NOT IN element must NOT be treated equal (would mask real drift):\n  normaliseDDL(observed)=%s\n  normaliseDDL(different)=%s",
			normaliseDDL(observed), normaliseDDL(different))
	}
}

// Negative control: element ORDER matters. We do not sort — an
// authored list with elements reordered must NOT compare equal to
// the observed form, because pg_get_indexdef preserves authored
// order and sorting would let a genuinely different index (a
// differently-authored predicate) compare equal to the stored one.
func TestNormaliseDDL_PartialIndexNotInAllArrayNegative_DifferentOrder(t *testing.T) {
	observed := `CREATE INDEX ix ON public.payment_events USING btree (status) WHERE ((status)::text <> ALL ((ARRAY['completed'::character varying, 'abandoned'::character varying])::text[]))`
	reordered := `CREATE INDEX "ix" ON "public"."payment_events" USING btree ("status") WHERE status NOT IN ('abandoned', 'completed')`
	if indexDDLMatch(observed, reordered) {
		t.Errorf("reordered NOT IN elements must NOT be treated equal (order is preserved, not sorted):\n  normaliseDDL(observed)=%s\n  normaliseDDL(reordered)=%s",
			normaliseDDL(observed), normaliseDDL(reordered))
	}
}

func TestNormaliseNotInAllArray(t *testing.T) {
	cases := []struct{ in, out string }{
		{`status <> all (array['a', 'b'])`, `status not in ('a', 'b')`}, // items preserved verbatim
		{`status <> all array['a', 'b']`, `status not in ('a', 'b')`},   // paren-less
		{`kind <> all (array[1, 2, 3])`, `kind not in (1, 2, 3)`},
		{`x <> y`, `x <> y`},                                              // no ALL — unchanged
		{`a <> all (foo)`, `a <> all (foo)`},                              // not an array literal — unchanged
		{`note = 'x <> all array[1]'`, `note = 'x <> all array[1]'`},      // inside literal — preserved
		{`a <> all (array['a, b', 'x::y'])`, `a not in ('a, b', 'x::y')`}, // comma/:: inside literal preserved
	}
	for _, c := range cases {
		if got := normaliseNotInAllArray(c.in); got != c.out {
			t.Errorf("normaliseNotInAllArray(%q) = %q, want %q", c.in, got, c.out)
		}
	}
}

// TestNormaliseDDL_ProductionThreeExistingPredicates pins the three
// already-live-in-production predicate shapes named in the fix
// requirements, so the new NOT IN / <> ALL pass cannot regress them.
func TestNormaliseDDL_ProductionThreeExistingPredicates(t *testing.T) {
	cases := []struct {
		name               string
		rendered, observed string
	}{
		{
			name:     "event_id not empty",
			rendered: `CREATE INDEX "ix_a" ON "s"."t" USING btree ("a") WHERE event_id <> ''`,
			observed: `CREATE INDEX ix_a ON s.t USING btree (a) WHERE ((event_id)::text <> ''::text)`,
		},
		{
			name:     "resource_type AND sweep_status",
			rendered: `CREATE INDEX "ix_b" ON "s"."t" USING btree ("a") WHERE resource_type = 'checkout_session' AND sweep_status = 'pending'`,
			observed: `CREATE INDEX ix_b ON s.t USING btree (a) WHERE (((resource_type)::text = 'checkout_session'::text) AND ((sweep_status)::text = 'pending'::text))`,
		},
		{
			name:     "subscription_reference_code IS NOT NULL",
			rendered: `CREATE INDEX "ix_c" ON "s"."t" USING btree ("a") WHERE subscription_reference_code IS NOT NULL`,
			observed: `CREATE INDEX ix_c ON s.t USING btree (a) WHERE (subscription_reference_code IS NOT NULL)`,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if !indexDDLMatch(c.observed, c.rendered) {
				t.Errorf("%s: must converge:\n  normaliseDDL(observed)=%s\n  normaliseDDL(rendered)=%s",
					c.name, normaliseDDL(c.observed), normaliseDDL(c.rendered))
			}
		})
	}
}
