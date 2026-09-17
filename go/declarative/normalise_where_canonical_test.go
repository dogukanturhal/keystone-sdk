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
