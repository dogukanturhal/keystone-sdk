// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 HexxLock

package sqlquote

import (
	"strings"
	"testing"
)

// FuzzValidateIdentifier guards the defence-in-depth identifier
// gate described in ADR 0010. Any input that reaches the DDL
// generator must either be rejected by ValidateIdentifier or be
// safely quotable by QuoteIdentifier.
//
// Oracle: we assert TWO invariants on every fuzzing input:
//
//  1. If ValidateIdentifier returns nil (accepted), the input matches
//     the documented regex (lowercase letter/underscore lead, then
//     lowercase alnum/underscore, max 63 chars).
//
//  2. If ValidateIdentifier returns nil, QuoteIdentifier produces a
//     string that:
//     a) starts and ends with a double-quote
//     b) contains no un-escaped double-quotes in the middle
//     c) produces the same output when run twice (idempotent on
//     the unquoted form)
//
// The fuzzer generates arbitrary UTF-8 (as Go's built-in fuzzer
// does) and we look for any input that breaks invariant 2 —
// an accepted identifier that QuoteIdentifier mishandles. That
// would be a DDL-injection window per ADR 0010.
//
// Run locally via:
//
//	go test -fuzz=FuzzValidateIdentifier -fuzztime=30s ./sqlquote/
func FuzzValidateIdentifier(f *testing.F) {
	// Seed with the classic attack vectors + legitimate names.
	seeds := []string{
		"users",
		"my_table",
		"a",
		"_leading_underscore",
		"t123",
		"table\"; DROP TABLE users; --",
		"a\"b",
		"a\x00b",
		"SELECT",  // reserved-looking; soft-enforced elsewhere
		"foo.bar", // schema-qualified is NOT an identifier
		strings.Repeat("a", 63),
		strings.Repeat("a", 64), // over MaxLength
		"",
		"123_leading_digit",
		"MiXeD_cAsE",
		"café",
		"日本語",
		"‮table", // right-to-left override
		" leading_space",
		"trailing_space ",
		"back`tick",
		"semi;colon",
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, in string) {
		err := ValidateIdentifier("fuzz", in)
		if err != nil {
			// Reject is always safe from this tool's perspective.
			return
		}

		// Accepted — now assert the documented shape. A failure here
		// means ValidateIdentifier is permissive beyond its regex.
		if len(in) == 0 {
			t.Errorf("accepted empty identifier")
			return
		}
		if len(in) > 63 {
			t.Errorf("accepted over-long identifier len=%d: %q", len(in), in)
			return
		}
		c := in[0]
		if !(c == '_' || (c >= 'a' && c <= 'z')) {
			t.Errorf("accepted identifier with illegal leading byte 0x%02x: %q", c, in)
			return
		}
		for i := 1; i < len(in); i++ {
			c := in[i]
			if !(c == '_' || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')) {
				t.Errorf("accepted identifier with illegal byte 0x%02x at pos %d: %q",
					c, i, in)
				return
			}
		}

		// QuoteIdentifier invariants.
		q := QuoteIdentifier(in)
		if !strings.HasPrefix(q, `"`) || !strings.HasSuffix(q, `"`) {
			t.Errorf("QuoteIdentifier(%q) = %q; expected wrapped in double-quotes", in, q)
			return
		}
		// The body (between outer quotes) must have every `"` escaped
		// as `""`. Count inner quotes and assert pair-even.
		inner := q[1 : len(q)-1]
		if strings.Count(inner, `"`)%2 != 0 {
			t.Errorf("QuoteIdentifier(%q) = %q; unbalanced inner quotes", in, q)
			return
		}
		// Idempotence on the unquoted form: QuoteIdentifier should be
		// deterministic; re-quoting the same name yields the same
		// output byte-for-byte.
		if QuoteIdentifier(in) != q {
			t.Errorf("QuoteIdentifier(%q) non-deterministic: got %q then %q",
				in, q, QuoteIdentifier(in))
		}
	})
}

// FuzzQuoteIdentifier exercises QuoteIdentifier on arbitrary inputs
// regardless of whether ValidateIdentifier would accept them. The
// invariant is narrower: QuoteIdentifier must never produce a string
// that can terminate the identifier literal unintentionally — any
// `"` in the input must land as `""` in the output.
func FuzzQuoteIdentifier(f *testing.F) {
	seeds := []string{
		"",
		"a",
		`a"b`,
		`""`,
		`"; DROP TABLE users; --`,
		"\x00",
		strings.Repeat(`"`, 100),
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, in string) {
		q := QuoteIdentifier(in)
		if !strings.HasPrefix(q, `"`) || !strings.HasSuffix(q, `"`) {
			t.Errorf("QuoteIdentifier(%q) = %q; not wrapped", in, q)
			return
		}
		inner := q[1 : len(q)-1]
		// Every inner `"` must be part of a `""` pair — scan by pairs.
		for i := 0; i < len(inner); i++ {
			if inner[i] == '"' {
				if i+1 >= len(inner) || inner[i+1] != '"' {
					t.Errorf("QuoteIdentifier(%q) = %q; unpaired inner quote at position %d",
						in, q, i)
					return
				}
				i++ // skip the paired second quote
			}
		}
	})
}
