// SPDX-License-Identifier: AGPL-3.0-or-later

package analyze

import (
	"regexp"
	"strings"
)

// -- Statement-verb helpers --------------------------------------------
//
// Many existing analyzer rules trip false positives because the regex
// matches keywords that appear LEXICALLY inside an unrelated SQL
// statement. Concrete cases observed in production (2026-05-12 example-service
// migration 234):
//
//   GRANT SELECT, INSERT, UPDATE, DELETE, TRUNCATE, REFERENCES, TRIGGER
//     ON TABLES TO example_service_app;
//
// trips:
//   no-truncate                — regex `\bTRUNCATE\b`
//   no-update-without-where    — regex `\bUPDATE\s+[^;]*;`
//
// even though both keywords are appearing as PostgreSQL privilege names
// in a GRANT clause, not as statement verbs.
//
// The proper fix is a real SQL parser (e.g. pg_query_go) but that's a
// heavy dep with cgo. The pragmatic fix used here is a statement-boundary
// + verb-gate helper: split the migration body into top-level statements
// (respecting `--` comments, `/* */` block comments, `$$tag$$ ... $$tag$$`
// dollar-quoted blocks, and string literals), then identify the leading
// keyword of each.
//
// False-positive-prone rules wrap their match with `stmtIsVerb(line,
// fileBody, "UPDATE")` so a TRUNCATE inside a GRANT only fires the
// no-truncate rule when the containing statement IS a TRUNCATE.

// reSingleLineComment matches a `--` line comment to the end of line.
var reSingleLineComment = regexp.MustCompile(`(?m)--[^\n]*`)

// reBlockComment matches `/* ... */` block comments (non-greedy).
var reBlockComment = regexp.MustCompile(`(?s)/\*.*?\*/`)

// reStringLiteral matches `'...'` literals, allowing `''` as an escaped
// single quote. Multi-line literals are allowed.
var reStringLiteral = regexp.MustCompile(`(?s)'(?:[^']|'')*'`)

// reVerb captures the leading SQL keyword of a statement (trimmed +
// upper-cased). PostgreSQL keywords are case-insensitive.
var reVerb = regexp.MustCompile(`(?i)^\s*([A-Z][A-Z_]+)\b`)

// stripCommentsAndLiterals erases the content of comments, dollar-quoted
// blocks, and string literals so subsequent statement-boundary detection
// doesn't trip on `;` characters inside them. The text length is
// preserved (replaced with spaces) so line / column offsets stay
// consistent with the original body.
//
// Dollar quotes (`$tag$ ... $tag$`) need tag-matching which RE2 can't
// express as a backreference, so we walk them by hand. Comments and
// single-quoted strings are simple regex masks.
func stripCommentsAndLiterals(body string) string {
	out := []byte(body)
	maskDollarQuotes(out, body)
	maskAll(out, reBlockComment, body)
	maskAll(out, reStringLiteral, body)
	maskAll(out, reSingleLineComment, body)
	return string(out)
}

func maskAll(dst []byte, re *regexp.Regexp, src string) {
	for _, loc := range re.FindAllStringIndex(src, -1) {
		for i := loc[0]; i < loc[1] && i < len(dst); i++ {
			// Preserve newlines so line counting stays correct.
			if dst[i] != '\n' {
				dst[i] = ' '
			}
		}
	}
}

// maskDollarQuotes finds `$tag$ ... $tag$` regions and replaces their
// content with spaces (preserving newlines). Tags can be empty (`$$`)
// or named (`$body$`). Properly tag-matched (no closure on a different
// tag).
func maskDollarQuotes(dst []byte, src string) {
	n := len(src)
	for i := 0; i < n; {
		if src[i] != '$' {
			i++
			continue
		}
		// Try to consume an opening tag: $tag$ where tag is
		// [a-zA-Z_][a-zA-Z0-9_]* (or empty).
		j := i + 1
		for j < n && (isAlnumUnder(src[j])) {
			j++
		}
		if j >= n || src[j] != '$' {
			i++
			continue
		}
		tag := src[i : j+1] // includes both $s
		// Find the matching close.
		close := strings.Index(src[j+1:], tag)
		if close < 0 {
			// Unterminated — treat as plain $ and move on.
			i++
			continue
		}
		end := j + 1 + close + len(tag)
		// Mask [i, end), preserving newlines.
		for k := i; k < end && k < len(dst); k++ {
			if dst[k] != '\n' {
				dst[k] = ' '
			}
		}
		i = end
	}
}

func isAlnumUnder(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
		(c >= '0' && c <= '9') || c == '_'
}

// statementSlices returns the byte offsets of each top-level statement
// in body. Each returned [start, end) covers from the statement's first
// non-whitespace character through (and including) its terminating `;`.
// Top-level here means: outside of comments, string literals, and
// dollar-quoted blocks. We DON'T attempt to honor nested BEGIN…END
// blocks in PL/pgSQL — those are wrapped in dollar quotes in practice.
func statementSlices(body string) [][2]int {
	masked := stripCommentsAndLiterals(body)
	var out [][2]int
	start := -1
	for i, b := range []byte(masked) {
		if start == -1 {
			if b == ' ' || b == '\t' || b == '\n' || b == '\r' {
				continue
			}
			start = i
		}
		if b == ';' {
			out = append(out, [2]int{start, i + 1})
			start = -1
		}
	}
	// Trailing statement with no `;` (rare; pgroll emits these in some
	// strategies). Treat as one statement.
	if start != -1 && start < len(body) {
		out = append(out, [2]int{start, len(body)})
	}
	return out
}

// statementContaining returns the statement [start, end) of body that
// contains the byte offset `at`, or (-1, -1) when `at` is between
// statements (whitespace / between `;` and the next verb).
func statementContaining(body string, at int) (int, int) {
	for _, s := range statementSlices(body) {
		if at >= s[0] && at < s[1] {
			return s[0], s[1]
		}
	}
	return -1, -1
}

// statementVerb returns the upper-cased leading keyword of the statement
// containing `at` in body. Returns the empty string when the offset is
// between statements or when the statement doesn't start with a verb.
//
// Example callers (from rules_data.go / rules.go):
//
//	if statementVerb(f.Body, matchStart) != "UPDATE" { continue }
//	if statementVerb(f.Body, matchStart) != "TRUNCATE" { continue }
//
// This single gate eliminates the GRANT-clause false positives without
// touching the existing regex semantics for legitimate matches.
func statementVerb(body string, at int) string {
	a, b := statementContaining(body, at)
	if a < 0 {
		return ""
	}
	m := reVerb.FindStringSubmatch(body[a:b])
	if len(m) < 2 {
		return ""
	}
	return strings.ToUpper(m[1])
}

// stmtVerbIs is a convenience wrapper used by rule Check() bodies. It
// returns true when the statement containing the match's start offset
// has the given verb (case-insensitive).
func stmtVerbIs(body string, at int, verb string) bool {
	return statementVerb(body, at) == strings.ToUpper(verb)
}
