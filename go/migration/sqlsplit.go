// SPDX-License-Identifier: AGPL-3.0-or-later

package migration

import "strings"

// splitSQLStatements splits a SQL script into individual statements on
// top-level semicolons, ignoring semicolons that appear inside single-
// quoted strings, double-quoted identifiers, dollar-quoted strings,
// line comments (`-- … \n`) or block comments (`/* … */`).
//
// Used by the no-tx apply path to send each statement in its own
// pgx.Exec call. PostgreSQL's simple-query protocol wraps multi-
// statement Query messages in an implicit transaction; CONCURRENTLY
// statements refuse to run in any transaction (implicit or explicit),
// so the runner must dispatch one statement per round-trip.
//
// The splitter does not validate SQL syntax; it returns whatever the
// caller supplies, trimmed of surrounding whitespace, with empty
// statements (e.g. a file ending in `;\n`) discarded. Trailing
// semicolons are preserved on each returned statement.
func splitSQLStatements(sql string) []string {
	var (
		stmts []string
		b     strings.Builder
	)
	runes := []rune(sql)
	n := len(runes)

	const (
		stateNormal = iota
		stateLineComment
		stateBlockComment
		stateSingleQuote
		stateDoubleQuote
		stateDollarQuote
	)
	state := stateNormal
	dollarTag := "" // set when state == stateDollarQuote; e.g. "$$" or "$body$"

	for i := 0; i < n; i++ {
		r := runes[i]

		switch state {
		case stateLineComment:
			b.WriteRune(r)
			if r == '\n' {
				state = stateNormal
			}
			continue

		case stateBlockComment:
			b.WriteRune(r)
			if r == '*' && i+1 < n && runes[i+1] == '/' {
				b.WriteRune(runes[i+1])
				i++
				state = stateNormal
			}
			continue

		case stateSingleQuote:
			b.WriteRune(r)
			if r == '\'' {
				if i+1 < n && runes[i+1] == '\'' {
					// `''` escaped single-quote inside the literal.
					b.WriteRune(runes[i+1])
					i++
					continue
				}
				state = stateNormal
			}
			continue

		case stateDoubleQuote:
			b.WriteRune(r)
			if r == '"' {
				if i+1 < n && runes[i+1] == '"' {
					b.WriteRune(runes[i+1])
					i++
					continue
				}
				state = stateNormal
			}
			continue

		case stateDollarQuote:
			b.WriteRune(r)
			if r == '$' {
				if tagAt(runes, i, dollarTag) {
					for k := 1; k < len(dollarTag); k++ {
						b.WriteRune(runes[i+k])
					}
					i += len(dollarTag) - 1
					state = stateNormal
					dollarTag = ""
				}
			}
			continue
		}

		// state == stateNormal
		switch {
		case r == '-' && i+1 < n && runes[i+1] == '-':
			b.WriteRune(r)
			b.WriteRune(runes[i+1])
			i++
			state = stateLineComment
		case r == '/' && i+1 < n && runes[i+1] == '*':
			b.WriteRune(r)
			b.WriteRune(runes[i+1])
			i++
			state = stateBlockComment
		case r == '\'':
			b.WriteRune(r)
			state = stateSingleQuote
		case r == '"':
			b.WriteRune(r)
			state = stateDoubleQuote
		case r == '$':
			if tag, ok := readDollarTag(runes, i); ok {
				for k := 0; k < len(tag); k++ {
					b.WriteRune(runes[i+k])
				}
				i += len(tag) - 1
				state = stateDollarQuote
				dollarTag = tag
			} else {
				b.WriteRune(r)
			}
		case r == ';':
			b.WriteRune(r)
			stmt := strings.TrimSpace(b.String())
			if stmt != "" && stmt != ";" {
				stmts = append(stmts, stmt)
			}
			b.Reset()
		default:
			b.WriteRune(r)
		}
	}

	if s := strings.TrimSpace(b.String()); s != "" {
		stmts = append(stmts, s)
	}
	return stmts
}

// readDollarTag matches a `$tag$` opening at runes[i]; tag is empty or
// `[A-Za-z_][A-Za-z0-9_]*`. Returns the full opening including both
// `$` characters (e.g. `$$` or `$body$`) on a successful match.
func readDollarTag(runes []rune, i int) (string, bool) {
	if i >= len(runes) || runes[i] != '$' {
		return "", false
	}
	j := i + 1
	for j < len(runes) {
		r := runes[j]
		if r == '$' {
			return string(runes[i : j+1]), true
		}
		if !(r == '_' ||
			(r >= 'a' && r <= 'z') ||
			(r >= 'A' && r <= 'Z') ||
			(j > i+1 && r >= '0' && r <= '9')) {
			return "", false
		}
		j++
	}
	return "", false
}

// tagAt reports whether runes[i:] starts with tag.
func tagAt(runes []rune, i int, tag string) bool {
	tagRunes := []rune(tag)
	if i+len(tagRunes) > len(runes) {
		return false
	}
	for k, tr := range tagRunes {
		if runes[i+k] != tr {
			return false
		}
	}
	return true
}
