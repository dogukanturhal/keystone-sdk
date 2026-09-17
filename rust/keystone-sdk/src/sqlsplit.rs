// SPDX-License-Identifier: Apache-2.0

//! Split a SQL script into individual statements on top-level semicolons.
//!
//! Ported faithfully from the Go `splitSQLStatements` / `readDollarTag` /
//! `tagAt`. Semicolons inside single-quoted strings, double-quoted
//! identifiers, dollar-quoted strings, line comments (`-- … \n`) or block
//! comments (`/* … */`, non-nesting) are ignored. Each returned statement
//! is trimmed of surrounding whitespace; empty / bare-`;` results are
//! dropped; trailing semicolons are preserved. A leading comment attaches
//! to the FOLLOWING statement.
//!
//! Used by the no-tx apply path to send each statement in its own Exec
//! call: PostgreSQL's simple-query protocol wraps multi-statement messages
//! in an implicit transaction, and `CONCURRENTLY` statements refuse to run
//! in any transaction, so the runner must dispatch one statement per
//! round-trip. The splitter does NOT validate SQL syntax.

#[derive(Clone, Copy, PartialEq, Eq)]
enum State {
    Normal,
    LineComment,
    BlockComment,
    SingleQuote,
    DoubleQuote,
    DollarQuote,
}

/// Splits `sql` into individual statements. See module docs.
pub fn split_sql_statements(sql: &str) -> Vec<String> {
    let runes: Vec<char> = sql.chars().collect();
    let n = runes.len();

    let mut stmts: Vec<String> = Vec::new();
    let mut b = String::new();
    let mut state = State::Normal;
    // Set when state == DollarQuote; e.g. "$$" or "$body$".
    let mut dollar_tag = String::new();

    let mut i = 0usize;
    while i < n {
        let r = runes[i];

        match state {
            State::LineComment => {
                b.push(r);
                if r == '\n' {
                    state = State::Normal;
                }
                i += 1;
                continue;
            }
            State::BlockComment => {
                b.push(r);
                if r == '*' && i + 1 < n && runes[i + 1] == '/' {
                    b.push(runes[i + 1]);
                    i += 1;
                    state = State::Normal;
                }
                i += 1;
                continue;
            }
            State::SingleQuote => {
                b.push(r);
                if r == '\'' {
                    if i + 1 < n && runes[i + 1] == '\'' {
                        // `''` escaped single-quote inside the literal.
                        b.push(runes[i + 1]);
                        i += 2;
                        continue;
                    }
                    state = State::Normal;
                }
                i += 1;
                continue;
            }
            State::DoubleQuote => {
                b.push(r);
                if r == '"' {
                    if i + 1 < n && runes[i + 1] == '"' {
                        b.push(runes[i + 1]);
                        i += 2;
                        continue;
                    }
                    state = State::Normal;
                }
                i += 1;
                continue;
            }
            State::DollarQuote => {
                b.push(r);
                if r == '$' && tag_at(&runes, i, &dollar_tag) {
                    let tag_len = dollar_tag.chars().count();
                    for k in 1..tag_len {
                        b.push(runes[i + k]);
                    }
                    i += tag_len - 1;
                    state = State::Normal;
                    dollar_tag.clear();
                }
                i += 1;
                continue;
            }
            State::Normal => {}
        }

        // state == Normal
        if r == '-' && i + 1 < n && runes[i + 1] == '-' {
            b.push(r);
            b.push(runes[i + 1]);
            i += 1;
            state = State::LineComment;
        } else if r == '/' && i + 1 < n && runes[i + 1] == '*' {
            b.push(r);
            b.push(runes[i + 1]);
            i += 1;
            state = State::BlockComment;
        } else if r == '\'' {
            b.push(r);
            state = State::SingleQuote;
        } else if r == '"' {
            b.push(r);
            state = State::DoubleQuote;
        } else if r == '$' {
            if let Some(tag) = read_dollar_tag(&runes, i) {
                let tag_len = tag.chars().count();
                for k in 0..tag_len {
                    b.push(runes[i + k]);
                }
                i += tag_len - 1;
                state = State::DollarQuote;
                dollar_tag = tag;
            } else {
                b.push(r);
            }
        } else if r == ';' {
            b.push(r);
            let stmt = b.trim().to_string();
            if !stmt.is_empty() && stmt != ";" {
                stmts.push(stmt);
            }
            b.clear();
        } else {
            b.push(r);
        }

        i += 1;
    }

    let s = b.trim();
    if !s.is_empty() {
        stmts.push(s.to_string());
    }
    stmts
}

/// Matches a `$tag$` opening at `runes[i]`; tag is empty or
/// `[A-Za-z_][A-Za-z0-9_]*`. Returns the full opening including both `$`
/// characters (e.g. `$$` or `$body$`) on a successful match.
fn read_dollar_tag(runes: &[char], i: usize) -> Option<String> {
    if i >= runes.len() || runes[i] != '$' {
        return None;
    }
    let mut j = i + 1;
    while j < runes.len() {
        let r = runes[j];
        if r == '$' {
            return Some(runes[i..=j].iter().collect());
        }
        let ok = r == '_'
            || r.is_ascii_lowercase()
            || r.is_ascii_uppercase()
            || (j > i + 1 && r.is_ascii_digit());
        if !ok {
            return None;
        }
        j += 1;
    }
    None
}

/// Reports whether `runes[i..]` starts with `tag`.
fn tag_at(runes: &[char], i: usize, tag: &str) -> bool {
    let tag_runes: Vec<char> = tag.chars().collect();
    if i + tag_runes.len() > runes.len() {
        return false;
    }
    for (k, tr) in tag_runes.iter().enumerate() {
        if runes[i + k] != *tr {
            return false;
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn empty_inputs_yield_nothing() {
        assert_eq!(split_sql_statements(""), Vec::<String>::new());
        assert_eq!(split_sql_statements("   \n\t  "), Vec::<String>::new());
        // A bare `;` is dropped (empty statement after trim) — not a Go test
        // case, but the Go splitter behaves identically (`stmt != ";"` guard).
        assert_eq!(split_sql_statements(";"), Vec::<String>::new());
    }

    /// Mirrors the Go `TestSplitSQLStatements` table verbatim (the reference
    /// vectors) so the port is locked to the source of truth case-for-case.
    #[test]
    fn vectors() {
        let cases: &[(&str, &[&str])] = &[
            ("", &[]),
            ("SELECT 1;", &["SELECT 1;"]),
            ("SELECT 1; SELECT 2;", &["SELECT 1;", "SELECT 2;"]),
            (
                "  SELECT 1;\n  SELECT 2;\n  ",
                &["SELECT 1;", "SELECT 2;"],
            ),
            ("SELECT 1", &["SELECT 1"]),
            ("SELECT 'a;b'; SELECT 2;", &["SELECT 'a;b';", "SELECT 2;"]),
            (
                "SELECT 'it''s ok; really'; SELECT 2;",
                &["SELECT 'it''s ok; really';", "SELECT 2;"],
            ),
            (
                "SELECT \"weird;name\" FROM t; SELECT 2;",
                &["SELECT \"weird;name\" FROM t;", "SELECT 2;"],
            ),
            (
                "SELECT 1; -- a; b;\nSELECT 2;",
                &["SELECT 1;", "-- a; b;\nSELECT 2;"],
            ),
            (
                "SELECT 1; /* a; b */ SELECT 2;",
                &["SELECT 1;", "/* a; b */ SELECT 2;"],
            ),
            (
                "DO $$ BEGIN PERFORM 1; END $$; SELECT 2;",
                &["DO $$ BEGIN PERFORM 1; END $$;", "SELECT 2;"],
            ),
            (
                "DO $body$ BEGIN PERFORM 1; END $body$; SELECT 2;",
                &["DO $body$ BEGIN PERFORM 1; END $body$;", "SELECT 2;"],
            ),
            (
                "CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_iam_tenants_plan ON public.iam_tenants (plan);\n\nDROP TABLE IF EXISTS public.iam_refresh_tokens;",
                &[
                    "CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_iam_tenants_plan ON public.iam_tenants (plan);",
                    "DROP TABLE IF EXISTS public.iam_refresh_tokens;",
                ],
            ),
        ];
        for (input, want) in cases {
            assert_eq!(split_sql_statements(input), v(want), "input: {input:?}");
        }
    }
}
