// SPDX-License-Identifier: Apache-2.0

//! Statement-verb helpers.
//!
//! Ported from the Go `rules_stmtverb.go`. Many rules trip false positives
//! because a keyword appears lexically inside an unrelated statement (e.g.
//! `TRUNCATE` as a privilege name in a `GRANT` clause). The fix is a
//! statement-boundary + leading-verb gate: split the body into top-level
//! statements (respecting `--`/`/* */` comments, `$tag$…$tag$` dollar
//! quotes, and `'…'` string literals), then identify each statement's
//! leading keyword. All offsets are BYTE offsets, matching Go and the
//! `regex` crate's `Match::start()`.

use std::sync::LazyLock;

use regex::Regex;

/// `--` line comment to end of line.
static RE_SINGLE_LINE_COMMENT: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?m)--[^\n]*").expect("single-line comment regex"));

/// `/* ... */` block comment (non-greedy, spans newlines).
static RE_BLOCK_COMMENT: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?s)/\*.*?\*/").expect("block comment regex"));

/// `'...'` literal allowing `''` as an escaped single quote (spans newlines).
static RE_STRING_LITERAL: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?s)'(?:[^']|'')*'").expect("string literal regex"));

/// Leading SQL keyword of a statement (case-insensitive).
static RE_VERB: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)^\s*([A-Z][A-Z_]+)\b").expect("verb regex"));

fn is_alnum_under(c: u8) -> bool {
    c.is_ascii_alphanumeric() || c == b'_'
}

/// Returns the first byte index of `needle` in `haystack`, or `None`.
fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() {
        return Some(0);
    }
    if needle.len() > haystack.len() {
        return None;
    }
    haystack.windows(needle.len()).position(|w| w == needle)
}

/// Masks `$tag$ ... $tag$` regions (content → spaces, newlines preserved),
/// matching the close tag exactly. Tags may be empty (`$$`) or named.
fn mask_dollar_quotes(dst: &mut [u8], src: &str) {
    let s = src.as_bytes();
    let n = s.len();
    let mut i = 0;
    while i < n {
        if s[i] != b'$' {
            i += 1;
            continue;
        }
        let mut j = i + 1;
        while j < n && is_alnum_under(s[j]) {
            j += 1;
        }
        if j >= n || s[j] != b'$' {
            i += 1;
            continue;
        }
        let tag = &s[i..=j]; // includes both $s
        match find_subslice(&s[j + 1..], tag) {
            None => i += 1, // unterminated — treat as plain $
            Some(close) => {
                let end = j + 1 + close + tag.len();
                for k in i..end.min(dst.len()) {
                    if dst[k] != b'\n' {
                        dst[k] = b' ';
                    }
                }
                i = end;
            }
        }
    }
}

/// Masks all matches of `re` in `src` into `dst` (→ spaces, newlines kept).
fn mask_all(dst: &mut [u8], re: &Regex, src: &str) {
    for mat in re.find_iter(src) {
        for k in mat.start()..mat.end().min(dst.len()) {
            if dst[k] != b'\n' {
                dst[k] = b' ';
            }
        }
    }
}

/// Erases comments, dollar-quoted blocks, and string literals (→ spaces,
/// length + newlines preserved) so statement-boundary detection ignores
/// `;` inside them.
fn strip_comments_and_literals(body: &str) -> Vec<u8> {
    let mut out = body.as_bytes().to_vec();
    mask_dollar_quotes(&mut out, body);
    mask_all(&mut out, &RE_BLOCK_COMMENT, body);
    mask_all(&mut out, &RE_STRING_LITERAL, body);
    mask_all(&mut out, &RE_SINGLE_LINE_COMMENT, body);
    out
}

/// Byte offsets `[start, end)` of each top-level statement (first non-ws
/// char through its terminating `;`). A trailing statement without `;` is
/// returned as one slice.
fn statement_slices(body: &str) -> Vec<(usize, usize)> {
    let masked = strip_comments_and_literals(body);
    let mut out = Vec::new();
    let mut start: Option<usize> = None;
    for (i, &b) in masked.iter().enumerate() {
        if start.is_none() {
            if b == b' ' || b == b'\t' || b == b'\n' || b == b'\r' {
                continue;
            }
            start = Some(i);
        }
        if b == b';' {
            out.push((start.unwrap(), i + 1));
            start = None;
        }
    }
    if let Some(s) = start {
        if s < body.len() {
            out.push((s, body.len()));
        }
    }
    out
}

/// The statement `[start, end)` containing byte offset `at`, or `None`.
fn statement_containing(body: &str, at: usize) -> Option<(usize, usize)> {
    statement_slices(body)
        .into_iter()
        .find(|&(s, e)| at >= s && at < e)
}

/// The upper-cased leading keyword of the statement containing `at`, or the
/// empty string between statements / when no verb leads.
fn statement_verb(body: &str, at: usize) -> String {
    let Some((a, b)) = statement_containing(body, at) else {
        return String::new();
    };
    match RE_VERB.captures(&body[a..b]) {
        Some(c) => c
            .get(1)
            .map(|x| x.as_str().to_uppercase())
            .unwrap_or_default(),
        None => String::new(),
    }
}

/// True when the statement containing `at` has the given leading verb.
pub(crate) fn stmt_verb_is(body: &str, at: usize, verb: &str) -> bool {
    statement_verb(body, at) == verb.to_uppercase()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verb_gate_ignores_grant_clause() {
        let body = "GRANT SELECT, INSERT, UPDATE, DELETE, TRUNCATE ON TABLE t TO app;";
        // The TRUNCATE keyword is inside a GRANT statement.
        let at = body.find("TRUNCATE").unwrap();
        assert!(stmt_verb_is(body, at, "GRANT"));
        assert!(!stmt_verb_is(body, at, "TRUNCATE"));
    }

    #[test]
    fn verb_gate_matches_real_truncate() {
        let body = "TRUNCATE TABLE t;";
        let at = body.find("TRUNCATE").unwrap();
        assert!(stmt_verb_is(body, at, "TRUNCATE"));
    }

    #[test]
    fn semicolon_in_string_literal_does_not_split() {
        let body = "INSERT INTO t VALUES ('a;b'); TRUNCATE t;";
        let at = body.find("TRUNCATE").unwrap();
        assert!(stmt_verb_is(body, at, "TRUNCATE"));
    }

    #[test]
    fn dollar_quote_block_is_masked() {
        let body = "DO $$ BEGIN TRUNCATE t; END $$; SELECT 1;";
        // The TRUNCATE inside the DO block belongs to the DO statement.
        let at = body.find("TRUNCATE").unwrap();
        assert!(stmt_verb_is(body, at, "DO"));
    }
}
