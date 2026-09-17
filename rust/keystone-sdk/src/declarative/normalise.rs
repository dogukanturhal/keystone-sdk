// SPDX-License-Identifier: Apache-2.0

//! SQL canonicalisation machinery for the differ.
//!
//! Ported verbatim (byte-for-byte semantics) from the normalisation helpers
//! in the Go `declarative` differ. These reduce cosmetic differences between
//! what PostgreSQL emits via `pg_get_indexdef` / `pg_get_expr` and what the
//! renderer emits, so identical objects don't look like drift. The functions
//! operate on bytes (Go used `[]byte`/string indexing) — quoted-literal
//! regions are copied verbatim so embedded UTF-8 survives.

#[inline]
fn is_ascii_letter(b: u8) -> bool {
    b.is_ascii_alphabetic()
}

#[inline]
fn is_digit(b: u8) -> bool {
    b.is_ascii_digit()
}

#[inline]
fn is_bare_lower_ident_char(c: u8) -> bool {
    c.is_ascii_lowercase() || c == b'_'
}

#[inline]
fn is_bare_lower_ident_inner(c: u8) -> bool {
    is_bare_lower_ident_char(c) || c.is_ascii_digit()
}

fn finish(v: Vec<u8>) -> String {
    // All transforms only drop/keep whole bytes from valid UTF-8 input,
    // copying multibyte sequences verbatim — so the result is valid UTF-8.
    String::from_utf8(v).expect("normalise produced valid UTF-8")
}

/// Index of the `)` matching the `(` at `start`, respecting `'…'` literals.
fn match_paren(s: &str, start: usize) -> Option<usize> {
    let b = s.as_bytes();
    if start >= b.len() || b[start] != b'(' {
        return None;
    }
    let mut depth = 1i32;
    let mut i = start + 1;
    while i < b.len() {
        let c = b[i];
        if c == b'\'' {
            i += 1;
            while i < b.len() && b[i] != b'\'' {
                i += 1;
            }
            i += 1;
            continue;
        }
        if c == b'(' {
            depth += 1;
        } else if c == b')' {
            depth -= 1;
            if depth == 0 {
                return Some(i);
            }
        }
        i += 1;
    }
    None
}

/// Index of the `]` matching the `[` at `start`, respecting `'…'` literals.
fn match_bracket(s: &str, start: usize) -> Option<usize> {
    let b = s.as_bytes();
    if start >= b.len() || b[start] != b'[' {
        return None;
    }
    let mut depth = 1i32;
    let mut i = start + 1;
    while i < b.len() {
        let c = b[i];
        if c == b'\'' {
            i += 1;
            while i < b.len() && b[i] != b'\'' {
                i += 1;
            }
            i += 1;
            continue;
        }
        if c == b'[' {
            depth += 1;
        } else if c == b']' {
            depth -= 1;
            if depth == 0 {
                return Some(i);
            }
        }
        i += 1;
    }
    None
}

/// Walks BACKWARDS from `end` (a closing bracket) to its matching opener.
fn match_bracket_back(s: &str, end: usize, open: u8, close: u8) -> Option<usize> {
    let b = s.as_bytes();
    if end >= b.len() || b[end] != close {
        return None;
    }
    let mut depth = 1i32;
    let mut in_quote = false;
    let mut i = end as isize - 1;
    while i >= 0 {
        let c = b[i as usize];
        if c == b'\'' {
            in_quote = !in_quote;
        } else if !in_quote {
            if c == close {
                depth += 1;
            } else if c == open {
                depth -= 1;
                if depth == 0 {
                    return Some(i as usize);
                }
            }
        }
        i -= 1;
    }
    None
}

fn is_bare_lower_identifier(s: &str) -> bool {
    let b = s.as_bytes();
    if b.is_empty() {
        return false;
    }
    let first = b[0];
    if !first.is_ascii_lowercase() && first != b'_' {
        return false;
    }
    b[1..]
        .iter()
        .all(|&c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'_')
}

/// Removes double-quote pairs around bare PG identifiers (`[a-z_][a-z0-9_]*`).
fn strip_bare_identifier_quotes(s: &str) -> String {
    let b = s.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(b.len());
    let mut in_single = false;
    let mut i = 0;
    while i < b.len() {
        let c = b[i];
        if c == b'\'' {
            in_single = !in_single;
            out.push(c);
            i += 1;
            continue;
        }
        if c == b'"' && !in_single {
            match s[i + 1..].find('"') {
                None => {
                    out.extend_from_slice(&b[i..]);
                    return finish(out);
                }
                Some(end) => {
                    let ident = &s[i + 1..i + 1 + end];
                    if is_bare_lower_identifier(ident) {
                        out.extend_from_slice(ident.as_bytes());
                    } else {
                        out.push(b'"');
                        out.extend_from_slice(ident.as_bytes());
                        out.push(b'"');
                    }
                    i = i + 1 + end + 1;
                    continue;
                }
            }
        }
        out.push(c);
        i += 1;
    }
    finish(out)
}

/// True when the byte before `i` (skipping whitespace) is `,` or `(`.
fn is_list_element_start(s: &str, i: usize) -> bool {
    let b = s.as_bytes();
    let mut j = i as isize - 1;
    while j >= 0 {
        let c = b[j as usize];
        if c == b' ' || c == b'\t' || c == b'\n' {
            j -= 1;
            continue;
        }
        return c == b',' || c == b'(';
    }
    false
}

/// Strips a single redundant outer paren layer around a function-call
/// expression in an index column list.
fn strip_redundant_expression_parens(s: &str) -> String {
    let b = s.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        let c = b[i];
        if c == b'\'' {
            out.push(c);
            i += 1;
            while i < b.len() && b[i] != b'\'' {
                out.push(b[i]);
                i += 1;
            }
            if i < b.len() {
                out.push(b[i]);
                i += 1;
            }
            continue;
        }
        if c == b'('
            && i + 1 < b.len()
            && is_bare_lower_ident_char(b[i + 1])
            && is_list_element_start(s, i)
        {
            let mut j = i + 1;
            while j < b.len() && is_bare_lower_ident_inner(b[j]) {
                j += 1;
            }
            let mut k = j;
            while k < b.len() && b[k] == b' ' {
                k += 1;
            }
            if k < b.len() && b[k] == b'(' {
                if let Some(closing) = match_paren(s, k) {
                    if closing + 1 < b.len() && b[closing + 1] == b')' {
                        out.extend_from_slice(&b[i + 1..closing + 1]);
                        i = closing + 2;
                        continue;
                    }
                }
            }
        }
        out.push(c);
        i += 1;
    }
    finish(out)
}

/// Splits an array literal's contents on top-level commas (paren/bracket/
/// quote aware).
fn split_top_level_array_items(s: &str) -> Vec<&str> {
    let b = s.as_bytes();
    let mut out = Vec::new();
    let (mut paren_depth, mut brack_depth) = (0i32, 0i32);
    let mut start = 0usize;
    let mut i = 0usize;
    while i < b.len() {
        let c = b[i];
        match c {
            b'\'' => {
                i += 1;
                while i < b.len() && b[i] != b'\'' {
                    i += 1;
                }
            }
            b'(' => paren_depth += 1,
            b')' => {
                if paren_depth > 0 {
                    paren_depth -= 1;
                }
            }
            b'[' => brack_depth += 1,
            b']' => {
                if brack_depth > 0 {
                    brack_depth -= 1;
                }
            }
            b',' if paren_depth == 0 && brack_depth == 0 => {
                out.push(&s[start..i]);
                start = i + 1;
            }
            _ => {}
        }
        i += 1;
    }
    if start < b.len() {
        out.push(&s[start..]);
    }
    out
}

/// Canonicalises `(array[…])::T[]` → `array[(…)::T, …]` (PG per-element form).
fn normalise_array_casts(s: &str) -> String {
    let b = s.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        let c = b[i];
        if c == b'\'' {
            out.push(c);
            i += 1;
            while i < b.len() && b[i] != b'\'' {
                out.push(b[i]);
                i += 1;
            }
            if i < b.len() {
                out.push(b[i]);
                i += 1;
            }
            continue;
        }
        if c == b'(' && s[i..].starts_with("(array[") {
            let bracket_open = i + "(array[".len() - 1; // position of `[`
            match match_bracket(s, bracket_open) {
                Some(bracket_close)
                    if bracket_close + 1 < b.len() && b[bracket_close + 1] == b')' =>
                {
                    let outer_close = bracket_close + 1; // `)`
                    if !s[outer_close + 1..].starts_with("::") {
                        out.push(c);
                        i += 1;
                        continue;
                    }
                    let type_start = outer_close + 1 + 2; // skip `::`
                    let mut type_end = type_start;
                    while type_end < b.len() {
                        let ch = b[type_end];
                        if is_bare_lower_ident_inner(ch) || ch == b' ' {
                            type_end += 1;
                            continue;
                        }
                        break;
                    }
                    while type_end > type_start && b[type_end - 1] == b' ' {
                        type_end -= 1;
                    }
                    if type_end >= b.len() - 1 || b[type_end] != b'[' || b[type_end + 1] != b']' {
                        out.push(c);
                        i += 1;
                        continue;
                    }
                    let cast_type = &s[type_start..type_end];
                    let contents = &s[bracket_open + 1..bracket_close];
                    let items = split_top_level_array_items(contents);
                    out.extend_from_slice(b"array[");
                    for (j, item) in items.iter().enumerate() {
                        if j > 0 {
                            out.extend_from_slice(b", ");
                        }
                        let item = item.trim();
                        out.push(b'(');
                        out.extend_from_slice(item.as_bytes());
                        out.extend_from_slice(b")::");
                        out.extend_from_slice(cast_type.as_bytes());
                    }
                    out.push(b']');
                    i = type_end + 2; // skip `[]`
                    continue;
                }
                _ => {
                    out.push(c);
                    i += 1;
                    continue;
                }
            }
        }
        out.push(c);
        i += 1;
    }
    finish(out)
}

/// Inner expression of a trailing `(…)::text` ending at `end`.
fn scan_back_text_cast(s: &str, end: usize) -> Option<(&str, usize)> {
    const SUFFIX: &str = ")::text";
    if end < SUFFIX.len() || &s[end - SUFFIX.len()..end] != SUFFIX {
        return None;
    }
    let paren_close = end - "::text".len() - 1; // position of `)`
    let paren_open = match_bracket_back(s, paren_close, b'(', b')')?;
    Some((&s[paren_open + 1..paren_close], paren_open))
}

/// Inner expression of a leading `(…)::text` starting at `start`; returns the
/// inner plus the index AFTER `::text`.
fn scan_fwd_text_cast(s: &str, start: usize) -> Option<(&str, usize)> {
    let b = s.as_bytes();
    if start >= b.len() || b[start] != b'(' {
        return None;
    }
    let paren_close = match_paren(s, start)?;
    const SUFFIX: &str = "::text";
    let tail_start = paren_close + 1;
    if tail_start + SUFFIX.len() > b.len() || &s[tail_start..tail_start + SUFFIX.len()] != SUFFIX {
        return None;
    }
    Some((&s[start + 1..paren_close], tail_start + SUFFIX.len()))
}

/// Rewrites `(…)::text<op>(…)::text` → `<inner><op><inner>`.
fn strip_text_cast_around_op(s: &str, op: &str) -> String {
    let b = s.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'\'' {
            out.push(b[i]);
            i += 1;
            while i < b.len() && b[i] != b'\'' {
                out.push(b[i]);
                i += 1;
            }
            if i < b.len() {
                out.push(b[i]);
                i += 1;
            }
            continue;
        }
        match s[i..].find(op) {
            None => {
                out.extend_from_slice(&b[i..]);
                break;
            }
            Some(rel) => {
                let op_start = i + rel;
                let lhs = scan_back_text_cast(s, op_start);
                let rhs_start = op_start + op.len();
                let rhs = scan_fwd_text_cast(s, rhs_start);
                match (lhs, rhs) {
                    (Some((linner, lstart)), Some((rinner, rend))) => {
                        out.extend_from_slice(&b[i..lstart]);
                        out.extend_from_slice(linner.as_bytes());
                        out.extend_from_slice(op.as_bytes());
                        out.extend_from_slice(rinner.as_bytes());
                        i = rend;
                    }
                    _ => {
                        out.extend_from_slice(&b[i..op_start + op.len()]);
                        i = op_start + op.len();
                    }
                }
            }
        }
    }
    finish(out)
}

/// Canonicalises PG's varchar `::text` cast distribution around comparisons.
fn strip_varchar_text_cast_equality(s: &str) -> String {
    let ops = [" = ", " <> ", " >= ", " <= ", " < ", " > "];
    let mut out = s.to_string();
    for op in ops {
        out = strip_text_cast_around_op(&out, op);
    }
    out
}

/// Removes the trailing string-type cast chain from bare string literals
/// (`'v'::text` → `'v'`, `'v'::character varying::text` → `'v'`).
///
/// The recognised casts are the interchangeable string types PG emits when it
/// canonicalises a literal against a varchar/text/bpchar column: `::text`,
/// `::character varying`, `::varchar`, `::bpchar`. All are value-preserving for
/// a string literal, so stripping them for equality never changes meaning.
/// Longest tokens are matched first so `::character varying` is never mistaken
/// for a bare `::character`.
///
/// Does not touch column-side casts (`(col)::text`) — those belong to
/// [`strip_varchar_text_cast_equality`] and [`strip_bareword_text_cast`].
fn strip_text_cast_from_literal(s: &str) -> String {
    // Longest-first so `::character varying` wins over any prefix of itself.
    const SUFFIXES: [&str; 4] = ["::character varying", "::bpchar", "::varchar", "::text"];
    let b = s.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] != b'\'' {
            out.push(b[i]);
            i += 1;
            continue;
        }
        let mut j = i + 1;
        while j < b.len() && b[j] != b'\'' {
            j += 1;
        }
        if j >= b.len() {
            out.extend_from_slice(&b[i..]);
            return finish(out);
        }
        out.extend_from_slice(&b[i..j + 1]);
        i = j + 1;
        // PG's array-cast distribution can leave a double cast on a literal
        // once its wrapping parens are removed (`'x'::character varying::text`),
        // so strip repeatedly until none remain.
        while let Some(suffix) = SUFFIXES.iter().find(|suf| s[i..].starts_with(**suf)) {
            i += suffix.len();
        }
    }
    finish(out)
}

/// Iteratively removes balanced paren pairs that purely group (recursive).
fn strip_inner_parens(s: &str) -> String {
    let b = s.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        let c = b[i];
        if c == b'\'' {
            out.push(c);
            i += 1;
            while i < b.len() && b[i] != b'\'' {
                out.push(b[i]);
                i += 1;
            }
            if i < b.len() {
                out.push(b[i]);
                i += 1;
            }
            continue;
        }
        if c == b'(' {
            match match_paren(s, i) {
                None => {
                    out.push(c);
                    i += 1;
                    continue;
                }
                Some(close_idx) => {
                    let inner = strip_inner_parens(&s[i + 1..close_idx]);
                    out.extend_from_slice(inner.as_bytes());
                    i = close_idx + 1;
                    continue;
                }
            }
        }
        out.push(c);
        i += 1;
    }
    finish(out)
}

/// Removes `<ident>::text` bareword column-side casts.
fn strip_bareword_text_cast(s: &str) -> String {
    const SUFFIX: &str = "::text";
    let b = s.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        let c = b[i];
        if c == b'\'' {
            out.push(c);
            i += 1;
            while i < b.len() && b[i] != b'\'' {
                out.push(b[i]);
                i += 1;
            }
            if i < b.len() {
                out.push(b[i]);
                i += 1;
            }
            continue;
        }
        if is_ascii_letter(c) || c == b'_' {
            let mut j = i;
            while j < b.len() && (is_ascii_letter(b[j]) || b[j].is_ascii_digit() || b[j] == b'_') {
                j += 1;
            }
            if s[j..].starts_with(SUFFIX) {
                out.extend_from_slice(&b[i..j]);
                i = j + SUFFIX.len();
                continue;
            }
            out.extend_from_slice(&b[i..j]);
            i = j;
            continue;
        }
        out.push(c);
        i += 1;
    }
    finish(out)
}

/// Rewrites PG's canonical membership form
///
/// ```text
/// <lhs> = any (array[items])      // and the paren-less variant:
/// <lhs> = any array[items]
/// ```
///
/// to the authored form `<lhs> in (items)`. PG rewrites every
/// `IN (constant-list)` predicate to `= ANY (ARRAY[…])` at parse time, so a
/// partial-index WHERE / CHECK predicate authored as
/// `status IN ('pending','failed')` is stored — and read back via
/// `pg_get_indexdef` — as `(status)::text = ANY (ARRAY['pending'::…])`. The two
/// are semantically identical for a literal array, so collapsing the ANY-form
/// to the IN-form lets the authored and stored predicates compare equal and
/// stops the differ emitting a perpetual DROP+CREATE INDEX.
///
/// Operates on the lowercased, whitespace-collapsed string and preserves
/// single-quoted literals verbatim. The remaining per-literal casts inside
/// `items` (`'pending'::character varying`) are stripped by the literal-cast
/// pass in [`normalise_where_clause_canonical`].
fn normalise_in_any_array(s: &str) -> String {
    const MARKER: &str = "= any ";
    const ARRAY: &str = "array[";
    let b = s.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(b.len());
    let mut i = 0usize;
    while i < b.len() {
        // Preserve quoted regions verbatim.
        if b[i] == b'\'' {
            out.push(b[i]);
            i += 1;
            while i < b.len() && b[i] != b'\'' {
                out.push(b[i]);
                i += 1;
            }
            if i < b.len() {
                out.push(b[i]);
                i += 1;
            }
            continue;
        }
        if s[i..].starts_with(MARKER) {
            let mut j = i + MARKER.len();
            let had_paren = j < b.len() && b[j] == b'(';
            if had_paren {
                j += 1;
            }
            if s[j..].starts_with(ARRAY) {
                let bracket_open = j + ARRAY.len() - 1; // index of '['
                if let Some(bracket_close) = match_bracket(s, bracket_open) {
                    let mut after = bracket_close + 1;
                    // An opening paren with no matching close means the region
                    // is malformed — leave it untouched rather than guess.
                    let balanced = if had_paren {
                        let ok = after < b.len() && b[after] == b')';
                        if ok {
                            after += 1;
                        }
                        ok
                    } else {
                        true
                    };
                    if balanced {
                        out.extend_from_slice(b"in (");
                        out.extend_from_slice(&b[bracket_open + 1..bracket_close]);
                        out.push(b')');
                        i = after;
                        continue;
                    }
                }
            }
        }
        out.push(b[i]);
        i += 1;
    }
    finish(out)
}

/// Reduces a CREATE INDEX WHERE-clause body to a canonical, cast-stripped,
/// paren-stripped form.
fn normalise_where_clause_canonical(s: &str) -> String {
    const NEEDLE: &str = " where ";
    let idx = match s.find(NEEDLE) {
        Some(i) => i,
        None => return s.to_string(),
    };
    let head = &s[..idx + NEEDLE.len()];
    let mut body = s[idx + NEEDLE.len()..].trim().to_string();

    // (a) strip outer paren layers.
    while body.starts_with('(') {
        match match_paren(&body, 0) {
            Some(close) if close == body.len() - 1 => {
                body = body[1..close].trim().to_string();
            }
            _ => break,
        }
    }
    // (b) strip balanced inner grouping parens. Runs BEFORE the literal-cast
    // strip so a paren-wrapped double cast left by array-cast distribution
    // (`('x'::character varying)::text`) becomes `'x'::character varying::text`
    // — a bare chain the literal stripper can then remove in full. With the two
    // reversed, the inner cast is stripped through the parens, the outer
    // `::text` survives, and the predicate never matches the authored form.
    body = strip_inner_parens(&body);
    // (c) strip the trailing string-type cast chain from bare string literals.
    body = strip_text_cast_from_literal(&body);
    // (d) strip bareword <ident>::text column-side casts.
    body = strip_bareword_text_cast(&body);

    format!("{head}{body}")
}

/// Canonical index-DDL form (lowercase, quote/keyword/cast/paren stripping).
pub(crate) fn normalise_ddl(s: &str) -> String {
    let mut s = s.to_lowercase();
    s = strip_bare_identifier_quotes(&s);
    s = s.split_whitespace().collect::<Vec<_>>().join(" ");
    s = s.replace("create index concurrently ", "create index ");
    s = s.replace("create unique index concurrently ", "create unique index ");
    s = s.replace(" if not exists ", " ");
    s = s.replace(" on only ", " on ");
    s = strip_redundant_expression_parens(&s);
    s = normalise_array_casts(&s);
    // `x IN (a, b)` is rewritten by PG to `x = ANY (ARRAY[a, b])` at parse
    // time, so pg_get_indexdef / pg_get_constraintdef always emit the ANY-form
    // while a hand-authored predicate uses IN. Collapse the ANY-form back to IN
    // before the cast/paren passes so the two compare equal. Runs *after*
    // `normalise_array_casts` has stripped the `(array[…])::t[]` cast wrapper
    // down to a bare `array[…]`.
    s = normalise_in_any_array(&s);
    s = strip_varchar_text_cast_equality(&s);
    s = normalise_where_clause_canonical(&s);
    s
}

/// True when two index DDL strings are equivalent after normalisation.
pub(crate) fn index_ddl_match(observed: &str, rendered: &str) -> bool {
    normalise_ddl(observed) == normalise_ddl(rendered)
}

/// Position past a `::<type>` cast at `i`, or `i` unchanged.
fn skip_type_cast(s: &str, i: usize) -> usize {
    let b = s.as_bytes();
    if i + 1 >= b.len() || b[i] != b':' || b[i + 1] != b':' {
        return i;
    }
    let mut j = i + 2;
    if j >= b.len() || !is_ascii_letter(b[j]) {
        return i;
    }
    while j < b.len() && (is_ascii_letter(b[j]) || is_digit(b[j]) || b[j] == b'_') {
        j += 1;
    }
    if j < b.len() && b[j] == b' ' && j + 1 < b.len() && is_ascii_letter(b[j + 1]) {
        j += 1;
        while j < b.len() && (is_ascii_letter(b[j]) || is_digit(b[j]) || b[j] == b'_') {
            j += 1;
        }
    }
    if j + 1 < b.len() && b[j] == b'[' && b[j + 1] == b']' {
        j += 2;
    }
    j
}

/// Strips PG `::<type>` cast suffixes from literal default expressions.
fn strip_literal_type_casts(s: &str) -> String {
    let b = s.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        let c = b[i];
        if c == b'\'' {
            out.push(c);
            i += 1;
            while i < b.len() {
                if b[i] == b'\'' {
                    if i + 1 < b.len() && b[i + 1] == b'\'' {
                        out.push(b[i]);
                        out.push(b[i + 1]);
                        i += 2;
                        continue;
                    }
                    out.push(b[i]);
                    i += 1;
                    break;
                }
                out.push(b[i]);
                i += 1;
            }
            i = skip_type_cast(s, i);
            continue;
        }
        if is_digit(c) {
            while i < b.len() && (is_digit(b[i]) || b[i] == b'.') {
                out.push(b[i]);
                i += 1;
            }
            i = skip_type_cast(s, i);
            continue;
        }
        out.push(c);
        i += 1;
    }
    finish(out)
}

/// Strips `public.<ident>` → `<ident>` (literals preserved).
fn strip_public_schema_prefix(s: &str) -> String {
    const PREFIX: &str = "public.";
    let b = s.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'\'' {
            out.push(b[i]);
            i += 1;
            while i < b.len() && b[i] != b'\'' {
                out.push(b[i]);
                i += 1;
            }
            if i < b.len() {
                out.push(b[i]);
                i += 1;
            }
            continue;
        }
        if s[i..].starts_with(PREFIX) {
            let rest = &b[i + PREFIX.len()..];
            if !rest.is_empty() && (is_ascii_letter(rest[0]) || rest[0] == b'_') {
                i += PREFIX.len();
                continue;
            }
        }
        out.push(b[i]);
        i += 1;
    }
    finish(out)
}

/// Canonicalises a column-default expression (lowercase, collapse ws, strip
/// literal type casts + `public.` prefix).
fn normalise_default(s: &str) -> String {
    let s = s.trim().to_lowercase();
    let s = s.split_whitespace().collect::<Vec<_>>().join(" ");
    let s = strip_literal_type_casts(&s);
    strip_public_schema_prefix(&s)
}

/// True when two column-default expressions are equivalent under PG storage
/// canonicalisation.
pub(crate) fn defaults_equal(desired: &str, observed: &str) -> bool {
    normalise_default(desired) == normalise_default(observed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalise_ddl_golden() {
        // (input, expected) captured from the Go normaliseDDL.
        let cases: &[(&str, &str)] = &[
            (
                "CREATE INDEX idx_arc_status ON public.access_review_campaigns USING btree (status)",
                "create index idx_arc_status on public.access_review_campaigns using btree (status)",
            ),
            (
                r#"CREATE INDEX "idx_arc_status" ON "public"."access_review_campaigns" USING btree ("status")"#,
                "create index idx_arc_status on public.access_review_campaigns using btree (status)",
            ),
            (
                "CREATE UNIQUE INDEX CONCURRENTLY IF NOT EXISTS idx_u ON public.t USING btree (a)",
                "create unique index idx_u on public.t using btree (a)",
            ),
            (
                "CREATE INDEX i ON ONLY public.parent USING btree (a)",
                "create index i on public.parent using btree (a)",
            ),
            (
                "CREATE INDEX i ON public.t USING btree (a, (coalesce(rule_value, ''::text)), b)",
                "create index i on public.t using btree (a, coalesce(rule_value, ''::text), b)",
            ),
            (
                "CREATE INDEX i ON public.t USING btree (level) WHERE (level)::text = ANY ((ARRAY['high'::character varying, 'critical'::character varying])::text[])",
                "create index i on public.t using btree (level) where level in 'high', 'critical'",
            ),
            (
                "CREATE INDEX i ON public.t USING btree (id) WHERE (resume_at IS NOT NULL)",
                "create index i on public.t using btree (id) where resume_at is not null",
            ),
            (
                "CREATE INDEX i ON public.t USING btree (id) WHERE (((trigger_type)::text = 'schedule'::text) AND (is_active = true) AND (schedule_enabled = true))",
                "create index i on public.t using btree (id) where trigger_type = 'schedule' and is_active = true and schedule_enabled = true",
            ),
            (
                "CREATE INDEX i ON public.t USING btree (id) WHERE ((activation_status)::text = ('pending_deletion'::character varying)::text)",
                "create index i on public.t using btree (id) where activation_status = 'pending_deletion'",
            ),
        ];
        for (input, want) in cases {
            assert_eq!(&normalise_ddl(input), want, "input: {input}");
        }
    }

    #[test]
    fn normalise_default_golden() {
        let cases: &[(&str, &str)] = &[
            ("public.uuid_generate_v4()", "uuid_generate_v4()"),
            ("uuid_generate_v4()", "uuid_generate_v4()"),
            ("''::text", "''"),
            ("'synced'::character varying", "'synced'"),
            ("'{}'::jsonb", "'{}'"),
            ("'{}'::integer[]", "'{}'"),
            ("0::integer", "0"),
            ("1.5::numeric", "1.5"),
            (
                "nextval('public.ord_seq'::regclass)",
                "nextval('public.ord_seq')",
            ),
            ("now()", "now()"),
            ("CURRENT_TIMESTAMP", "current_timestamp"),
        ];
        for (input, want) in cases {
            assert_eq!(&normalise_default(input), want, "input: {input}");
        }
    }

    #[test]
    fn index_ddl_match_golden() {
        assert!(index_ddl_match(
            "CREATE INDEX idx_arc_status ON public.access_review_campaigns USING btree (status)",
            r#"CREATE INDEX "idx_arc_status" ON "public"."access_review_campaigns" USING btree ("status")"#,
        ));
        assert!(index_ddl_match(
            "CREATE INDEX idx_orders_created ON public.orders USING btree (tenant_id, created_at DESC)",
            r#"CREATE INDEX "idx_orders_created" ON "public"."orders" USING btree ("tenant_id", "created_at" DESC)"#,
        ));
        assert!(!index_ddl_match(
            "CREATE INDEX i ON public.t USING btree (a)",
            r#"CREATE INDEX "i" ON "public"."t" USING btree ("b")"#,
        ));
        assert!(index_ddl_match(
            r#"CREATE INDEX "MyIndex" ON public.t USING btree (a)"#,
            r#"CREATE INDEX "myindex" ON "public"."t" USING btree ("a")"#,
        ));
    }

    #[test]
    fn defaults_equal_golden() {
        assert!(defaults_equal(
            "public.uuid_generate_v4()",
            "uuid_generate_v4()"
        ));
        assert!(defaults_equal("''", "''::text"));
        assert!(defaults_equal("'{}'", "'{}'::jsonb"));
        assert!(defaults_equal("now()", "now()"));
        assert!(!defaults_equal("0", "1"));
    }

    #[test]
    fn bare_identifier_helpers() {
        assert!(is_bare_lower_identifier("idx_arc_status"));
        assert!(is_bare_lower_identifier("_underscore_start"));
        assert!(is_bare_lower_identifier("a"));
        assert!(!is_bare_lower_identifier(""));
        assert!(!is_bare_lower_identifier("123_starts_with_digit"));
        assert!(!is_bare_lower_identifier("has-dash"));
        assert!(!is_bare_lower_identifier("MixedCase"));
        assert!(!is_bare_lower_identifier("has space"));
        assert!(!is_bare_lower_identifier("has.dot"));
    }

    #[test]
    fn strip_bare_identifier_quotes_preserves_predicate_literals() {
        let input =
            "where (status)::text = any (array['high'::character varying, 'critical'::character varying])";
        assert_eq!(strip_bare_identifier_quotes(input), input);
    }

    /// Ports go/declarative/normalise_where_canonical_test.go's
    /// `TestNormaliseInAnyArray`. Both differs must plan identical SQL, so the
    /// two case tables are kept literally in sync.
    #[test]
    fn normalise_in_any_array_golden() {
        let cases: &[(&str, &str)] = &[
            // Items preserved verbatim.
            ("status = any (array['a', 'b'])", "status in ('a', 'b')"),
            // Paren-less.
            ("status = any array['a', 'b']", "status in ('a', 'b')"),
            ("kind = any (array[1, 2, 3])", "kind in (1, 2, 3)"),
            // No ANY — unchanged.
            ("x = y", "x = y"),
            // Not an array literal — unchanged.
            ("a = any (foo)", "a = any (foo)"),
            // Inside a literal — preserved.
            ("note = 'x = any array[1]'", "note = 'x = any array[1]'"),
        ];
        for (input, want) in cases {
            // Upstream callers lowercase and strip bare-ident quotes first; the
            // inputs here are already in that shape.
            assert_eq!(&normalise_in_any_array(input), want, "input: {input}");
        }
    }

    /// PG rewrote a hand-authored `status IN ('pending', 'failed')` partial
    /// index into `((status)::text = ANY ((ARRAY[…])::text[]))`. Without
    /// IN/ANY canonicalisation the differ re-emits DROP+CREATE INDEX forever
    /// and the SchemaDefinition never reaches Ready — observed 2026-06-14 on
    /// `marketing.ix_outbox_events_status_next_retry_at`.
    #[test]
    fn partial_index_in_any_array_converges() {
        let rendered = r#"CREATE INDEX CONCURRENTLY IF NOT EXISTS "ix_outbox_events_status_next_retry_at" ON "marketing"."outbox_events" USING btree ("status", "next_retry_at") WHERE status IN ('pending', 'failed')"#;
        let observed = r#"CREATE INDEX ix_outbox_events_status_next_retry_at ON marketing.outbox_events USING btree (status, next_retry_at) WHERE ((status)::text = ANY ((ARRAY['pending'::character varying, 'failed'::character varying])::text[]))"#;
        assert!(
            index_ddl_match(observed, rendered),
            "observed={}\nrendered={}",
            normalise_ddl(observed),
            normalise_ddl(rendered)
        );

        // Integer IN-list: no per-literal casts, no column cast.
        let rendered_int =
            r#"CREATE INDEX "ix_x" ON "s"."t" USING btree ("a") WHERE kind IN (1, 2, 3)"#;
        let observed_int =
            r#"CREATE INDEX ix_x ON s.t USING btree (a) WHERE (kind = ANY (ARRAY[1, 2, 3]))"#;
        assert!(
            index_ddl_match(observed_int, rendered_int),
            "observed={}\nrendered={}",
            normalise_ddl(observed_int),
            normalise_ddl(rendered_int)
        );

        // Negative control: a genuinely different IN-list must NOT match, or the
        // canonicalisation would mask real predicate drift.
        let different = r#"CREATE INDEX "ix" ON "marketing"."outbox_events" USING btree ("status") WHERE status IN ('pending', 'sent')"#;
        let observed_ix = r#"CREATE INDEX ix ON marketing.outbox_events USING btree (status) WHERE ((status)::text = ANY ((ARRAY['pending'::character varying, 'failed'::character varying])::text[]))"#;
        assert!(
            !index_ddl_match(observed_ix, different),
            "different IN-lists must not compare equal"
        );
    }

    /// Ports `TestStripTextCastFromLiteral_VarcharChain`. `::text` alone is not
    /// enough: PG canonicalises a literal against a varchar column as
    /// `'x'::character varying`, and array-cast distribution leaves the double
    /// cast `'x'::character varying::text` behind once the wrapping parens go.
    #[test]
    fn strip_text_cast_from_literal_varchar_chain() {
        let cases: &[(&str, &str)] = &[
            ("col = 'value'::character varying", "col = 'value'"),
            ("col = 'value'::varchar", "col = 'value'"),
            ("col = 'value'::bpchar", "col = 'value'"),
            // Double-cast chain.
            (
                "in ('a'::character varying::text, 'b'::character varying::text)",
                "in ('a', 'b')",
            ),
            // Unchanged behaviour for a plain ::text.
            ("col = 'value'::text", "col = 'value'"),
        ];
        for (input, want) in cases {
            assert_eq!(&strip_text_cast_from_literal(input), want, "input: {input}");
        }
    }
}
