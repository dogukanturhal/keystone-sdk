// SPDX-License-Identifier: Apache-2.0

//! `keystone.sum` integrity sidecar.
//!
//! Ported from the Go `migration` package's `sum.go`. The sidecar is a
//! small text document committed alongside the `*.sql` files; any edit to
//! any byte changes the root hash, forcing a VCS merge conflict when two
//! branches both add migrations.
//!
//! Canonical serialisation:
//! ```text
//! h1:<hex64>                     ← root hash (sha256 of body bytes)
//! <name-1> h1:<hex64>
//! <name-2> h1:<hex64>
//! ...
//! ```
//! Entries are sorted lexicographically by name. The body is every line
//! after the root line (terminating newlines included); the root hash is
//! SHA-256(body) in hex.

use std::collections::BTreeMap;

use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::hash::file_hash;

/// Well-known file name for a bundle's integrity sum.
pub const SUM_FILENAME: &str = "keystone.sum";

/// Algorithm tag prefixing every hash in `keystone.sum`.
pub const SUM_HASH_PREFIX: &str = "h1:";

/// Outcome of verifying a resolved bundle against its committed
/// `keystone.sum`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SumStatus {
    /// Present, parses cleanly, every per-file + root hash matches.
    Valid,
    /// No `keystone.sum` in the resolved source. Not an error on its own.
    Missing,
    /// Exists but fails to parse. Always an error.
    Malformed,
    /// Parses, but at least one file's hash (or the root) diverges.
    Mismatch,
}

/// One `<name> h1:<hex>` line in a `keystone.sum` document.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SumEntry {
    pub name: String,
    /// Hex-encoded SHA-256 (no `h1:` prefix).
    pub hash: String,
}

/// Parsed representation of a `keystone.sum` document.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SumFile {
    /// Hex-encoded SHA-256 of the body (lines 2..end). Empty in a
    /// zero-value `SumFile`.
    pub root_hash: String,
    /// Entries sorted by name.
    pub entries: Vec<SumEntry>,
}

/// Error returned when a `keystone.sum` document fails to parse.
#[derive(Debug, Clone, Error, PartialEq, Eq)]
#[error("{0}")]
pub struct SumParseError(pub String);

impl SumParseError {
    fn new(msg: impl Into<String>) -> Self {
        SumParseError(msg.into())
    }
}

/// First divergence found between resolved files and a committed
/// `keystone.sum`. Exactly one mismatch is reported per instance.
#[derive(Debug, Clone, Error, PartialEq, Eq)]
pub struct SumMismatch {
    /// One of: `extra`, `missing`, `content`, `root`.
    pub kind: String,
    /// Name of the offending file (empty for `kind == "root"`).
    pub name: String,
    /// Expected / Actual hashes (hex). Empty where not applicable.
    pub expected: String,
    pub actual: String,
}

impl std::fmt::Display for SumMismatch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.kind.as_str() {
            "root" => write!(
                f,
                "sum root hash mismatch: expected {}, computed {}",
                self.expected, self.actual
            ),
            "extra" => write!(
                f,
                "resolved source contains {:?} but keystone.sum does not list it",
                self.name
            ),
            "missing" => write!(
                f,
                "keystone.sum lists {:?} but resolved source does not contain it",
                self.name
            ),
            "content" => write!(
                f,
                "file {:?} content hash mismatch: expected {}, computed {}",
                self.name, self.expected, self.actual
            ),
            _ => write!(f, "sum mismatch ({}) on {:?}", self.kind, self.name),
        }
    }
}

/// Computes the [`SumFile`] for the given files. Names are sorted before
/// hashing. Any file named [`SUM_FILENAME`] is ignored (you don't list
/// `keystone.sum` inside itself).
pub fn build_sum(files: &BTreeMap<String, String>) -> SumFile {
    let entries: Vec<SumEntry> = files
        .iter()
        .filter(|(n, _)| n.as_str() != SUM_FILENAME)
        .map(|(n, c)| SumEntry {
            name: n.clone(),
            hash: file_hash(n, c),
        })
        .collect();
    // BTreeMap iteration is already sorted by name.
    let body = sum_body(&entries);
    let root = Sha256::digest(body.as_bytes());
    SumFile {
        root_hash: hex::encode(root),
        entries,
    }
}

/// Serialises a [`SumFile`] to its canonical string form. The output
/// always ends in a newline.
pub fn marshal_sum(s: &SumFile) -> String {
    let mut out = String::new();
    out.push_str(SUM_HASH_PREFIX);
    out.push_str(&s.root_hash);
    out.push('\n');
    out.push_str(&sum_body(&s.entries));
    out
}

/// Parses a `keystone.sum` document. Tolerant of trailing whitespace and a
/// trailing newline; intolerant of everything else.
pub fn parse_sum(raw: &str) -> Result<SumFile, SumParseError> {
    if raw.is_empty() {
        return Err(SumParseError::new("empty sum file"));
    }
    let trimmed = raw.trim_end_matches('\n');
    let lines: Vec<&str> = trimmed.split('\n').collect();
    if lines.is_empty() {
        return Err(SumParseError::new("empty sum file"));
    }

    // Line 1: root. `h1:<hex64>`.
    let root_line = lines[0].trim();
    let root = root_line.strip_prefix(SUM_HASH_PREFIX).ok_or_else(|| {
        SumParseError::new(format!(
            "line 1: root hash must start with {SUM_HASH_PREFIX:?}"
        ))
    })?;
    validate_hex256(root)
        .map_err(|e| SumParseError::new(format!("line 1: invalid root hash: {e}")))?;

    // Lines 2..end: per-file entries.
    let mut entries: Vec<SumEntry> = Vec::with_capacity(lines.len().saturating_sub(1));
    for (i, line) in lines[1..].iter().enumerate() {
        let ln = i + 2;
        if line.trim().is_empty() {
            return Err(SumParseError::new(format!(
                "line {ln}: blank line not permitted inside sum body"
            )));
        }
        // `<name> h1:<hex64>` — name is everything up to the LAST space.
        let idx = match line.rfind(' ') {
            Some(idx) if idx >= 1 => idx,
            _ => {
                return Err(SumParseError::new(format!(
                    "line {ln}: missing space separator"
                )))
            }
        };
        let name = &line[..idx];
        let hash_tok = line[idx + 1..].trim();
        let h = hash_tok.strip_prefix(SUM_HASH_PREFIX).ok_or_else(|| {
            SumParseError::new(format!(
                "line {ln}: hash must start with {SUM_HASH_PREFIX:?}"
            ))
        })?;
        validate_hex256(h).map_err(|e| SumParseError::new(format!("line {ln}: {e}")))?;
        if name == SUM_FILENAME {
            return Err(SumParseError::new(format!(
                "line {ln}: keystone.sum must not list itself"
            )));
        }
        entries.push(SumEntry {
            name: name.to_string(),
            hash: h.to_string(),
        });
    }

    // Reject duplicate filenames and enforce sorted order.
    for pair in entries.windows(2) {
        let (prev, cur) = (&pair[0], &pair[1]);
        if prev.name == cur.name {
            return Err(SumParseError::new(format!(
                "duplicate entry for {:?}",
                cur.name
            )));
        }
        if prev.name > cur.name {
            return Err(SumParseError::new(format!(
                "entries not sorted: {:?} before {:?}",
                prev.name, cur.name
            )));
        }
    }

    Ok(SumFile {
        root_hash: root.to_string(),
        entries,
    })
}

impl SumFile {
    /// Checks that `root_hash` matches SHA-256 of this file's own body.
    pub fn verify_root(&self) -> Result<(), SumMismatch> {
        let want = Sha256::digest(sum_body(&self.entries).as_bytes());
        let got = hex::encode(want);
        if got != self.root_hash {
            return Err(SumMismatch {
                kind: "root".to_string(),
                name: String::new(),
                expected: self.root_hash.clone(),
                actual: got,
            });
        }
        Ok(())
    }
}

/// Checks resolved content against a parsed [`SumFile`]. Returns
/// `SumStatus::Valid` iff every file's hash matches, the committed set
/// equals the resolved set, and the root hash matches the body.
///
/// On divergence returns the classified status alongside the first
/// [`SumMismatch`].
pub fn verify_sum(files: &BTreeMap<String, String>, sum: &SumFile) -> Result<(), SumMismatch> {
    sum.verify_root()?;

    // Index the sum for O(1) lookups.
    let mut expect: BTreeMap<&str, &str> = BTreeMap::new();
    for e in &sum.entries {
        expect.insert(e.name.as_str(), e.hash.as_str());
    }

    // Pass 1: every resolved file must appear in the sum with a matching
    // per-file hash. Sorted names so errors are deterministic (BTreeMap).
    for (name, content) in files.iter() {
        if name == SUM_FILENAME {
            continue;
        }
        match expect.get(name.as_str()) {
            None => {
                return Err(SumMismatch {
                    kind: "extra".to_string(),
                    name: name.clone(),
                    expected: String::new(),
                    actual: String::new(),
                })
            }
            Some(want) => {
                let got = file_hash(name, content);
                if got != **want {
                    return Err(SumMismatch {
                        kind: "content".to_string(),
                        name: name.clone(),
                        expected: (*want).to_string(),
                        actual: got,
                    });
                }
            }
        }
    }

    // Pass 2: every sum entry must have a matching file.
    for e in &sum.entries {
        if !files.contains_key(&e.name) {
            return Err(SumMismatch {
                kind: "missing".to_string(),
                name: e.name.clone(),
                expected: String::new(),
                actual: String::new(),
            });
        }
    }

    Ok(())
}

/// Verifies `files` against `sum`, classifying the result as a
/// [`SumStatus`]. `Valid` on success, `Mismatch` on any divergence.
pub fn verify_sum_status(files: &BTreeMap<String, String>, sum: &SumFile) -> SumStatus {
    match verify_sum(files, sum) {
        Ok(()) => SumStatus::Valid,
        Err(_) => SumStatus::Mismatch,
    }
}

/// Emits the deterministic byte representation of the entries (sorted by
/// name, one per line, `<name> h1:<hash>\n`). This is what `root_hash`
/// hashes over.
fn sum_body(entries: &[SumEntry]) -> String {
    let mut out = String::new();
    for e in entries {
        out.push_str(&e.name);
        out.push(' ');
        out.push_str(SUM_HASH_PREFIX);
        out.push_str(&e.hash);
        out.push('\n');
    }
    out
}

/// Rejects anything that isn't 64 lowercase hex chars.
fn validate_hex256(s: &str) -> Result<(), String> {
    if s.len() != 64 {
        return Err(format!("expected 64 hex chars, got {}", s.len()));
    }
    for (i, r) in s.chars().enumerate() {
        if !(r.is_ascii_digit() || ('a'..='f').contains(&r)) {
            return Err(format!("invalid hex char {r:?} at position {i}"));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn files() -> BTreeMap<String, String> {
        let mut m = BTreeMap::new();
        m.insert(
            "001_init.up.sql".to_string(),
            "CREATE TABLE t (id int);".to_string(),
        );
        m.insert(
            "002_more.up.sql".to_string(),
            "ALTER TABLE t ADD c int;".to_string(),
        );
        m
    }

    #[test]
    fn round_trip_build_marshal_parse() {
        let f = files();
        let sum = build_sum(&f);
        let marshalled = marshal_sum(&sum);
        let parsed = parse_sum(&marshalled).expect("parse");
        assert_eq!(parsed, sum);
        // Marshalling is idempotent.
        assert_eq!(marshal_sum(&parsed), marshalled);
        assert!(marshalled.ends_with('\n'));
    }

    #[test]
    fn verify_valid() {
        let f = files();
        let sum = build_sum(&f);
        assert_eq!(verify_sum_status(&f, &sum), SumStatus::Valid);
        assert!(verify_sum(&f, &sum).is_ok());
    }

    #[test]
    fn verify_content_mismatch() {
        let f = files();
        let sum = build_sum(&f);
        let mut tampered = f.clone();
        tampered.insert("001_init.up.sql".to_string(), "DROP TABLE t;".to_string());
        let err = verify_sum(&tampered, &sum).unwrap_err();
        assert_eq!(err.kind, "content");
        assert_eq!(err.name, "001_init.up.sql");
        assert_eq!(verify_sum_status(&tampered, &sum), SumStatus::Mismatch);
    }

    #[test]
    fn verify_extra_file() {
        let f = files();
        let sum = build_sum(&f);
        let mut extra = f.clone();
        extra.insert("003_extra.up.sql".to_string(), "SELECT 1;".to_string());
        let err = verify_sum(&extra, &sum).unwrap_err();
        assert_eq!(err.kind, "extra");
        assert_eq!(err.name, "003_extra.up.sql");
    }

    #[test]
    fn verify_missing_file() {
        let f = files();
        let sum = build_sum(&f);
        let mut fewer = f.clone();
        fewer.remove("002_more.up.sql");
        let err = verify_sum(&fewer, &sum).unwrap_err();
        assert_eq!(err.kind, "missing");
        assert_eq!(err.name, "002_more.up.sql");
    }

    #[test]
    fn verify_root_mismatch() {
        let f = files();
        let mut sum = build_sum(&f);
        sum.root_hash = "0".repeat(64);
        let err = verify_sum(&f, &sum).unwrap_err();
        assert_eq!(err.kind, "root");
    }

    #[test]
    fn reject_bad_prefix() {
        let f = files();
        let marshalled = marshal_sum(&build_sum(&f));
        let bad = marshalled.replacen("h1:", "h2:", 1);
        assert!(parse_sum(&bad).is_err());
    }

    #[test]
    fn reject_uppercase_hex() {
        let f = files();
        let marshalled = marshal_sum(&build_sum(&f));
        let bad = marshalled.to_uppercase();
        assert!(parse_sum(&bad).is_err());
    }

    #[test]
    fn reject_duplicate() {
        let body = "a.sql h1:".to_string() + &"0".repeat(64);
        let dup = format!("{body}\n{body}");
        // Root line is bogus but parse fails earlier on dup only after the
        // root parses; supply a syntactically-valid root then dup body.
        let with_root = format!("{}\n{dup}", "h1:".to_string() + &"0".repeat(64));
        // root won't match but parse rejects dup before verifying root.
        let err = parse_sum(&with_root).unwrap_err();
        assert!(err.to_string().contains("duplicate"));
    }

    #[test]
    fn reject_unsorted() {
        let h = "0".repeat(64);
        let doc = format!("h1:{h}\nb.sql h1:{h}\na.sql h1:{h}\n");
        let err = parse_sum(&doc).unwrap_err();
        assert!(err.to_string().contains("not sorted"));
    }

    #[test]
    fn reject_self_listed() {
        let h = "0".repeat(64);
        let doc = format!("h1:{h}\nkeystone.sum h1:{h}\n");
        let err = parse_sum(&doc).unwrap_err();
        assert!(err.to_string().contains("must not list itself"));
    }

    #[test]
    fn reject_blank_body_line() {
        let h = "0".repeat(64);
        let doc = format!("h1:{h}\na.sql h1:{h}\n\nb.sql h1:{h}\n");
        let err = parse_sum(&doc).unwrap_err();
        assert!(err.to_string().contains("blank line"));
    }
}
