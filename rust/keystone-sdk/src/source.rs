// SPDX-License-Identifier: Apache-2.0

//! In-memory resolved source.
//!
//! [`resolve`] takes the caller's ordered [`SqlFile`] slice, strips any
//! `keystone.sum` entry into the integrity check, and computes the bundle
//! `ContentHash` over the remaining files **in the caller's supplied order**
//! (wire-compat invariant #2 — "per file in supplied order"). This mirrors
//! the reference `toResolvedSource` (the in-memory `keystone.Apply` path) and
//! .NET `ApplyAsync`, both of which preserve caller order. (Only the
//! operator's configmap/OCI resolver — which starts from an unordered map —
//! sorts; that is a separate loader, not this in-memory path.) When a
//! `keystone.sum` was present the integrity status is verified.

use std::collections::BTreeMap;

use crate::hash::content_hash;
use crate::sum::{parse_sum, verify_sum_status, SumFile, SumStatus, SUM_FILENAME};

/// One migration file the SDK ingests.
///
/// `name` is displayed in diagnostics and stored on the tracking row;
/// `body` is the SQL text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SqlFile {
    pub name: String,
    pub body: String,
}

/// The materialised SQL content for a bundle.
#[derive(Debug, Clone)]
pub struct ResolvedSource {
    /// filename → SQL content (lookup map). Excludes [`SUM_FILENAME`].
    /// Iterate via [`ResolvedSource::names`] for the canonical apply order.
    files: BTreeMap<String, String>,
    /// Apply order: the caller's supplied order. Excludes [`SUM_FILENAME`].
    names: Vec<String>,
    /// SHA-256 over `(name ‖ NUL ‖ content ‖ NUL)` for every file in
    /// `names` (caller) order.
    content_hash: String,
    /// Parsed `keystone.sum` when one was present; `None` otherwise.
    integrity_sum: Option<SumFile>,
    /// Classifies the outcome of verifying `files` against `integrity_sum`.
    integrity_status: SumStatus,
}

impl ResolvedSource {
    /// filename → SQL content lookup map (excludes `keystone.sum`).
    pub fn files(&self) -> &BTreeMap<String, String> {
        &self.files
    }

    /// Apply order: the caller's supplied order.
    pub fn names(&self) -> &[String] {
        &self.names
    }

    /// The bundle content hash.
    pub fn content_hash(&self) -> &str {
        &self.content_hash
    }

    /// The parsed integrity sidecar, if present.
    pub fn integrity_sum(&self) -> Option<&SumFile> {
        self.integrity_sum.as_ref()
    }

    /// The integrity verification status.
    pub fn integrity_status(&self) -> SumStatus {
        self.integrity_status
    }
}

/// Resolves the caller's ordered file slice into a [`ResolvedSource`].
///
/// A `keystone.sum` entry, if present, is stripped from `files` and used for
/// the integrity check. The remaining filenames keep the caller's supplied
/// order, and `content_hash` is computed over the files in that order
/// (invariant #2). Mirrors the reference `HashFiles(fileMap, names)`: the
/// hash iterates `names` (caller order), looking up the file body in the map,
/// so a duplicate filename is last-wins on body and hashed once per
/// occurrence.
pub fn resolve(files: Vec<SqlFile>) -> ResolvedSource {
    let mut file_map: BTreeMap<String, String> = BTreeMap::new();
    let mut names: Vec<String> = Vec::new();
    let mut raw_sum: Option<String> = None;

    for f in files {
        if f.name == SUM_FILENAME {
            raw_sum = Some(f.body);
            continue;
        }
        names.push(f.name.clone());
        file_map.insert(f.name, f.body);
    }

    // content_hash over files in caller (`names`) order, last-wins on body
    // lookup — matches the reference HashFiles(fileMap, names).
    let ordered: Vec<SqlFile> = names
        .iter()
        .map(|n| SqlFile {
            name: n.clone(),
            body: file_map[n].clone(),
        })
        .collect();
    let content_hash = content_hash(&ordered);

    // Integrity check.
    let (integrity_sum, integrity_status) = match raw_sum {
        None => (None, SumStatus::Missing),
        Some(raw) => match parse_sum(&raw) {
            Err(_) => (None, SumStatus::Malformed),
            Ok(sum) => {
                let status = verify_sum_status(&file_map, &sum);
                (Some(sum), status)
            }
        },
    };

    ResolvedSource {
        files: file_map,
        names,
        content_hash,
        integrity_sum,
        integrity_status,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::content_hash as ch;
    use crate::sum::{build_sum, marshal_sum};

    fn f(name: &str, body: &str) -> SqlFile {
        SqlFile {
            name: name.to_string(),
            body: body.to_string(),
        }
    }

    #[test]
    fn names_preserve_caller_order_and_sum_stripped() {
        // Caller order is b-then-a; resolve MUST NOT re-sort it.
        let src = resolve(vec![
            f("002_b.sql", "B"),
            f("001_a.sql", "A"),
            f(SUM_FILENAME, "ignored"),
        ]);
        assert_eq!(
            src.names(),
            &["002_b.sql".to_string(), "001_a.sql".to_string()]
        );
        assert!(!src.files().contains_key(SUM_FILENAME));
    }

    #[test]
    fn content_hash_is_over_caller_order() {
        // Hash follows supplied order, NOT lexicographic order.
        let src = resolve(vec![f("b.sql", "beta"), f("a.sql", "alpha")]);
        let expected = ch(&[f("b.sql", "beta"), f("a.sql", "alpha")]);
        assert_eq!(src.content_hash(), expected);
        // And it differs from the sorted-order hash (proves no re-sort).
        let sorted = ch(&[f("a.sql", "alpha"), f("b.sql", "beta")]);
        assert_ne!(src.content_hash(), sorted);
    }

    #[test]
    fn integrity_missing_when_no_sum() {
        let src = resolve(vec![f("a.sql", "alpha")]);
        assert_eq!(src.integrity_status(), SumStatus::Missing);
        assert!(src.integrity_sum().is_none());
    }

    #[test]
    fn integrity_valid_with_correct_sum() {
        let mut m = BTreeMap::new();
        m.insert("a.sql".to_string(), "alpha".to_string());
        m.insert("b.sql".to_string(), "beta".to_string());
        let sum_text = marshal_sum(&build_sum(&m));
        let src = resolve(vec![
            f("a.sql", "alpha"),
            f("b.sql", "beta"),
            f(SUM_FILENAME, &sum_text),
        ]);
        assert_eq!(src.integrity_status(), SumStatus::Valid);
    }

    #[test]
    fn integrity_malformed_with_bad_sum() {
        let src = resolve(vec![f("a.sql", "alpha"), f(SUM_FILENAME, "not a sum")]);
        assert_eq!(src.integrity_status(), SumStatus::Malformed);
    }

    #[test]
    fn integrity_mismatch_with_tampered_content() {
        let mut m = BTreeMap::new();
        m.insert("a.sql".to_string(), "alpha".to_string());
        let sum_text = marshal_sum(&build_sum(&m));
        let src = resolve(vec![f("a.sql", "TAMPERED"), f(SUM_FILENAME, &sum_text)]);
        assert_eq!(src.integrity_status(), SumStatus::Mismatch);
    }
}
