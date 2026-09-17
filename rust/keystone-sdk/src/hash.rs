// SPDX-License-Identifier: Apache-2.0

//! ContentHash + FileHash primitives.
//!
//! Both hashes are SHA-256 over `(name ‖ 0x00 ‖ body ‖ 0x00)` tuples,
//! lowercase hex. [`content_hash`] streams every file through ONE running
//! digest in the supplied order; [`file_hash`] hashes a single file with a
//! FRESH digest. They deliberately share a mental model so the per-file
//! `keystone.sum` hash and the bundle `ContentHash` agree byte-for-byte.

use sha2::{Digest, Sha256};

use crate::source::SqlFile;

/// Returns the SHA-256 hex over `(name ‖ 0x00 ‖ body ‖ 0x00)` for every
/// file in the provided order, using ONE running digest. Deterministic
/// given a consistent ordering — the caller ([`crate::source::resolve`])
/// preserves the supplied order (invariant #2), mirroring the reference
/// `HashFiles(files, names)`.
pub fn content_hash(files: &[SqlFile]) -> String {
    let mut h = Sha256::new();
    for f in files {
        h.update(f.name.as_bytes());
        h.update([0u8]);
        h.update(f.body.as_bytes());
        h.update([0u8]);
    }
    hex::encode(h.finalize())
}

/// Returns the per-file hash stored in a `keystone.sum` entry: a FRESH
/// SHA-256 over `name ‖ 0x00 ‖ content ‖ 0x00`, lowercase hex.
pub fn file_hash(name: &str, content: &str) -> String {
    let mut h = Sha256::new();
    h.update(name.as_bytes());
    h.update([0u8]);
    h.update(content.as_bytes());
    h.update([0u8]);
    hex::encode(h.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn f(name: &str, body: &str) -> SqlFile {
        SqlFile {
            name: name.to_string(),
            body: body.to_string(),
        }
    }

    #[test]
    fn content_hash_empty_file_golden() {
        // One file with empty name + empty body => digest of
        // (0x00 ‖ 0x00) = SHA-256 of two NUL bytes.
        assert_eq!(
            content_hash(&[f("", "")]),
            "96a296d224f285c67bee93c30f8a309157f0daa35dc5b87e410b78630a09cfc7"
        );
    }

    #[test]
    fn file_hash_golden() {
        assert_eq!(
            file_hash("migrations/001_init.up.sql", "CREATE TABLE t (id int);"),
            "662665dd2588e4710126a3a68923f0932a4a7ebecc8acb21a0876fc461a8d425"
        );
    }

    #[test]
    fn content_hash_order_matters() {
        let forward = content_hash(&[f("a.sql", "alpha"), f("b.sql", "beta")]);
        let reversed = content_hash(&[f("b.sql", "beta"), f("a.sql", "alpha")]);
        assert_ne!(forward, reversed);
    }

    #[test]
    fn content_hash_name_body_not_interchangeable() {
        assert_ne!(content_hash(&[f("a", "b")]), content_hash(&[f("b", "a")]));
    }

    #[test]
    fn outputs_are_lowercase_hex_64() {
        let re = regex::Regex::new(r"^[0-9a-f]{64}$").unwrap();
        assert!(re.is_match(&content_hash(&[f("", "")])));
        assert!(re.is_match(&file_hash("x", "y")));
        assert!(re.is_match(&content_hash(&[f("a.sql", "alpha"), f("b.sql", "beta")])));
    }
}
