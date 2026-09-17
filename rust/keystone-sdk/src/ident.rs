// SPDX-License-Identifier: Apache-2.0

//! PostgreSQL identifier validation + quoting helpers.
//!
//! Ported from the Go `sqlquote` package. The functions are kept
//! intentionally small and stable so consumers can depend on them without
//! taking on the full migration / drift surface.

use std::sync::LazyLock;

use regex::Regex;
use thiserror::Error;

/// Strict SQL-identifier pattern: lowercase letter or underscore, then
/// lowercase alphanumeric or underscore, max 63 bytes (PG NAMEDATALEN-1).
const VALID_IDENTIFIER_PATTERN: &str = r"^[a-z_][a-z0-9_]{0,62}$";

/// Relaxed pattern for PostgreSQL extension names, which follow PG's
/// filesystem-based naming and allow hyphens (e.g. `uuid-ossp`).
const VALID_EXTENSION_PATTERN: &str = r"^[a-z_][a-z0-9_-]{0,62}$";

static VALID_IDENTIFIER: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(VALID_IDENTIFIER_PATTERN).expect("valid identifier regex"));

static VALID_EXTENSION: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(VALID_EXTENSION_PATTERN).expect("valid extension regex"));

/// Error returned by [`validate_identifier`] for a rejected identifier.
///
/// The `Display` form is exactly:
/// `invalid {kind} identifier "{name}": must match {pattern}`
#[derive(Debug, Error, Clone, PartialEq, Eq)]
#[error("invalid {kind} identifier {name:?}: must match {pattern}")]
pub struct IdentError {
    pub kind: String,
    pub name: String,
    pub pattern: String,
}

/// Validates `name` against the SQL-identifier pattern (or the relaxed
/// extension pattern when `kind == "extension"`).
///
/// On failure the error's `Display` reports the literal regex string used.
pub fn validate_identifier(kind: &str, name: &str) -> Result<(), IdentError> {
    let (re, pattern): (&Regex, &str) = if kind == "extension" {
        (&VALID_EXTENSION, VALID_EXTENSION_PATTERN)
    } else {
        (&VALID_IDENTIFIER, VALID_IDENTIFIER_PATTERN)
    };
    if !re.is_match(name) {
        return Err(IdentError {
            kind: kind.to_string(),
            name: name.to_string(),
            pattern: pattern.to_string(),
        });
    }
    Ok(())
}

/// Wraps `name` per PostgreSQL identifier rules: double-quotes around the
/// value with embedded double-quotes doubled.
pub fn quote_identifier(name: &str) -> String {
    format!("\"{}\"", name.replace('"', "\"\""))
}

/// Wraps `s` in PostgreSQL string-literal quoting: single-quote with
/// embedded single-quotes doubled.
pub fn quote_string(s: &str) -> String {
    format!("'{}'", s.replace('\'', "''"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_identifiers_accepted() {
        for name in [
            "public",
            "schema_migrations",
            "hr",
            "a",
            "_private",
            "a1b2c3",
        ] {
            assert!(
                validate_identifier("schema", name).is_ok(),
                "expected {name:?} to be valid"
            );
        }
    }

    #[test]
    fn invalid_identifiers_rejected() {
        let sixty_four = "a".repeat(64);
        for name in [
            "",
            "1startsWithDigit",
            "UPPERCASE",
            "with-hyphen",
            "with space",
            "with;semicolon",
            "\"quoted\"",
            sixty_four.as_str(),
        ] {
            assert!(
                validate_identifier("schema", name).is_err(),
                "expected {name:?} to be invalid"
            );
        }
    }

    #[test]
    fn extension_allows_hyphen() {
        assert!(validate_identifier("extension", "uuid-ossp").is_ok());
        // Other kinds still reject hyphens.
        assert!(validate_identifier("schema", "uuid-ossp").is_err());
    }

    #[test]
    fn error_display_is_exact_strict() {
        let err = validate_identifier("schema", "Bad").unwrap_err();
        assert_eq!(
            err.to_string(),
            r#"invalid schema identifier "Bad": must match ^[a-z_][a-z0-9_]{0,62}$"#
        );
    }

    #[test]
    fn error_display_is_exact_extension() {
        let err = validate_identifier("extension", "BAD").unwrap_err();
        assert_eq!(
            err.to_string(),
            r#"invalid extension identifier "BAD": must match ^[a-z_][a-z0-9_-]{0,62}$"#
        );
    }

    #[test]
    fn quote_identifier_doubles_quotes() {
        assert_eq!(quote_identifier("a\"b"), "\"a\"\"b\"");
        assert_eq!(quote_identifier("public"), "\"public\"");
        assert_eq!(quote_identifier(""), "\"\"");
    }

    #[test]
    fn quote_string_doubles_apostrophes() {
        assert_eq!(quote_string("O'Reilly"), "'O''Reilly'");
        assert_eq!(quote_string(""), "''");
    }
}
