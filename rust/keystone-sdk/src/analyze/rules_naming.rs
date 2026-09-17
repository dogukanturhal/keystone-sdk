// SPDX-License-Identifier: Apache-2.0

//! Phase A2 — identifier hygiene. Ported from `rules_naming.go`.

use std::sync::LazyLock;

use regex::Regex;

use super::{finding, line_of_offset, Analyzer, Finding, LintLevel, Migration};

macro_rules! re {
    ($name:ident, $pat:expr) => {
        static $name: LazyLock<Regex> = LazyLock::new(|| Regex::new($pat).expect($pat));
    };
}

re!(
    RE_NAMED_OBJECTS,
    r#"(?i)\b(CREATE\s+(?:UNIQUE\s+)?INDEX(?:\s+CONCURRENTLY)?|CREATE\s+TABLE(?:\s+IF\s+NOT\s+EXISTS)?|CREATE\s+(?:MATERIALIZED\s+)?VIEW|CREATE\s+SEQUENCE|CREATE\s+FUNCTION|ALTER\s+TABLE|CONSTRAINT|REFERENCES)\s+(?:IF\s+NOT\s+EXISTS\s+)?"?([a-zA-Z_][a-zA-Z0-9_]*)"?"#
);
re!(
    RE_PG_PREFIX,
    r#"(?i)\b(CREATE\s+(?:UNIQUE\s+)?INDEX(?:\s+CONCURRENTLY)?|CREATE\s+TABLE|CREATE\s+(?:MATERIALIZED\s+)?VIEW|CREATE\s+SEQUENCE|CREATE\s+FUNCTION|CREATE\s+ROLE|CREATE\s+SCHEMA|ALTER\s+TABLE|CONSTRAINT)\s+(?:IF\s+NOT\s+EXISTS\s+)?"?(pg_\w+)"?"#
);

/// max-identifier-length (default threshold 60)
pub struct MaxIdentifierLength;
impl Analyzer for MaxIdentifierLength {
    fn id(&self) -> &'static str {
        "max-identifier-length"
    }
    fn description(&self) -> &'static str {
        "PostgreSQL truncates identifiers at 63 bytes; warn at 60+"
    }
    fn check(&self, m: &Migration) -> Vec<Finding> {
        const THRESHOLD: usize = 60;
        let mut out = Vec::new();
        for f in &m.files {
            for caps in RE_NAMED_OBJECTS.captures_iter(&f.body) {
                let Some(g) = caps.get(2) else {
                    continue;
                };
                let name = g.as_str();
                if name.len() < THRESHOLD {
                    continue;
                }
                out.push(finding(
                    self.id(),
                    LintLevel::Warning,
                    &f.name,
                    line_of_offset(&f.body, g.start()),
                    format!(
                        "identifier {name} is {} chars; \
                         PostgreSQL truncates at 63 bytes and a truncated suffix can collide \
                         with other objects. Shorten to < {THRESHOLD}.",
                        name.len()
                    ),
                ));
            }
        }
        out
    }
}

/// no-pg-prefix-identifier
pub struct NoPgPrefixIdentifier;
impl Analyzer for NoPgPrefixIdentifier {
    fn id(&self) -> &'static str {
        "no-pg-prefix-identifier"
    }
    fn description(&self) -> &'static str {
        "user objects named `pg_*` collide with system namespace"
    }
    fn check(&self, m: &Migration) -> Vec<Finding> {
        let mut out = Vec::new();
        for f in &m.files {
            for caps in RE_PG_PREFIX.captures_iter(&f.body) {
                let Some(g) = caps.get(2) else {
                    continue;
                };
                let name = g.as_str();
                if !name.to_lowercase().starts_with("pg_") {
                    continue;
                }
                out.push(finding(
                    self.id(),
                    LintLevel::Warning,
                    &f.name,
                    line_of_offset(&f.body, g.start()),
                    format!(
                        "object named {name} uses the reserved `pg_` prefix. \
                         Future PostgreSQL versions may add a system object with the same \
                         name and collide. Rename to a project-specific prefix."
                    ),
                ));
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::super::{FileBody, Migration};
    use super::*;

    fn mig(body: &str) -> Migration {
        Migration {
            files: vec![FileBody {
                name: "001.sql".into(),
                body: body.into(),
            }],
            ..Default::default()
        }
    }

    #[test]
    fn max_identifier_length() {
        let long = "a".repeat(61);
        let f = MaxIdentifierLength.check(&mig(&format!("CREATE TABLE {long} (id int);")));
        assert_eq!(f.len(), 1);
        assert!(f[0].message.contains("61 chars"));
        // 59 chars is fine.
        let ok = "a".repeat(59);
        assert_eq!(
            MaxIdentifierLength
                .check(&mig(&format!("CREATE TABLE {ok} (id int);")))
                .len(),
            0
        );
    }

    #[test]
    fn pg_prefix() {
        assert_eq!(
            NoPgPrefixIdentifier
                .check(&mig("CREATE TABLE pg_secret (id int);"))
                .len(),
            1
        );
        assert_eq!(
            NoPgPrefixIdentifier
                .check(&mig("CREATE TABLE secret (id int);"))
                .len(),
            0
        );
    }
}
