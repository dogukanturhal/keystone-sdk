// SPDX-License-Identifier: Apache-2.0

//! Phase A2 — PG type and schema-declaration conventions. Ported from
//! `rules_types.go`.

use std::sync::LazyLock;

use regex::Regex;

use super::{finding, statement_matches, Analyzer, Finding, LintLevel, Migration};

macro_rules! re {
    ($name:ident, $pat:expr) => {
        static $name: LazyLock<Regex> = LazyLock::new(|| Regex::new($pat).expect($pat));
    };
}

re!(RE_VARCHAR_ANY, r"(?i)\b(VARCHAR|CHARACTER\s+VARYING)\b");
re!(
    RE_VARCHAR_BOUNDED,
    r"(?i)\b(VARCHAR|CHARACTER\s+VARYING)\s*\("
);
re!(RE_JSON_TYPE, r"(?i)\b\w+\s+JSON\b");
re!(
    RE_HAS_COLUMN_DECLARATION,
    r"(?i)\b(CREATE\s+TABLE|ADD\s+COLUMN|ALTER\s+COLUMN)\b"
);
re!(RE_NUMERIC_ANY, r"(?i)\b\w+\s+(NUMERIC|DECIMAL)\b");
re!(RE_NUMERIC_BOUNDED, r"(?i)\b\w+\s+(NUMERIC|DECIMAL)\s*\(");
re!(RE_CREATE_TABLE_STRICT, r"(?i)\bCREATE\s+TABLE\s+(\w+)\b");
re!(
    RE_CREATE_TABLE_IF_NOT_EXISTS,
    r"(?i)\bCREATE\s+TABLE\s+IF\s+NOT\s+EXISTS\b"
);
re!(RE_UUID_V1, r"(?i)\buuid_generate_v1(mc)?\s*\(");

fn has_column_declaration(body: &str) -> bool {
    RE_HAS_COLUMN_DECLARATION.is_match(body)
}

/// no-varchar-without-limit
pub struct NoVarcharWithoutLimit;
impl Analyzer for NoVarcharWithoutLimit {
    fn id(&self) -> &'static str {
        "no-varchar-without-limit"
    }
    fn description(&self) -> &'static str {
        "unbounded VARCHAR has no advantage over TEXT; be explicit"
    }
    fn check(&self, m: &Migration) -> Vec<Finding> {
        let mut out = Vec::new();
        for f in &m.files {
            for (i, line) in f.body.split('\n').enumerate() {
                if !RE_VARCHAR_ANY.is_match(line) {
                    continue;
                }
                let any_count = RE_VARCHAR_ANY.find_iter(line).count();
                let bounded_count = RE_VARCHAR_BOUNDED.find_iter(line).count();
                if bounded_count >= any_count {
                    continue;
                }
                out.push(finding(
                    self.id(),
                    LintLevel::Notice,
                    &f.name,
                    (i + 1) as i32,
                    "unbounded VARCHAR / CHARACTER VARYING has no advantage over TEXT. \
                     Use TEXT when the length is unbounded, VARCHAR(N) when it isn't.",
                ));
            }
        }
        out
    }
}

/// prefer-jsonb-over-json
pub struct PreferJsonbOverJson;
impl Analyzer for PreferJsonbOverJson {
    fn id(&self) -> &'static str {
        "prefer-jsonb-over-json"
    }
    fn description(&self) -> &'static str {
        "use JSONB for indexability and parse-once storage; JSON only for strict round-trip"
    }
    fn check(&self, m: &Migration) -> Vec<Finding> {
        let mut out = Vec::new();
        for f in &m.files {
            if !has_column_declaration(&f.body) {
                continue;
            }
            for (i, line) in f.body.split('\n').enumerate() {
                if !RE_JSON_TYPE.is_match(line) {
                    continue;
                }
                out.push(finding(
                    self.id(),
                    LintLevel::Notice,
                    &f.name,
                    (i + 1) as i32,
                    "column typed as JSON. JSONB is binary-decomposed, indexable \
                     (GIN / path-ops), and parses once at INSERT. JSON preserves \
                     whitespace + key order — useful only for strict byte-round-trip.",
                ));
            }
        }
        out
    }
}

/// no-numeric-without-precision
pub struct NoNumericWithoutPrecision;
impl Analyzer for NoNumericWithoutPrecision {
    fn id(&self) -> &'static str {
        "no-numeric-without-precision"
    }
    fn description(&self) -> &'static str {
        "NUMERIC without precision is arbitrary-digit; declare (p, s) explicitly"
    }
    fn check(&self, m: &Migration) -> Vec<Finding> {
        let mut out = Vec::new();
        for f in &m.files {
            if !has_column_declaration(&f.body) {
                continue;
            }
            for (i, line) in f.body.split('\n').enumerate() {
                if !RE_NUMERIC_ANY.is_match(line) {
                    continue;
                }
                let any_count = RE_NUMERIC_ANY.find_iter(line).count();
                let bounded_count = RE_NUMERIC_BOUNDED.find_iter(line).count();
                if bounded_count >= any_count {
                    continue;
                }
                out.push(finding(
                    self.id(),
                    LintLevel::Notice,
                    &f.name,
                    (i + 1) as i32,
                    "unbounded NUMERIC / DECIMAL stores arbitrary-precision digits — slow, \
                     heavy, and usually wrong. Declare the intended range: \
                     NUMERIC(12, 2) for money, NUMERIC(5, 4) for probabilities, etc.",
                ));
            }
        }
        out
    }
}

/// require-if-not-exists-on-create-table
pub struct RequireIfNotExistsOnCreateTable;
impl Analyzer for RequireIfNotExistsOnCreateTable {
    fn id(&self) -> &'static str {
        "require-if-not-exists-on-create-table"
    }
    fn description(&self) -> &'static str {
        "CREATE TABLE IF NOT EXISTS makes migrations idempotent under retry"
    }
    fn check(&self, m: &Migration) -> Vec<Finding> {
        let mut out = Vec::new();
        for f in &m.files {
            for (i, line) in f.body.split('\n').enumerate() {
                if !RE_CREATE_TABLE_STRICT.is_match(line) {
                    continue;
                }
                if RE_CREATE_TABLE_IF_NOT_EXISTS.is_match(line) {
                    continue;
                }
                out.push(finding(
                    self.id(),
                    LintLevel::Notice,
                    &f.name,
                    (i + 1) as i32,
                    "CREATE TABLE without IF NOT EXISTS. Retries after partial failure \
                     re-run the whole file — add IF NOT EXISTS to make creation idempotent.",
                ));
            }
        }
        out
    }
}

/// no-uuid-generate-v1
pub struct NoUuidGenerateV1;
impl Analyzer for NoUuidGenerateV1 {
    fn id(&self) -> &'static str {
        "no-uuid-generate-v1"
    }
    fn description(&self) -> &'static str {
        "uuid_generate_v1 leaks host MAC + timestamp; use gen_random_uuid()"
    }
    fn check(&self, m: &Migration) -> Vec<Finding> {
        statement_matches(
            m,
            &RE_UUID_V1,
            LintLevel::Warning,
            self.id(),
            "uuid_generate_v1 / v1mc encode host MAC address + timestamp, leaking both \
             in every row's identifier. On PG 13+, gen_random_uuid() produces \
             v4 UUIDs with no leakage and no extension required.",
        )
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
    fn varchar_limit() {
        assert_eq!(NoVarcharWithoutLimit.check(&mig("a VARCHAR")).len(), 1);
        assert_eq!(NoVarcharWithoutLimit.check(&mig("a VARCHAR(20)")).len(), 0);
    }

    #[test]
    fn jsonb_preference_gated_on_ddl() {
        assert_eq!(
            PreferJsonbOverJson
                .check(&mig("CREATE TABLE t (a json);"))
                .len(),
            1
        );
        // JSONB does not match (no word boundary N→B).
        assert_eq!(
            PreferJsonbOverJson
                .check(&mig("CREATE TABLE t (a jsonb);"))
                .len(),
            0
        );
        // Not a DDL context → skipped.
        assert_eq!(
            PreferJsonbOverJson
                .check(&mig("SELECT json_build_object('a', 1);"))
                .len(),
            0
        );
    }

    #[test]
    fn numeric_precision() {
        assert_eq!(
            NoNumericWithoutPrecision
                .check(&mig("CREATE TABLE t (a NUMERIC);"))
                .len(),
            1
        );
        assert_eq!(
            NoNumericWithoutPrecision
                .check(&mig("CREATE TABLE t (a NUMERIC(12,2));"))
                .len(),
            0
        );
    }

    #[test]
    fn create_table_if_not_exists() {
        assert_eq!(
            RequireIfNotExistsOnCreateTable
                .check(&mig("CREATE TABLE t (id int);"))
                .len(),
            1
        );
        assert_eq!(
            RequireIfNotExistsOnCreateTable
                .check(&mig("CREATE TABLE IF NOT EXISTS t (id int);"))
                .len(),
            0
        );
    }

    #[test]
    fn uuid_v1() {
        assert_eq!(
            NoUuidGenerateV1
                .check(&mig("DEFAULT uuid_generate_v1()"))
                .len(),
            1
        );
        assert_eq!(
            NoUuidGenerateV1
                .check(&mig("DEFAULT gen_random_uuid()"))
                .len(),
            0
        );
    }
}
