// SPDX-License-Identifier: Apache-2.0

//! Shared analyzer helper(s).

use regex::Regex;

use super::{finding, Finding, LintLevel, Migration};

/// Returns a finding per file *line* whose content matches `re` — the
/// line-granular matcher used by the simple rules (Go `statementMatches`).
pub(crate) fn statement_matches(
    m: &Migration,
    re: &Regex,
    sev: LintLevel,
    rule: &str,
    msg: &str,
) -> Vec<Finding> {
    let mut out = Vec::new();
    for f in &m.files {
        for (i, line) in f.body.split('\n').enumerate() {
            if re.is_match(line) {
                out.push(finding(rule, sev, &f.name, (i + 1) as i32, msg));
            }
        }
    }
    out
}
