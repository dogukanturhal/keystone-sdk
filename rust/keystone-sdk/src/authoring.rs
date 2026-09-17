// SPDX-License-Identifier: Apache-2.0

//! Renders a [`crate::declarative::Plan`] into a versioned, reversible
//! migration bundle (`NNN_name.up.sql` / `NNN_name.down.sql`).
//!
//! Ported from the Go `authoring` package. Pure — no database, filesystem,
//! or Kubernetes. The forward file applies `plan.statements` in order; the
//! down file replays `plan.reverse_statements` in REVERSE order (rollback
//! unwinds most-recent-first). Irreversible ops (empty reverse) are rendered
//! as explicit comment markers, not silently dropped.

use std::collections::BTreeMap;

use crate::declarative::Plan;
use crate::ident::quote_identifier;

/// Prepended to every rendered file as `SET LOCAL statement_timeout =
/// '<this>';`. 30s fails fast on an accidental non-CONCURRENTLY index build.
pub const DEFAULT_STATEMENT_TIMEOUT: &str = "30s";

/// Controls how a [`Plan`] is rendered into a [`Bundle`].
#[derive(Debug, Clone, Default)]
pub struct Options {
    /// Human-readable change slug (sanitised into the filename).
    pub name: String,
    /// Zero-padded ordinal prefix (e.g. `"002"`). See [`next_version`].
    pub version: String,
    /// Target schema name, recorded in the header (does not affect SQL).
    pub schema: String,
    /// Overrides [`DEFAULT_STATEMENT_TIMEOUT`] when non-empty.
    pub statement_timeout: String,
    /// Provenance string for the header comment.
    pub generated_by: String,
    /// When non-empty, strips the `"<strip_schema>".` qualifier the differ
    /// emits, yielding schema-relative (portable) DDL.
    pub strip_schema: String,
}

/// The rendered file set for a single migration.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Bundle {
    pub version: String,
    pub name: String,
    pub up_file: String,
    pub down_file: String,
    pub up: String,
    pub down: String,
}

impl Bundle {
    /// The bundle as a filename→content map (for writing to disk + feeding
    /// `keystone.sum` regeneration).
    pub fn files(&self) -> BTreeMap<String, String> {
        let mut m = BTreeMap::new();
        m.insert(self.up_file.clone(), self.up.clone());
        m.insert(self.down_file.clone(), self.down.clone());
        m
    }
}

/// One line of a rendered file: a SQL statement (gets a trailing `;`) or a
/// standalone comment (emitted verbatim). Exactly one field is non-empty.
struct Entry {
    sql: String,
    comment: String,
}

fn has_sql(entries: &[Entry]) -> bool {
    entries.iter().any(|e| !e.sql.is_empty())
}

/// Renders `plan` into a [`Bundle`]. `None` yields header-only bodies.
pub fn render_up_down(plan: Option<&Plan>, opts: &Options) -> Bundle {
    let timeout = if opts.statement_timeout.is_empty() {
        DEFAULT_STATEMENT_TIMEOUT
    } else {
        &opts.statement_timeout
    };
    let slug = sanitize_slug(&opts.name);
    let base = if !opts.version.is_empty() && !slug.is_empty() {
        format!("{}_{}", opts.version, slug)
    } else if !slug.is_empty() {
        slug.clone()
    } else {
        opts.version.clone()
    };

    let mut up: Vec<Entry> = Vec::new();
    let mut down: Vec<Entry> = Vec::new();
    if let Some(plan) = plan {
        for s in &plan.statements {
            let s = strip_schema(s, &opts.strip_schema);
            let s = s.trim();
            if !s.is_empty() {
                up.push(Entry {
                    sql: s.to_string(),
                    comment: String::new(),
                });
            }
        }
        // Reverse order: reverse_statements[i] undoes statements[i].
        for i in (0..plan.reverse_statements.len()).rev() {
            let r = strip_schema(&plan.reverse_statements[i], &opts.strip_schema);
            let r = r.trim();
            if r.is_empty() {
                let fwd = if i < plan.statements.len() {
                    first_line(&plan.statements[i])
                } else {
                    String::new()
                };
                down.push(Entry {
                    sql: String::new(),
                    comment: format!("irreversible: no automatic rollback for: {fwd}"),
                });
                continue;
            }
            down.push(Entry {
                sql: r.to_string(),
                comment: String::new(),
            });
        }
    }

    if !has_sql(&down) {
        down.push(Entry {
            sql: "SELECT 'irreversible: see migration notes for the rollback procedure' AS rollback_note".to_string(),
            comment: String::new(),
        });
    }

    Bundle {
        version: opts.version.clone(),
        name: slug.clone(),
        up_file: format!("{base}.up.sql"),
        down_file: format!("{base}.down.sql"),
        up: render_file(opts, &slug, "up", timeout, &up),
        down: render_file(opts, &slug, "down", timeout, &down),
    }
}

/// Returns the next zero-padded ordinal given existing migration names
/// (filenames or bare versions). Reads each leading digit run, takes the
/// max + 1, padded to ≥3 digits (wider if any existing version is). Empty
/// input yields `"001"`.
pub fn next_version(existing: &[String]) -> String {
    let mut max_n = 0u64;
    let mut width = 3usize;
    for e in existing {
        let b = e.rsplit('/').next().unwrap_or(e);
        let digits: String = b.chars().take_while(|c| c.is_ascii_digit()).collect();
        if digits.is_empty() {
            continue;
        }
        let n: u64 = digits.parse().unwrap_or(0);
        if digits.len() > width {
            width = digits.len();
        }
        if n > max_n {
            max_n = n;
        }
    }
    format!("{:0width$}", max_n + 1, width = width)
}

fn render_file(
    opts: &Options,
    slug: &str,
    direction: &str,
    timeout: &str,
    entries: &[Entry],
) -> String {
    let mut sb = String::new();

    let title = if slug.is_empty() { "migration" } else { slug };
    sb.push_str(&format!("-- {title} ({direction})\n"));
    let gen = if opts.generated_by.is_empty() {
        "keystone authoring"
    } else {
        &opts.generated_by
    };
    sb.push_str(&format!(
        "-- generated by {gen} from a declarative schema diff; edit the SchemaDefinition, not this file.\n"
    ));
    if !opts.schema.is_empty() {
        sb.push_str(&format!("-- target schema: {}\n", opts.schema));
    }
    sb.push('\n');

    sb.push_str(&format!("SET LOCAL statement_timeout = '{timeout}';\n"));

    for e in entries {
        sb.push('\n');
        if !e.comment.is_empty() {
            sb.push_str(&format!("-- {}\n", e.comment));
            continue;
        }
        sb.push_str(&e.sql);
        if !e.sql.trim_end_matches([' ', '\t']).ends_with(';') {
            sb.push(';');
        }
        sb.push('\n');
    }
    sb
}

/// Lowercases and replaces any char outside `[a-z0-9_]` with a single
/// underscore (collapsing runs), trimming leading/trailing underscores.
fn sanitize_slug(s: &str) -> String {
    let s = s.trim().to_lowercase();
    let mut out = String::new();
    let mut prev_underscore = false;
    for c in s.chars() {
        if c.is_ascii_lowercase() || c.is_ascii_digit() {
            out.push(c);
            prev_underscore = false;
        } else if !prev_underscore {
            out.push('_');
            prev_underscore = true;
        }
    }
    out.trim_matches('_').to_string()
}

/// Removes the `"<schema>".` qualifier the differ prepends to every object.
fn strip_schema(sql: &str, schema: &str) -> String {
    if schema.is_empty() || sql.is_empty() {
        return sql.to_string();
    }
    sql.replace(&format!("{}.", quote_identifier(schema)), "")
}

fn first_line(s: &str) -> String {
    let s = s.trim();
    match s.find('\n') {
        Some(i) => s[..i].trim().to_string(),
        None => s.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn next_version_cases() {
        assert_eq!(next_version(&[]), "001");
        assert_eq!(
            next_version(&["001_init.up.sql".into(), "002_foo.up.sql".into()]),
            "003"
        );
        assert_eq!(next_version(&["007".into()]), "008");
        // Width widens to match the widest existing version.
        assert_eq!(next_version(&["0001_x.up.sql".into()]), "0002");
        // Non-numeric entries are skipped.
        assert_eq!(
            next_version(&["readme.md".into(), "005_a.sql".into()]),
            "006"
        );
    }

    #[test]
    fn sanitize_slug_cases() {
        assert_eq!(
            sanitize_slug("Add Users Email Index"),
            "add_users_email_index"
        );
        assert_eq!(sanitize_slug("  --weird/Name--  "), "weird_name");
        assert_eq!(sanitize_slug("already_ok"), "already_ok");
    }

    #[test]
    fn render_up_down_basic() {
        let plan = Plan {
            statements: vec![
                "CREATE INDEX CONCURRENTLY IF NOT EXISTS \"app\".\"idx\" ON \"app\".\"t\" USING btree (\"c\")".into(),
                "ALTER TABLE \"app\".\"t\" DROP COLUMN IF EXISTS \"old\"".into(),
            ],
            reverse_statements: vec![
                "DROP INDEX CONCURRENTLY IF EXISTS \"app\".\"idx\"".into(),
                String::new(), // drop column = irreversible
            ],
            warnings: vec![],
            destructive_ops: 1,
        };
        let opts = Options {
            name: "add idx".into(),
            version: "002".into(),
            schema: "app".into(),
            strip_schema: "app".into(),
            generated_by: "keystonectl v0.2.0".into(),
            ..Default::default()
        };
        let b = render_up_down(Some(&plan), &opts);
        assert_eq!(b.up_file, "002_add_idx.up.sql");
        assert_eq!(b.down_file, "002_add_idx.down.sql");

        // Up: header + timeout + 2 statements, schema-stripped, terminated.
        assert!(b.up.starts_with("-- add_idx (up)\n"));
        assert!(b
            .up
            .contains("-- generated by keystonectl v0.2.0 from a declarative schema diff"));
        assert!(b.up.contains("-- target schema: app\n"));
        assert!(b.up.contains("SET LOCAL statement_timeout = '30s';\n"));
        assert!(b.up.contains(
            "CREATE INDEX CONCURRENTLY IF NOT EXISTS \"idx\" ON \"t\" USING btree (\"c\");\n"
        ));
        assert!(b
            .up
            .contains("ALTER TABLE \"t\" DROP COLUMN IF EXISTS \"old\";\n"));
        assert!(!b.up.contains("\"app\"."));

        // Down: reverse order — the DROP COLUMN's irreversible marker comes
        // first (it's the last forward op), then the index drop.
        let irr = b.down.find("-- irreversible: no automatic rollback for: ALTER TABLE \"app\".\"t\" DROP COLUMN IF EXISTS \"old\"").unwrap();
        let dropidx = b
            .down
            .find("DROP INDEX CONCURRENTLY IF EXISTS \"idx\";")
            .unwrap();
        assert!(
            irr < dropidx,
            "irreversible marker should precede the index drop"
        );
    }

    #[test]
    fn render_empty_plan_has_rollback_note() {
        let b = render_up_down(
            None,
            &Options {
                name: "noop".into(),
                version: "001".into(),
                ..Default::default()
            },
        );
        assert!(b.down.contains("rollback_note"));
        assert!(b.up.contains("SET LOCAL statement_timeout = '30s';"));
    }
}
