// SPDX-License-Identifier: Apache-2.0

//! `keystonectl` — a CLI peer built on the Rust keystone-sdk.
//!
//! Subcommands: `sum` (compute keystone.sum), `lint` (53-rule analyzer pack),
//! `inspect` (live-schema snapshot JSON), `apply` (versioned migrations), and
//! `diff` (live schema vs a desired-state source). The DB subcommands connect
//! over TLS, honouring the DSN's `sslmode`/`sslrootcert` and defaulting to
//! `verify-full` — see `keystone_sdk::pgconn`.

use std::collections::BTreeMap;
use std::error::Error;
use std::path::Path;
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use keystone_sdk::declarative;
use keystone_sdk::drift::Inspector;
use keystone_sdk::schemasource::{parse_ref, resolve_desired};
use keystone_sdk::sum::{build_sum, marshal_sum, SUM_FILENAME};
use keystone_sdk::{apply, ApplyOptions, SqlFile};
use tokio_postgres::Client;

type CliResult = Result<(), Box<dyn Error>>;

#[derive(Parser)]
#[command(
    name = "keystonectl",
    version,
    about = "Keystone schema-management CLI (Rust SDK)"
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Compute keystone.sum over the files in a directory.
    Sum {
        /// Directory holding the migration files.
        dir: String,
    },
    /// Lint SQL migration files with the native 53-rule analyzer pack.
    Lint {
        /// SQL files to lint.
        files: Vec<String>,
    },
    /// Inspect a live schema and print its structural snapshot as JSON.
    Inspect {
        /// PostgreSQL connection string.
        dsn: String,
        /// Schema to inspect.
        schema: String,
    },
    /// Apply versioned SQL migration files to a schema.
    Apply {
        /// PostgreSQL connection string.
        dsn: String,
        /// Target schema (must already exist).
        schema: String,
        /// Migration version recorded in the tracking table.
        version: String,
        /// SQL files to apply, in order.
        files: Vec<String>,
    },
    /// Diff a live schema against a desired-state source (yaml:// / sql:// /
    /// db:// / path).
    Diff {
        /// PostgreSQL connection string for the OBSERVED (live) schema.
        dsn: String,
        /// Observed schema name (also the target schema for the diff).
        schema: String,
        /// Desired-state source reference.
        desired: String,
        /// Permit DROP statements in the plan.
        #[arg(long)]
        allow_destructive: bool,
    },
}

#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(cli).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            // Print the cause chain, not just the outermost message. A TLS
            // failure surfaces from tokio-postgres as the single line "error
            // performing TLS handshake", which is the same string whether the
            // CA was untrusted, the hostname did not match, or the
            // certificate had expired — three problems with three different
            // fixes. The reason is always in `source()`; only the printing
            // threw it away.
            let mut cause = e.source();
            while let Some(c) = cause {
                eprintln!("  caused by: {c}");
                cause = c.source();
            }
            ExitCode::FAILURE
        }
    }
}

async fn run(cli: Cli) -> CliResult {
    match cli.cmd {
        Cmd::Sum { dir } => cmd_sum(&dir),
        Cmd::Lint { files } => cmd_lint(&files),
        Cmd::Inspect { dsn, schema } => cmd_inspect(&dsn, &schema).await,
        Cmd::Apply {
            dsn,
            schema,
            version,
            files,
        } => cmd_apply(&dsn, &schema, &version, &files).await,
        Cmd::Diff {
            dsn,
            schema,
            desired,
            allow_destructive,
        } => cmd_diff(&dsn, &schema, &desired, allow_destructive).await,
    }
}

fn basename(p: &str) -> String {
    Path::new(p)
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or(p)
        .to_string()
}

/// Connects to `dsn`, negotiating TLS per its `sslmode` (default
/// `verify-full`). The returned client owns the connection; dropping it ends
/// the driver task.
async fn connect(dsn: &str) -> Result<Client, Box<dyn Error>> {
    let (client, _driver) = keystone_sdk::pgconn::connect(dsn).await?;
    Ok(client)
}

fn cmd_sum(dir: &str) -> CliResult {
    let mut files: BTreeMap<String, String> = BTreeMap::new();
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        if !entry.file_type()?.is_file() {
            continue;
        }
        let name = entry.file_name().to_string_lossy().to_string();
        if name == SUM_FILENAME {
            continue;
        }
        files.insert(name, std::fs::read_to_string(entry.path())?);
    }
    if files.is_empty() {
        return Err(format!("no files found in {dir}").into());
    }
    print!("{}", marshal_sum(&build_sum(&files)));
    Ok(())
}

fn cmd_lint(files: &[String]) -> CliResult {
    if files.is_empty() {
        return Err("lint: no files given".into());
    }
    let sql_files: Vec<SqlFile> = files
        .iter()
        .map(|p| {
            Ok::<_, Box<dyn Error>>(SqlFile {
                name: basename(p),
                body: std::fs::read_to_string(p)?,
            })
        })
        .collect::<Result<_, _>>()?;

    let findings = keystone_sdk::lint("", "", &sql_files);
    let mut errors = 0;
    for f in &findings {
        let loc = if f.line > 0 {
            format!("{}:{}", f.file, f.line)
        } else {
            f.file.clone()
        };
        println!("{}\t{}\t{}\t{}", f.severity, loc, f.rule, f.message);
        if f.severity == "error" {
            errors += 1;
        }
    }
    if errors > 0 {
        return Err(format!("lint failed: {errors} error-level finding(s)").into());
    }
    Ok(())
}

async fn cmd_inspect(dsn: &str, schema: &str) -> CliResult {
    let client = connect(dsn).await?;
    let snap = Inspector::new().inspect(&client, schema).await?;
    println!("{}", serde_json::to_string_pretty(&snap)?);
    Ok(())
}

async fn cmd_apply(dsn: &str, schema: &str, version: &str, files: &[String]) -> CliResult {
    if files.is_empty() {
        return Err("apply: no files given".into());
    }
    let sql_files: Vec<SqlFile> = files
        .iter()
        .map(|p| {
            Ok::<_, Box<dyn Error>>(SqlFile {
                name: basename(p),
                body: std::fs::read_to_string(p)?,
            })
        })
        .collect::<Result<_, _>>()?;

    let mut client = connect(dsn).await?;
    let res = apply(
        &mut client,
        ApplyOptions {
            schema: schema.to_string(),
            version: version.to_string(),
            files: sql_files,
            tracking_table: None,
            owner_role: None,
        },
    )
    .await?;

    if res.files.is_empty() {
        println!("version {} already applied (no-op)", res.version);
    } else {
        println!(
            "applied version {} ({} file(s), {} ms); contentHash {}",
            res.version,
            res.files.len(),
            res.total_duration_ms,
            res.content_hash
        );
        for f in &res.files {
            println!("  [{}] {} ({} ms)", f.index, f.file, f.duration_ms);
        }
    }
    Ok(())
}

async fn cmd_diff(dsn: &str, schema: &str, desired: &str, allow_destructive: bool) -> CliResult {
    let mut client = connect(dsn).await?;

    // Observed: the live schema (full snapshot for high-fidelity matching).
    let observed = Inspector::new().inspect(&client, schema).await?;

    // Desired: resolve the source (the live client doubles as the sql:// dev DB).
    let reference = parse_ref(desired)?;
    let mut spec = resolve_desired(&reference, Some(&mut client), schema).await?;
    spec.allow_destructive = allow_destructive;

    match declarative::diff(&observed, &spec) {
        Ok(plan) => {
            print_plan(&plan.statements, &plan.warnings, plan.destructive_ops);
            Ok(())
        }
        Err(declarative::DiffError::DestructiveRefused { count, plan }) => {
            print_plan(&plan.statements, &plan.warnings, plan.destructive_ops);
            Err(format!(
                "{count} destructive operation(s) refused; pass --allow-destructive to permit"
            )
            .into())
        }
    }
}

fn print_plan(statements: &[String], warnings: &[String], destructive: usize) {
    if statements.is_empty() {
        println!("-- no changes: schema matches desired");
    }
    for s in statements {
        // Each statement is bare; terminate for a copy-pasteable script.
        if s.trim_end().ends_with(';') {
            println!("{s}");
        } else {
            println!("{s};");
        }
    }
    for w in warnings {
        eprintln!("warning: {w}");
    }
    if destructive > 0 {
        eprintln!("-- {destructive} destructive operation(s) in this plan");
    }
}
