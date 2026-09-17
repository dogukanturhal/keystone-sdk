# Changelog

This repo ships per-language tags. .NET tags are `dotnet-vX.Y.Z`; Go
tags are `go/vX.Y.Z`; Rust tags are `rust-vX.Y.Z`.

## .NET

### keystone-ef dotnet-v0.3.0 — EF Core provider tool

- New package `keystone-ef`, a `dotnet tool` (`dotnet tool install --local
  keystone-ef`) that prints an EF Core model's desired schema as PostgreSQL
  DDL on stdout. This is the .NET half of Keystone's ORM story: it is
  invoked through the Go SDK's new `exec://` schema source, so
  `keystonectl migrate diff --desired 'exec://dotnet keystone-ef'` authors
  a migration straight from your entities.
- Drives `dotnet ef dbcontext script`, which renders the model bypassing
  migrations entirely, so EF's own design-time DbContext discovery
  (`IDesignTimeDbContextFactory`, host builder, parameterless ctor) is
  reused rather than reimplemented. Needs no database connection.
- Build output and diagnostics are kept on stderr; stdout is always pure
  DDL, so it is safe to capture.
- `--strip-schema <name>` emits schema-relative DDL for Keystone's
  scratch-schema normaliser, removing both the `"app".` qualifier and the
  `DO $EF$ … CREATE SCHEMA app … $EF$;` guard block Npgsql emits (removing
  only the inner statement would leave an empty `IF … THEN`, which
  PL/pgSQL rejects).
- Project-selection flags (`--context`, `--project`, `--startup-project`,
  `--framework`, `--configuration`, `--no-build`) forward to `dotnet ef`.

**Fixed**: `dotnet:publish` packed only `HexxLock.Keystone.Sdk`, so
`HexxLock.Keystone.Sdk.EntityFrameworkCore` — announced in dotnet-v0.2.0
below — never actually reached the package registry. All packable projects
are now packed on the `dotnet-v*` tag.

### HexxLock.Keystone.Sdk.EntityFrameworkCore dotnet-v0.2.0 — EF Core schema-as-code provider

- New package `HexxLock.Keystone.Sdk.EntityFrameworkCore`.
- `KeystoneEf.ExportCreateScript(DbContext, stripSchema?)` — render an EF
  Core model's full CREATE DDL via `GenerateCreateScript` (no DB
  connection) as a Keystone `sql://` schema source.
- `KeystoneEf.WriteCreateScriptAsync(...)` overloads (DbContext or
  `IDesignTimeDbContextFactory<T>`) for "program mode" CI exporters.
- Feeds `keystonectl migrate diff --desired sql://schema.sql` and
  `keystonectl scaffold`, so .NET teams author Keystone migrations from
  their entities. Multi-targets `net8.0` and `net10.0`.

### dotnet-v0.1.0 — initial release

- `Keystone.ApplyAsync(NpgsqlDataSource, ApplyOptions)` — versioned,
  content-hashed SQL migration runner with `schema_migrations`
  bookkeeping.
- `Keystone.InspectAsync(NpgsqlDataSource, string)` — read-only
  structural snapshot (tables, columns, indexes, constraints).
- Wire-compatible with the Go SDK / Keystone operator on
  `schema_migrations` row format and SHA-256 content-hash algorithm.
- Multi-targets `net8.0` and `net10.0`.
- Targets the in-operator Go SDK
  (`github.com/dogukanturhal/keystone/pkg/sdk/keystone`) for
  cross-language interop until the Go SDK is lifted into this repo.

## Go

Tags are `go/vX.Y.Z`.

### Unreleased

- `drift` — `TableShape.RLSForced` records `pg_class.relforcerowsecurity`,
  and `Diff` reports its loss. ENABLE alone exempts the table's owner from
  every policy on the table, so an application connecting as the owning
  role was unconstrained while the snapshot showed RLS on. Because the
  snapshot hash is a digest of the struct, the un-modelled bit meant
  `ALTER TABLE … NO FORCE ROW LEVEL SECURITY` produced an identical hash
  and raised no drift at all. Three-state (`*bool`): absent means the
  snapshot predates the field, not "not forced" — see
  `Snapshot.PredatesRLSForce` / `WithoutRLSForce`, which let a consumer
  prove a moved hash is only the model growing.
- `drift` — policies are compared, not just counted. A policy whose `USING`
  or `WITH CHECK` expression changed under a stable name used to pass
  silently.
- `declarative` — `diffRLS` consults the observed snapshot. Both RLS
  statements are idempotent, so emitting them for every table was correct
  but produced a plan that could never be empty — 172 no-op statements on
  downstream-service's 97-table schema, on a database that already matched its
  declaration exactly. A converged schema now plans to nothing. Unknown
  still emits: a table absent from the snapshot is one this plan is about
  to create, and a nil FORCE bit is a snapshot written before the field
  existed.
- `declarative` — `NO FORCE ROW LEVEL SECURITY` counts as a destructive op.
  It destroys no data, but handing the owning role a blanket exemption from
  every policy on a multi-tenant table is a wider blast radius than most
  DROPs, and it now needs `allowDestructive` plus whatever approval gate
  the SchemaPolicy imposes. `DISABLE ROW LEVEL SECURITY` remains
  unreachable as a forward action — clearing `enableRLS` skips the table
  rather than stripping RLS from a live one.

### go/v0.3.0 — exec:// provider scheme + ORM providers

The ORM integration seam. Keystone stops needing to know anything about
any ORM: a provider program prints DDL, and the existing dev-database
normaliser does the rest.

- `schemasource` — new `exec://<program> <args…>` scheme. Runs a provider
  program and treats its stdout as the desired schema's DDL, flowing
  through the same normaliser as `sql://`. Mirrors Atlas's
  `external_schema`, so existing providers port with a rename.
- `schemasource.Resolver` — capability-gated resolution. `exec://` is
  refused unless `AllowExec` is set, so a reference arriving in a CR spec
  can never become code execution inside the operator. The package-level
  `ResolveDesired` is unchanged and remains exec-free; `Resolver` also
  carries `ExecDir` / `ExecEnv` / `ExecTimeout`.
- `schemasource.SplitProgram` — POSIX-style quote handling that produces
  argv directly. No shell is spawned, so `;`, pipes and redirection are
  not smuggle-able through a reference.
- `orm/gorm` — the GORM model reader, lifted out of the operator's
  `internal/` tree where nothing could import it (relicensed AGPL-3.0 →
  Apache-2.0 with the rest of the SDK). New `ReadDir` walks a package —
  the unit real projects organise models in — merging files in lexical
  order and sorting tables, so provider output is deterministic.
- `cmd/keystone-gorm` — the GORM provider program, honouring the same
  stdout-is-DDL contract as keystone-ef. Renders via `declarative.Diff`
  against an empty snapshot so one code path owns spec→SQL, and emits
  schema-relative DDL.
- `authoring.StripSchemaQualifier` — exported so providers and authored
  migrations share one definition of "schema-relative".

### go/v0.2.0 — schema-source authoring

Adds the building blocks for "scaffold from a database" and "author
migrations from code" (declarative schema-as-code and ORM entities),
mirroring Atlas's dev-database normalisation model.

- `schemaspec.FromSnapshot(*drift.Snapshot, Options)` — converts a live
  schema snapshot into a desired-state `SchemaDefinitionSpec` (moved out
  of keystonectl's main package so the CLI, scaffold, and the loaders
  share one faithful conversion).
- `authoring.RenderUpDown(*declarative.Plan, Options)` /
  `authoring.NextVersion([]string)` — render a diff into a versioned,
  reversible `NNN_name.up.sql` / `.down.sql` bundle pair that satisfies
  the five migration-authoring standards by construction
  (statement_timeout header, leading comment, schema-relative DDL via
  `StripSchema`, IF EXISTS rollbacks, irreversible-op markers).
- `schemasource` — resolve a source reference (`yaml://`, `sql://` /
  `file://`, `db://`) into a desired `SchemaDefinitionSpec`.
  `SnapshotFromDDL` / `SnapshotFromFiles` apply DDL (or replay a
  migration directory) onto a throwaway scratch schema via the
  production `migration.Runner` and inspect it back — the dev-database
  normaliser that lets any ORM that can emit SQL feed Keystone.

### go/v0.1.x — initial lift-out

See git history; `migration`, `drift`, `declarative`, `analyze`,
`sqlquote`, and the `keystone` runtime SDK.

## Rust

Tags are `rust-vX.Y.Z`. Crate: `keystone-sdk` (workspace at `rust/`), plus
the `keystonectl` binary.

### Unreleased

Tracks the Go changes above statement for statement — the two differs are
expected to plan identical SQL, and RLS is the one place where a silent
divergence is a security difference rather than a cosmetic one.

- `drift` — `TableShape::rls_forced` (`Option<bool>`, three-state on the
  wire), `Snapshot::predates_rls_force` / `without_rls_force`, and drift
  findings for a lost FORCE bit. Hash stays byte-compatible with Go's
  `encoding/json` in all three states.
- `drift` — policy expressions are compared rather than counted.
- `declarative` — `diff_rls` consults the observed snapshot, so a converged
  schema plans to nothing, and honours `force_rls`. The field was reaching
  the Rust `DesiredTable` but the differ ignored it: `forceRLS: false`
  planned `FORCE`, the exact opposite of the declaration, and diverged from
  Go.
- `declarative` — `NO FORCE ROW LEVEL SECURITY` counts toward
  `destructive_ops`.

#### TLS — `pgconn`

**Behavioural change:** a DSN that names no `sslmode` now connects with
`verify-full` and fails if the server cannot satisfy it. It previously
connected in cleartext. Add `?sslmode=disable` to keep the old behaviour.

- New `pgconn` module. Both places the Rust side opened a socket —
  `schemasource`'s `db://` and every `keystonectl` DB subcommand — passed
  `NoTls` literally, so the crate had no code path that would ever negotiate
  TLS. Against CloudNativePG, which serves TLS with a per-cluster CA, that
  was an unfixable `error performing TLS handshake`: no connection string
  could work around it, because the client never offered. The Go operator
  has dialled `verify-full` by default since it was written
  (`internal/postgres/pool.go`), so the two halves of the same SDK disagreed
  about whether the wire was encrypted.
- The full libpq `sslmode` ladder, with the distinction that is easiest to
  lose: `require` encrypts but does *not* authenticate, so only `verify-ca`
  and `verify-full` check the chain. `allow` is accepted and negotiated as
  `prefer`. `sslrootcert` takes a PEM bundle path or the literal `system`;
  omitted, the platform trust store is used.
- `verify-ca` is implemented by delegating to the Web PKI verifier and
  forgiving exactly one rejection — the certificate not being valid for the
  requested name. Untrusted issuer, expiry and bad signature still reject.
- The default diverges from libpq's `prefer` deliberately. `prefer` falls
  back to cleartext when the server declines TLS, which means an attacker
  strips encryption by answering "no"; matching the operator's `verify-full`
  makes the safe mode the one you get by saying nothing.
- `keystonectl` prints the error's `source()` chain. Untrusted CA, name
  mismatch and expiry all surface from tokio-postgres as the same single
  line, `error performing TLS handshake` — three problems with three
  different fixes, and the reason was always in the chain that the printing
  discarded.

#### Differ parity with Go

Ten defects where the Rust differ planned different SQL from Go's for the
same inputs. Found by diffing both against the same live database — first a
converged schema, where Rust planned 396 statements (45 destructive) that Go
did not, then against a *nonexistent* schema, which forces a from-scratch
CREATE plan across all 97 tables and is a far stronger signal: 854 lines
differed. Both are now byte-identical, and the converged case plans nothing
on either side.

The parity is not cosmetic. The operator runs the Go differ, `keystonectl`
runs the Rust one, and a schema reconciled by one is expected to read as
converged by the other — otherwise the two fight, each reverting the other's
work on every reconcile.

- `declarative` — extensions were not modelled at all: no
  `SchemaDefinitionSpec::extensions`, no `Snapshot::extensions`, no diff
  phase. `CREATE EXTENSION IF NOT EXISTS "pgcrypto"` was never emitted, so
  every `gen_random_uuid()` default failed 42883 on a fresh database. Now a
  Phase 0a, before any other object, since a column cannot be declared with
  a type an extension has not yet created. Creation only: `DROP EXTENSION`
  is deliberately never authored, because extensions are database-scoped and
  routinely shared by schemas the differ cannot see.
- `declarative` — `DesiredTable` had no `unique_constraints`, so all 45
  guarded `ADD CONSTRAINT … UNIQUE` blocks were missing and uniqueness went
  silently unenforced. serde's container-level `default` meant the YAML
  section was dropped without any error. Emitted with a `pg_constraint`
  existence guard like CHECKs, but with no `NOT VALID` two-phase form —
  PostgreSQL has none for UNIQUE, since it must build the backing index to
  prove uniqueness.
- `declarative` — `render_create_table` predated Go's `render_pk_line`
  refactor. No `primary_key_name`, so an ORM-named primary key
  (EF Core emits `PK_Todos`) silently became PostgreSQL's `<table>_pkey`
  default; and with two inline `primary_key: true` columns and no
  table-level list, the trailing comma was omitted, so the emitted SQL was a
  syntax error on top of the 42P16 it already was. The PK clause is now
  decided once, up front, and the comma and inline-suppression both read off
  it.
- `schemaspec` — no CHECK-constraint projection at all. An adopted schema's
  desired state carried none, so the differ saw every existing CHECK as
  removed and authored a bare `DROP CONSTRAINT` with no matching `ADD`,
  silently deleting data-integrity rules.
- `schemaspec` — constraint-backed indexes were filtered by an
  `ends_with("_pkey")` guess at PostgreSQL's default constraint name. It
  missed every explicitly-named PK and every `*_key` UNIQUE backing index
  (round-tripping those as independent indexes), and would have wrongly
  dropped a hand-written index called `*_pkey`. Now matched against the
  constraint names themselves, which is exact.
- `schemaspec` — identifier lists were split on bare commas and never
  unquoted. `pg_get_constraintdef` quotes anything that is not a bare
  lowercase word, so `PRIMARY KEY ("Id")` produced a column name matching no
  column and the primary key vanished from the desired state; a quoted
  identifier containing a comma was split into two. Splitting is now
  quote-aware, `""` unescapes, and `parse_constraint_cols` takes the *last*
  `)` so a trailing `DEFERRABLE` does not truncate the list.
- `drift` — `ColumnShape` dropped `formatted_type`, `identity` and
  `generated`, so `numeric(12,2)` round-tripped as bare `numeric` and an
  identity column was re-planned as a plain NOT NULL column with no value
  source (23502 on the first insert). `resolve_column_type_shape` prefers
  `format_type(atttypid, atttypmod)` and falls back for older snapshots.
- `drift` — views were read from `information_schema.views`, whose
  definition is raw over-parenthesised ruleutils output; now
  `pg_get_viewdef(oid, true)`, matching Go.
- `declarative::normalise` — `normalise_in_any_array` was missing, so a
  partial index authored as `WHERE status IN ('a','b')` never matched the
  `= ANY (ARRAY[…])` form PostgreSQL rewrites it to and was re-planned on
  every diff.
- `declarative::normalise` — `normalise_where_clause_canonical` ran its
  inner-paren strip *after* the literal-cast strip, and only knew `::text`.
  A predicate left as `('x'::character varying)::text` by array-cast
  distribution therefore kept its outer cast and never matched the authored
  form. The passes are reordered and the cast chain is stripped repeatedly
  over the full string-type set, longest suffix first.

`Snapshot::extensions` is declared between `enums` and `sequences` to match
Go's field order exactly — the canonical JSON that `hash` digests is emitted
in declaration order, so moving it would make the two SDKs hash the same
database differently. Pinned by a golden captured from Go.

### rust-v0.1.0 — initial release

A faithful, full-feature port of the Go SDK, wire-compatible on the
tracking-table DDL, content-hash, identifier rules, `CONCURRENTLY`
detection, UPSERT, and anti-replay refusal. Validated with golden vectors
generated from the Go SDK (hashes, sqlsplit, the 53 analyzer rules, the
drift snapshot hash, and declarative-diff plans) plus live-PostgreSQL
integration tests.

- **Apply** — `apply` / `runner` / `tracking` / `source` / `sum` / `ident`
  / `sqlsplit` / `hash`. Borrows a `&mut tokio_postgres::Client`; TX path +
  no-tx (`CONCURRENTLY`) path; `rows_affected` mirrors pgx.
- **Inspect** — `drift::Inspector` → `Snapshot`, `drift::hash`
  (byte-compatible with Go's `encoding/json`), baselines, snapshot store,
  Snapshot-vs-Snapshot drift findings; public `inspect`.
- **Lint** — `analyze` 53-rule native regex pack; public `lint`.
- **Diff** — `declarative::diff` (forward + reverse SQL, warnings,
  destructive-op gate); spec types; SQL canonicalisation; public `diff`.
- **Author** — `authoring::render_up_down` (versioned up/down bundle),
  `schemaspec::from_snapshot` (inverse of the differ), `schemasource`
  (`yaml://` / `sql://` / `db://` + the dev-database normaliser).
- **CLI** — `keystonectl` with `sum` / `lint` / `inspect` / `apply` /
  `diff` subcommands.
