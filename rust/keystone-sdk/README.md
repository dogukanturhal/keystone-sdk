<!-- SPDX-License-Identifier: Apache-2.0 -->
# keystone-sdk (Rust) — wire-compatibility core

A TIER-1 faithful Rust port of the **wire-compatible core** of the Keystone
SDK: the versioned `Apply` pipeline plus the primitives it is built on. It
reproduces the documented behaviour of the Go reference SDK exactly so the
Go, .NET, and Rust SDKs interoperate on the wire.

This crate ships **Apply + primitives + the drift inspector** (`inspect` +
baselines) **+ the native lint pack** (`lint`, 53 rules) **+ the declarative
differ** (`diff`) **+ authoring / schemaspec / schemasource**. A CLI is
**forthcoming**.

## Modules

| Module     | Purpose                                                      |
|------------|-------------------------------------------------------------|
| `hash`     | `content_hash` (one running digest) + `file_hash` (fresh).   |
| `ident`    | identifier validation + `quote_identifier` / `quote_string`.|
| `sqlsplit` | `split_sql_statements` — quote/comment/dollar-quote aware.   |
| `sum`      | `keystone.sum` build / marshal / parse / verify.            |
| `source`   | `resolve` → `ResolvedSource` (caller-order names + hash).   |
| `tracking` | bookkeeping table DDL + read helpers (needs a DB).          |
| `runner`   | the apply engine: TX path + no-tx (`CONCURRENTLY`) path.     |
| `drift`    | `Inspector` → `Snapshot`, `hash` (Go-compatible), baselines. |
| `analyze`  | native lint pack — 53 regex rules, `default_registry`.      |
| `declarative` | `diff(observed, desired)` → `Plan` (fwd+reverse SQL); spec types; SQL normalisation. |
| `authoring` | `render_up_down` → `NNN_name.up/down.sql` bundle; `next_version`. |
| `schemaspec` | `from_snapshot` → `SchemaDefinitionSpec` (inverse of the differ). |
| `schemasource` | `parse_ref` + `resolve_desired` (yaml:// / sql:// / db://); dev-DB normaliser. |
| crate root | `apply` / `inspect` / `lint` / `diff` + public `Snapshot`.  |

## Wire-compatibility invariants

Every Keystone SDK MUST agree byte-for-byte on these:

- **ContentHash / FileHash** — SHA-256 over `(name ‖ 0x00 ‖ body ‖ 0x00)`
  tuples, lowercase hex. `content_hash` streams all files through ONE
  running digest in the caller's order; `file_hash` uses a fresh digest
  per file.
- **Identifier validation** — strict `^[a-z_][a-z0-9_]{0,62}$` (or the
  hyphen-allowing `^[a-z_][a-z0-9_-]{0,62}$` for extensions). The rejection
  error is exactly `invalid {kind} identifier "{name}": must match
  {pattern}`. Quoting doubles embedded `"` / `'`.
- **`keystone.sum`** — line 1 `h1:<root>`, then sorted `<name> h1:<hash>`
  body lines; the root is SHA-256 of the body bytes. Per-file hash =
  `file_hash(name, content)`. Parsing is strict (64 lowercase hex; no
  blanks / dups / unsorted / self-listing).
- **Statement splitting** — a char state machine over
  Normal/LineComment/BlockComment/SingleQuote/DoubleQuote/DollarQuote;
  `''`/`""` escapes; `$$`/`$tag$` dollar-quoting; non-nesting block
  comments; top-level `;` splits with trailing semicolons preserved; a
  leading comment attaches to the following statement.
- **Tracking table DDL + UPSERT** — reproduced character-for-character with
  identifiers quoted.
- **Idempotency / anti-replay** — re-applying `(version, same hash)` is a
  no-op; `(version, different hash)` is refused with the exact reference
  message (em-dash included).

There is **no advisory lock** — the reference SDK deliberately has none, and
this port faithfully omits it.

## Connection model

`apply` and `runner::Runner` borrow a `&mut tokio_postgres::Client`. The
client is **never closed** by this crate — the caller owns its lifecycle.
Pooling is out of scope for the wire-compat core.

## `rows_affected`

`FileResult::rows_affected` mirrors the Go SDK. Migration bodies run via
tokio-postgres `simple_query` (the simple query protocol — it permits
multi-statement files and `CONCURRENTLY`), and every statement reports a
`CommandComplete` row count. The TX path sends the whole file in one
round-trip and reports the **last** statement's count (pgx's `Exec` returns
the final command tag for a multi-statement simple query); the no-tx path
splits the file and **sums** the per-statement counts. The version-recording
UPSERT keeps the extended protocol (`execute`) because it binds parameters.

## Tests

```sh
cargo test                 # default features, NO database required
cargo test --features integration   # needs KEYSTONE_TEST_DATABASE_URL
```

The default test suite covers the hash / ident / sqlsplit / sum / source
golden vectors and the anti-replay refusal-message formatting. DB-dependent
behaviour lives in `tests/integration.rs`, gated behind the `integration`
feature.
