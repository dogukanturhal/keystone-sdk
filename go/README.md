# Keystone Go SDK

`go.mod` path: `github.com/dogukanturhal/keystone-sdk/go`

This is the Go counterpart to the .NET SDK at `keystone-sdk/dotnet/`. It
exposes the migration runner, declarative differ, drift inspector, and
analyzer pack used by the Keystone operator and CLI, plus a high-level
client for the five top-level operations (Apply, Lint, Inspect, Diff,
Enroll).

## Public packages

| Path | Purpose | License |
|------|---------|---------|
| `keystone` | High-level client: `Apply`, `Lint`, `Inspect`, `Diff`, `Enroll`. Operations-oriented; mirrors the `keystonectl` CLI commands. | Apache-2.0 |
| `sqlquote` | PostgreSQL identifier and literal quoting helpers (`QuoteIdentifier`, `QuoteString`, `ValidateIdentifier`). Stable, narrow surface. | Apache-2.0 |
| `migration` | Migration runner. Reads SQL bundles, applies via pgx pool, records to a tracking table. | AGPL-3.0-or-later |
| `analyze` | 52-rule SQL analyzer pack (the engine behind `keystonectl lint`). | AGPL-3.0-or-later |
| `declarative` | Declarative differ. Computes the operation list to bring a database from observed state to a desired-state CR spec. | AGPL-3.0-or-later |
| `drift` | Drift inspector + snapshot store. Captures observed schema state for diff against expected. | AGPL-3.0-or-later |

## License boundary

The `keystone` and `sqlquote` packages are Apache-2.0. The `migration`,
`analyze`, `declarative`, and `drift` packages are AGPL-3.0-or-later
(matching their upstream origin in the keystone operator).

The `keystone` client transitively imports `migration` / `drift` /
`analyze` / `declarative`, so any consumer linking against `keystone`
inherits the AGPL obligation. If you need an Apache-only redistribution
surface, link only against `sqlquote`, or use the .NET SDK at
`keystone-sdk/dotnet/` (clean-room, wholly Apache-2.0).

See `LICENSE` (Apache-2.0) and `LICENSE-AGPL` (AGPL-3.0-or-later) at
the keystone-sdk repo root.

## Versioning

Tags follow Go's [module path-suffix rule](https://go.dev/ref/mod#vcs-version)
for sub-directory modules: **`go/vX.Y.Z`** — slash, not hyphen
(e.g. `go/v0.1.0`). The Go module proxy resolves
`github.com/dogukanturhal/keystone-sdk/go@vX.Y.Z` by reading the
underlying `go/vX.Y.Z` git tag.

The hyphen-prefix convention used by the .NET SDK (`dotnet-vX.Y.Z`)
does NOT work for Go: the proxy silently returns `unknown revision`
because it's looking for the slash form.

The SDK depends on the keystone API submodule
(`github.com/dogukanturhal/keystone/api`) for CRD types. That
module is tagged separately as `api/vX.Y.Z` from the keystone operator
repo (same slash convention, same reason).

## Local development

When working on both the operator and the SDK simultaneously, use a
sibling checkout layout:

```
~/projects/
├── keystone/         # operator repo (checked out)
└── keystone-sdk/     # this repo (checked out)
    └── go/
```

The operator's `go.mod` carries a `replace` directive pointing at
`../keystone-sdk/go`, so changes are picked up without re-tagging.
Release CI strips the `replace` and pins the published `vX.Y.Z`
(resolved via the underlying `go/vX.Y.Z` git tag).
