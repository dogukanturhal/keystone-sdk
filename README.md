# keystone-sdk

Multi-language client SDKs for [Keystone](https://github.com/dogukanturhal/keystone) —
HexxLock's Kubernetes-native PostgreSQL schema-management operator.

This repo carries the Apache-2.0-licensed runtime SDKs that third-party
applications and CI test suites use to apply versioned SQL migrations
without going through the operator. The operator itself
([`hexxlock/keystone`](https://github.com/dogukanturhal/keystone)) is
AGPL-3.0-or-later.

## Languages

| SDK | Path | Status | Released |
|---|---|---|---|
| .NET | [`dotnet/`](./dotnet) | v0.1.0 — `Apply`, `Inspect` | NuGet (internal GitLab Package Registry) |
| Go | [`go/`](./go) | Pending lift-out from operator repo | — |
| Rust | [`rust/`](./rust) | v0.1.0 — `apply`, `inspect`, `lint`, `diff` + authoring/schemaspec/schemasource + `keystonectl` CLI | crates.io (pending) |

The Go SDK currently lives at
`github.com/dogukanturhal/keystone/pkg/sdk/keystone` inside the
operator repo. Moving it here requires extracting the migration runner /
analyzer / inspector / differ packages from the operator's `internal/`
tree — that's deferred. See [`MIGRATION.md`](./MIGRATION.md) for the plan.

## Wire-compat invariants

Both SDKs are wire-compatible with the operator and with each other —
either implementation can apply a bundle the other has already recorded.
The shared invariants:

1. **Tracking-table DDL** is byte-identical (column names, types,
   defaults, comment).
2. **ContentHash** — SHA-256 over `(name‖0x00‖body‖0x00)` per file in
   supplied order, lowercase hex.
3. **Identifier validation** — `^[a-z_][a-z0-9_]{0,62}$`.
4. **`CONCURRENTLY` detection** — case-insensitive word boundary; switches
   to autocommit / per-statement dispatch.
5. **UPSERT on tracking insert** — `ON CONFLICT (version) DO UPDATE SET
   content_hash, duration_ms, applied_at = NOW()`.
6. **Same-version, different-hash refusal** with the same error wording
   ("bump Version to ship changed SQL").

## Versioning + release cadence

- Each language ships independently. .NET tags are `dotnet-vX.Y.Z`; Go
  tags will be `go-vX.Y.Z` once the SDK is lifted in. The first column of
  the per-language CHANGELOGs is the source of truth for what shipped.
- Wire-compat invariants are bumped in lockstep across both SDKs in the
  same merge commit. Any change to the hash algorithm or tracking table
  shape must update both SDKs in one PR.

## License

[Apache License 2.0](./LICENSE).
