# Migration log — Go SDK lift-out

**Status: complete (2026-05-11).**

The Go SDK has moved from
`github.com/dogukanturhal/keystone/pkg/sdk/keystone` (operator repo)
to `github.com/dogukanturhal/keystone-sdk/go/keystone` (this repo)
as part of the v0.1.0 cut.

## What landed

1. **API submodule split.** `keystone/api/v1alpha1` is now a Go
   sub-module at `github.com/dogukanturhal/keystone/api`. This
   prevents a require-cycle between the operator and the SDK while
   keeping CRD types versioned alongside their owning controller.
   Pattern matches `ariga/atlas-operator` and
   `controlplaneio-fluxcd/flux-operator`. See kubebuilder's
   sub-module layout guide for the broader rationale.

2. **SDK lifted to keystone-sdk/go/.** Six public packages:
   - `keystone` (Apache-2.0) — operations client (`Apply`, `Lint`,
     `Inspect`, `Diff`, `Enroll`).
   - `sqlquote` (Apache-2.0) — quote/validation helpers.
   - `migration` (AGPL) — runner, source resolver, OCI ingestion.
   - `analyze` (AGPL) — 52-rule analyzer.
   - `declarative` (AGPL) — schema differ.
   - `drift` (AGPL) — inspector + snapshot store.

3. **Operator imports flipped.** All keystone-operator
   controllers / webhook / devdb / viz / cmd code that previously
   reached into `internal/migration`, `internal/migration/analyze`,
   `internal/migration/declarative`, `internal/drift`, and
   `internal/postgres/quote.go` now import from `keystone-sdk/go/*`
   public paths.

4. **Operator left clean.** The lifted-out source is removed from
   the operator. The deprecation shim originally planned at
   `keystone/pkg/sdk/keystone/` was dropped — there were no external
   Go consumers of that path beyond the operator's own example
   tests, so the tier-1 cleanup was a clean delete rather than a
   shim.

5. **pgroll stays in operator.** The `internal/migration/pgroll`
   engine is operator-only (used only by
   `migrationexecution_controller`) and was kept where it was; it
   was not part of the SDK surface.

## Why this shape

- Public surface mirrors `xataio/pgroll`'s `pkg/{roll,migrations,
  schema,backfill,sql2pgroll}` layout — the operator and CLI
  themselves consume the SDK as building blocks, so a narrow
  Atlas-style operations-only API would have forced a major
  operator refactor for no consumer benefit.
- Dual licensing (Apache public surface + AGPL internals) is
  intentional. See `go/README.md` for the boundary rules.
- API sub-module split is the kubebuilder-endorsed pattern for
  external SDK consumers; both `atlas-operator` and `flux-operator`
  do this.

## Release sequencing

Three coordinated MRs land in this order:

1. **keystone (api split):** branch `feat/split-api-v1alpha1-module`.
   Adds `api/go.mod`, wires `replace` in main `go.mod`. Tagged
   `api/v0.1.0`.
2. **keystone-sdk (Go SDK):** branch `feat/go-sdk-v0.1.0`. Drops
   the `replace` for `keystone/api` after step 1 tags. Tagged
   `go/v0.1.0` (slash, not hyphen — Go's path-suffix rule for
   subdirectory modules; see
   https://go.dev/ref/mod#vcs-version).
3. **keystone (operator imports):** branch
   `feat/import-sdk-from-keystone-sdk`. Drops the local `replace`
   for `keystone-sdk/go` and pins `v0.1.0`.

A single combined MR was an option but the API split is
prerequisite-shaped — it makes more sense as its own discrete
review unit with its own tag, so the SDK's go.mod can pin a real
version rather than living forever on a `replace` directive.
