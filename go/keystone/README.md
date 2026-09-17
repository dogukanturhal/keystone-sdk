# Keystone SDK

Apache-2.0-licensed Go library exposing Keystone's core
schema-management primitives — analyzer pack, SQL runner,
structural inspector, and declarative differ — for use outside a
Kubernetes cluster.

This is the legitimate integration point for proprietary Go code.
The operator itself (`services/keystone/{cmd,internal,api}`) is
AGPL-3.0-or-later; this package is Apache-2.0 per
[ADR 0001](../../../docs/adrs/0001-agplv3-license.md). See the
`LICENSE-Apache-SDK` file at the repository root for the full text.

## When to use the SDK

- **CI test suites** that spin up a real Postgres via
  `testcontainers-go`, apply your migrations, and assert schema
  shape against the running DB.
- **Dev seeders** that stand up a local Postgres and bootstrap the
  schema without going through Kubernetes.
- **Schema-validation pipelines** that need Keystone's analyzer
  pack but don't want the controller-runtime + kubebuilder surface.

If you want the full Keystone experience — GitOps bundles,
approvals, Plan-Gate-Apply, auto-snapshots — run the operator. The
SDK is a strict subset.

## Quick start

```go
package migrations_test

import (
    "context"
    "testing"

    "github.com/jackc/pgx/v5/pgxpool"
    ks "github.com/dogukanturhal/keystone/pkg/sdk/keystone"
)

func TestMyMigrations(t *testing.T) {
    ctx := context.Background()
    pool := yourPostgresTestHelper(t) // testcontainers, local dev, etc.

    files := []ks.SQLFile{
        {Name: "001_init.up.sql", Body: `
            CREATE TABLE IF NOT EXISTS users (
                id uuid PRIMARY KEY,
                email text NOT NULL
            );
        `},
    }

    // 1. Lint — catches the 52+ common footguns before they hit PG.
    findings, _ := ks.Lint(ctx, "my-app", "v1", files)
    for _, f := range findings {
        if f.Severity == "error" {
            t.Errorf("%s @ %s:%d — %s", f.Rule, f.File, f.Line, f.Message)
        }
    }

    // 2. Apply — idempotent against schema_migrations.
    result, err := ks.Apply(ctx, pool, ks.ApplyOptions{
        Schema:  "public",
        Version: "v1",
        Files:   files,
    })
    if err != nil {
        t.Fatalf("Apply: %v", err)
    }
    t.Logf("applied %s @ %s in %dms",
        result.Version, result.ContentHash, result.TotalDurationMS)

    // 3. Inspect — assert the resulting shape.
    snap, err := ks.Inspect(ctx, pool, "public")
    if err != nil { t.Fatalf("Inspect: %v", err) }
    if len(snap.Tables) == 0 {
        t.Error("no tables found after apply")
    }
}
```

## API surface

| Function | Purpose | Pool? |
|---|---|---|
| `Apply(ctx, pool, opts) (*ApplyResult, error)` | Run versioned SQL files idempotently | yes |
| `Lint(ctx, bundle, version, files) ([]LintFinding, error)` | Run the 52+ analyzer pack | no |
| `Inspect(ctx, pool, schema) (*Snapshot, error)` | Capture structural shape | yes |
| `Diff(observed, desired, opts) (*DiffPlan, error)` | Compute statements to converge | no |

## Stability contract

- **Exported types and functions are v1-stable.** Within a major
  release, we don't rename, retype, or remove public identifiers.
- **Breaking changes are gated** by a major version bump of the
  module.
- **Additive changes** (new fields on option structs, new helpers)
  happen in minor releases.
- **Internal types are not imported.** The SDK shadows `drift.Snapshot`,
  `migration.ApplyResult`, etc. with its own Go types so that
  internal refactors don't break consumers.

## What's not in the SDK

- Any Kubernetes / controller-runtime / kubebuilder code.
- The audit-chain `AuditEntry` ledger (operator-only).
- The approval workflow (operator-only; authored via SchemaPolicy
  CRs).
- The MigrationPlan Plan-Gate-Apply gate (operator-only).
- The pgroll expand/contract engine (operator-only; coupled to
  MigrationExecution lifecycle).

These are load-bearing for the GitOps operator but don't make sense
outside a cluster. If you need them, run the operator.

## Testing

Unit + integration tests live alongside the SDK:

```
# Unit (fast)
GOWORK=off go test ./pkg/sdk/keystone/

# Integration (requires Docker; spins up a real Postgres via testcontainers)
GOWORK=off go test -tags=integration ./pkg/sdk/keystone/
```

## License

Apache-2.0. See `../../LICENSE-Apache-SDK`.
