# HexxLock.Keystone.Sdk

Apache-2.0-licensed .NET runtime SDK for Keystone — apply versioned SQL
migrations against PostgreSQL with content-hash anti-replay,
`schema_migrations` tracking, and PostgreSQL-`CONCURRENTLY`-aware no-tx
fallback.

Wire-compatible with the Go SDK at
[`pkg/sdk/keystone`](../../pkg/sdk/keystone) and the Keystone operator —
either implementation can apply a bundle the other has already recorded.
The per-version content hash is the shared anti-replay token.

The operator itself (`internal/`, `cmd/manager/`, CRDs) is
AGPL-3.0-or-later; this package is Apache-2.0 per
[ADR 0001](../../docs/adrs/0001-agplv3-license.md). See
[`LICENSE-Apache-SDK`](../../LICENSE-Apache-SDK) at the repository root.

## When to use the SDK

- **CI test suites** that spin up a real PostgreSQL via
  `Testcontainers.PostgreSql`, apply the migrations the production code
  expects, and assert against the running schema.
- **Dev seeders** that bootstrap a local PostgreSQL without going through
  Kubernetes.
- **Schema-validation pipelines** that need Keystone's content-hash
  semantics and tracking table without the controller-runtime surface.

If you want the full Keystone experience — GitOps bundles, approvals,
Plan-Gate-Apply, auto-snapshots — run the operator. This SDK is a strict
subset.

## What's in v0.1

- ✅ **Apply** — versioned, content-hashed migration runner with
  `schema_migrations` bookkeeping, in-tx by default, autocommit fallback
  when the bundle contains `CONCURRENTLY`.
- ✅ **Inspect** — read-only structural snapshot (tables, columns,
  indexes, constraints) from `information_schema` + `pg_catalog`.
- ⏳ **Lint** — deferred (52-rule analyzer pack — port pending).
- ⏳ **Diff** — deferred (declarative differ + CRD spec types).

## Quick start

```csharp
using HexxLock.Keystone.Sdk;
using Npgsql;

await using var dataSource = NpgsqlDataSource.Create(connectionString);

var result = await Keystone.ApplyAsync(dataSource, new ApplyOptions
{
    Schema = "public",
    Version = "v1",
    Files = new[]
    {
        new SqlFile
        {
            Name = "001_init.up.sql",
            Body = """
                CREATE TABLE IF NOT EXISTS items (
                    id uuid PRIMARY KEY,
                    name text NOT NULL
                );
            """,
        },
    },
});

Console.WriteLine($"applied {result.Version} @ {result.ContentHash} in {result.TotalDurationMs}ms");

var snapshot = await Keystone.InspectAsync(dataSource, "public");
foreach (var table in snapshot.Tables)
{
    Console.WriteLine($"{table.Name} ({table.Columns.Count} columns)");
}
```

## Test suite usage (xunit + Testcontainers)

```csharp
[Collection(nameof(PostgresCollection))]
public class MyDbTests
{
    private readonly PostgresFixture _pg;
    public MyDbTests(PostgresFixture pg) => _pg = pg;

    [Fact]
    public async Task Schema_IsCorrectShape()
    {
        await Keystone.ApplyAsync(_pg.DataSource, new ApplyOptions
        {
            Schema = "public",
            Version = "test-v1",
            Files = LoadProductionMigrations(),
        });

        var snap = await Keystone.InspectAsync(_pg.DataSource, "public");
        snap.Tables.Should().Contain(t => t.Name == "items");
    }
}
```

## Contract invariants — wire compat with the Go SDK

The C# SDK and the Go SDK / Keystone operator interoperate on the same
`schema_migrations` table. The following are byte-identical between
implementations:

1. **Tracking-table DDL** — `version`, `content_hash`, `applied_at`,
   `applied_by`, `duration_ms`, `dirty` columns; canonical comment string.
2. **Content-hash algorithm** — SHA-256 over `(name‖0x00‖body‖0x00)` for
   each file in supplied order, lowercase hex.
3. **Identifier validation** — `^[a-z_][a-z0-9_]{0,62}$`.
4. **`CONCURRENTLY` detection** — case-insensitive, word-boundary; switches
   the apply to autocommit / per-statement dispatch.
5. **UPSERT on tracking insert** — `ON CONFLICT (version) DO UPDATE SET
   content_hash, duration_ms, applied_at = NOW()`.
6. **Same-version, different-hash refusal** — both implementations throw /
   error with a message that says "bump Version to ship changed SQL".

Parity is enforced by the unit tests in `tests/HexxLock.Keystone.Sdk.Tests`
— `ContentHashTests` re-implements the Go contract and cross-checks; the
splitter tests mirror cases from `internal/migration/sqlsplit_test.go`.

## Targeting

`net8.0` and `net10.0`. Older runtimes can consume the `net8.0` build
unchanged. Single dependency: `Npgsql` (9.x).

## License

Apache-2.0 — see [`LICENSE-Apache-SDK`](../../LICENSE-Apache-SDK).
