# HexxLock.Keystone.Sdk.EntityFrameworkCore

Export an EF Core model as a Keystone **schema-as-code** source, so .NET
teams can author Keystone migrations from their entities — the "migrations
from code" bridge for .NET.

It mirrors how [Atlas](https://atlasgo.io) integrates with ORMs: the ORM
emits SQL, a throwaway dev database normalises it, and Keystone's differ
authors a versioned, reversible migration. Keystone never re-implements
EF Core's model layer — it just consumes the DDL EF already knows how to
generate.

## Install

```bash
dotnet add package HexxLock.Keystone.Sdk.EntityFrameworkCore
```

## Use — program mode

Write a tiny exporter (run it in CI, or by hand) that builds your
`DbContext` and writes its CREATE DDL:

```csharp
using HexxLock.Keystone.Sdk.EntityFrameworkCore;

await using var ctx = new AppDbContext(/* design-time options */);
await KeystoneEf.WriteCreateScriptAsync(ctx, "schema.sql");
```

Or, from an `IDesignTimeDbContextFactory<T>` (the same factory `dotnet ef`
uses):

```csharp
await KeystoneEf.WriteCreateScriptAsync(new AppDbContextFactory(), "schema.sql");
```

`GenerateCreateScript` runs against the **model metadata only** — no
database connection is opened.

## Then author the migration

```bash
keystonectl migrate diff add_customer_table \
    --desired sql://schema.sql \
    --dev-url postgres://localhost/devdb \
    --dir migrations
```

Keystone applies `schema.sql` to a scratch schema on the dev database,
inspects it, diffs it against the current migration state, and writes a
new `NNN_add_customer_table.up.sql` / `.down.sql` pair with a regenerated
`keystone.sum`.

## Schema-relative output

Keystone applies the DDL under a scratch schema's `search_path`, so the
script should be **schema-relative** (unqualified table names). The clean
path is to *not* call `modelBuilder.HasDefaultSchema(...)` — EF then emits
unqualified DDL. If your model does set a default schema, pass it to strip
the qualifier:

```csharp
KeystoneEf.ExportCreateScript(ctx, stripSchema: "app");
```

## License

Apache-2.0.
