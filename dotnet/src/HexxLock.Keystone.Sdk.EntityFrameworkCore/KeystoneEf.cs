// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 HexxLock

using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Design;

namespace HexxLock.Keystone.Sdk.EntityFrameworkCore;

/// <summary>
/// Exports an EF Core model as a Keystone "schema from code" source.
/// <para/>
/// Keystone manages schemas declaratively: you describe the desired shape
/// and the operator (or <c>keystonectl migrate diff</c>) computes the SQL
/// to reach it. For .NET teams whose source of truth is their EF Core
/// model, this type bridges the two — it renders the model's full CREATE
/// DDL via EF Core's own <see cref="RelationalDatabaseFacadeExtensions.GenerateCreateScript"/>,
/// requiring no database connection and no reflection over your entities.
/// <para/>
/// The emitted <c>.sql</c> is consumed by Keystone exactly like any other
/// SQL schema source:
/// <code>
///   keystonectl migrate diff add_customer_table \
///       --desired sql://schema.sql \
///       --dev-url postgres://…/devdb \
///       --dir migrations
/// </code>
/// Keystone applies the DDL to a throwaway dev schema, inspects it, diffs
/// it against the current migration state, and authors a versioned,
/// reversible migration. This mirrors Atlas's ORM-provider model: the ORM
/// emits SQL, the dev database normalises it, the differ does the rest —
/// so Keystone supports "migrations from code" without re-implementing
/// EF Core's model layer.
/// </summary>
public static class KeystoneEf
{
    /// <summary>
    /// Renders the full CREATE DDL for <paramref name="context"/>'s model.
    /// Does not connect to a database — the script is generated from the
    /// model metadata alone.
    /// </summary>
    /// <param name="context">A configured DbContext (provider set, e.g. UseNpgsql).</param>
    /// <param name="stripSchema">
    /// When non-null, removes the <c>"&lt;stripSchema&gt;".</c> qualifier
    /// EF Core emits when the model declares a default schema, yielding
    /// schema-relative DDL. Keystone's dev-database normaliser applies the
    /// DDL under a scratch schema's search_path, so schema-relative is the
    /// right shape; pass your model's default schema here if it sets one.
    /// </param>
    /// <returns>The CREATE script (CREATE TABLE / INDEX / constraint DDL).</returns>
    /// <exception cref="ArgumentNullException">when <paramref name="context"/> is null.</exception>
    public static string ExportCreateScript(DbContext context, string? stripSchema = null)
    {
        ArgumentNullException.ThrowIfNull(context);
        var sql = context.Database.GenerateCreateScript();
        if (!string.IsNullOrEmpty(stripSchema))
        {
            // EF Core qualifies objects as `<schema>."Table"`, quoting the
            // schema only when it is not a bare-legal identifier. Strip both
            // forms so the DDL becomes schema-relative; Keystone applies it
            // under a scratch schema's search_path. The leftover
            // `CREATE SCHEMA <schema>` block (if any) is harmless on the dev
            // database. (Best-effort: prefer a model with no default schema,
            // which emits unqualified DDL needing no stripping at all.)
            sql = sql.Replace($"\"{stripSchema}\".", string.Empty, StringComparison.Ordinal);
            sql = sql.Replace($"{stripSchema}.", string.Empty, StringComparison.Ordinal);
        }
        return sql;
    }

    /// <summary>
    /// Renders the model from a design-time context factory (the
    /// <see cref="IDesignTimeDbContextFactory{TContext}"/> pattern EF Core
    /// tooling uses) and writes it to <paramref name="path"/>. Convenience
    /// for a small "program mode" exporter you run in CI to keep
    /// <c>schema.sql</c> in sync with your entities.
    /// </summary>
    public static async Task WriteCreateScriptAsync<TContext>(
        IDesignTimeDbContextFactory<TContext> factory,
        string path,
        string? stripSchema = null,
        CancellationToken cancellationToken = default)
        where TContext : DbContext
    {
        ArgumentNullException.ThrowIfNull(factory);
        await using var context = factory.CreateDbContext([]);
        await WriteCreateScriptAsync(context, path, stripSchema, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Writes <see cref="ExportCreateScript(DbContext, string?)"/> output to
    /// <paramref name="path"/>.
    /// </summary>
    public static async Task WriteCreateScriptAsync(
        DbContext context,
        string path,
        string? stripSchema = null,
        CancellationToken cancellationToken = default)
    {
        var sql = ExportCreateScript(context, stripSchema);
        await File.WriteAllTextAsync(path, sql, cancellationToken).ConfigureAwait(false);
    }
}
