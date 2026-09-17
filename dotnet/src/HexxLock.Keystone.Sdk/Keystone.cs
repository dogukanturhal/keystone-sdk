// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 HexxLock

using HexxLock.Keystone.Sdk.Internal;
using Npgsql;

namespace HexxLock.Keystone.Sdk;

/// <summary>
/// Apache-2.0 .NET runtime SDK for Keystone. Public entry point — wraps
/// Keystone's schema-management primitives so .NET CI test suites and dev
/// seeders can apply versioned SQL migrations and introspect the live
/// schema without going through the Kubernetes operator.
/// <para/>
/// Wire-compatible with the Go SDK: identical content-hash algorithm,
/// identical <c>schema_migrations</c> tracking-table shape, identical
/// CONCURRENTLY-detection semantics. Either SDK can apply a bundle the
/// other has already recorded — the per-version content-hash check is the
/// shared anti-replay token.
/// </summary>
public static class Keystone
{
    /// <summary>
    /// Runs the given migration against <paramref name="dataSource"/>.
    /// Creates the tracking table if absent, refuses on (version, different
    /// content hash), and commits per-bundle. Returns the per-file result
    /// list on success.
    /// <para/>
    /// The data source is NOT disposed by Apply — callers own lifecycle.
    /// </summary>
    /// <exception cref="ArgumentNullException">when <paramref name="dataSource"/> or <paramref name="options"/> is null.</exception>
    /// <exception cref="ArgumentException">when <paramref name="options"/>.Schema/Version/Files is invalid.</exception>
    /// <exception cref="InvalidOperationException">when the version is recorded with a different content hash than the supplied bundle hashes to (anti-replay).</exception>
    public static async Task<ApplyResult> ApplyAsync(
        NpgsqlDataSource dataSource,
        ApplyOptions options,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(dataSource);
        ArgumentNullException.ThrowIfNull(options);
        if (string.IsNullOrEmpty(options.Schema))
            throw new ArgumentException("ApplyOptions.Schema is required", nameof(options));
        if (string.IsNullOrEmpty(options.Version))
            throw new ArgumentException("ApplyOptions.Version is required", nameof(options));
        if (options.Files is null || options.Files.Count == 0)
            throw new ArgumentException("ApplyOptions.Files is empty", nameof(options));

        var runner = new Runner(dataSource, options.Schema, options.TrackingTable);
        await runner.EnsureBookkeepingAsync(cancellationToken).ConfigureAwait(false);

        var contentHash = ContentHash.Compute(options.Files);

        // Idempotency gate: same (Version, ContentHash) → no-op success;
        // same Version, different ContentHash → refuse. Mirrors the
        // MigrationExecution controller's logic so SDK + operator behave
        // identically under retries.
        var prior = await runner.ReadAppliedAsync(options.Version, cancellationToken).ConfigureAwait(false);
        if (prior is not null)
        {
            if (prior.ContentHash != contentHash)
            {
                throw new InvalidOperationException(
                    $"keystone sdk: version \"{options.Version}\" already applied with " +
                    $"contentHash \"{prior.ContentHash}\"; new content hashes to \"{contentHash}\" " +
                    $"— bump Version to ship changed SQL");
            }
            return new ApplyResult
            {
                Version = options.Version,
                ContentHash = contentHash,
                TotalDurationMs = 0,
                Files = Array.Empty<FileResult>(),
            };
        }

        var result = await runner.ApplyAsync(
            options.Version, contentHash, options.Files, cancellationToken).ConfigureAwait(false);

        return new ApplyResult
        {
            Version = options.Version,
            ContentHash = contentHash,
            TotalDurationMs = result.TotalDurationMs,
            Files = result.Files,
        };
    }

    /// <summary>
    /// Returns the live structural snapshot for <paramref name="schema"/>.
    /// Runs read-only queries against <c>information_schema</c> and
    /// <c>pg_catalog</c>. Tables and columns are ordered (by name and ordinal
    /// respectively) to give callers a stable comparison surface.
    /// </summary>
    public static async Task<Snapshot> InspectAsync(
        NpgsqlDataSource dataSource,
        string schema,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(dataSource);
        Identifier.Validate("schema", schema);

        var tables = await Inspector.LoadTablesAsync(dataSource, schema, cancellationToken).ConfigureAwait(false);
        var indexes = await Inspector.LoadIndexesAsync(dataSource, schema, cancellationToken).ConfigureAwait(false);
        var constraints = await Inspector.LoadConstraintsAsync(dataSource, schema, cancellationToken).ConfigureAwait(false);

        return new Snapshot
        {
            Schema = schema,
            Tables = tables,
            Indexes = indexes,
            Constraints = constraints,
        };
    }
}
