// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 HexxLock

using System.Diagnostics;
using System.Text.RegularExpressions;
using Npgsql;

namespace HexxLock.Keystone.Sdk.Internal;

/// <summary>
/// SQL runner that applies migration files inside a transaction (or in
/// autocommit mode when the bundle requires it). Wire-faithful port of
/// <c>internal/migration/runner.go</c> — same tracking-table DDL, same
/// CONCURRENTLY-detection regex, same UPSERT semantics on the version row,
/// same <c>SET LOCAL search_path</c> behavior.
/// </summary>
internal sealed class Runner
{
    public const string DefaultTrackingTable = "schema_migrations";

    /// <summary>
    /// Tracking-table DDL template — byte-identical to the Go runner's
    /// <c>migrationsTableDDLTemplate</c> so both SDK and operator can write
    /// to the same row format. Two <c>{0}.{1}</c> pairs: schema, table.
    /// </summary>
    private const string TrackingTableDdlTemplate = @"
CREATE TABLE IF NOT EXISTS {0}.{1} (
    version       TEXT PRIMARY KEY,
    content_hash  TEXT NOT NULL,
    applied_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    applied_by    TEXT NOT NULL DEFAULT current_user,
    duration_ms   BIGINT NOT NULL,
    dirty         BOOLEAN NOT NULL DEFAULT FALSE
);

COMMENT ON TABLE {0}.{1} IS
    'Maintained by Keystone (keystone.hexxlock.io). Do not edit manually.';
";

    /// <summary>
    /// Matches the <c>CONCURRENTLY</c> keyword used by CREATE/DROP INDEX
    /// CONCURRENTLY and REINDEX … CONCURRENTLY. PostgreSQL refuses these
    /// inside a transaction block (SQLSTATE 25001). When any source file
    /// contains the keyword, Apply switches to autocommit mode for that
    /// bundle.
    /// </summary>
    private static readonly Regex ConcurrentlyPattern = new(
        @"\bCONCURRENTLY\b",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private readonly NpgsqlDataSource _dataSource;
    private readonly string _schema;
    private readonly string _trackingTable;

    public Runner(NpgsqlDataSource dataSource, string schema, string? trackingTable)
    {
        Identifier.Validate("schema", schema);
        var table = string.IsNullOrEmpty(trackingTable) ? DefaultTrackingTable : trackingTable;
        Identifier.Validate("trackingTable", table);

        _dataSource = dataSource;
        _schema = schema;
        _trackingTable = table;
    }

    public string SchemaQuoted => Identifier.Quote(_schema);
    public string TrackingTableQuoted => Identifier.Quote(_trackingTable);

    /// <summary>Creates the tracking table if missing. Idempotent.</summary>
    public async Task EnsureBookkeepingAsync(CancellationToken ct)
    {
        var ddl = string.Format(TrackingTableDdlTemplate, SchemaQuoted, TrackingTableQuoted);
        await using var cmd = _dataSource.CreateCommand(ddl);
        await cmd.ExecuteNonQueryAsync(ct).ConfigureAwait(false);
    }

    /// <summary>
    /// Looks up <paramref name="version"/> in the tracking table. Returns
    /// <c>null</c> when no row exists; otherwise the recorded row.
    /// </summary>
    public async Task<AppliedMigration?> ReadAppliedAsync(string version, CancellationToken ct)
    {
        var sql = $@"SELECT version, content_hash, applied_at, duration_ms, dirty
                       FROM {SchemaQuoted}.{TrackingTableQuoted}
                      WHERE version = $1";
        await using var cmd = _dataSource.CreateCommand(sql);
        cmd.Parameters.AddWithValue(version);
        await using var reader = await cmd.ExecuteReaderAsync(ct).ConfigureAwait(false);
        if (!await reader.ReadAsync(ct).ConfigureAwait(false))
        {
            return null;
        }
        return new AppliedMigration
        {
            Version = reader.GetString(0),
            ContentHash = reader.GetString(1),
            AppliedAt = reader.GetDateTime(2),
            DurationMs = reader.GetInt64(3),
            Dirty = reader.GetBoolean(4),
        };
    }

    /// <summary>
    /// Applies the bundle. Picks the in-tx path or the no-tx (CONCURRENTLY)
    /// path based on whether any file's body matches the CONCURRENTLY regex.
    /// </summary>
    public Task<RunnerResult> ApplyAsync(
        string version,
        string contentHash,
        IReadOnlyList<SqlFile> files,
        CancellationToken ct)
    {
        return NeedsNoTx(files)
            ? ApplyNoTxAsync(version, contentHash, files, ct)
            : ApplyInTxAsync(version, contentHash, files, ct);
    }

    private async Task<RunnerResult> ApplyInTxAsync(
        string version,
        string contentHash,
        IReadOnlyList<SqlFile> files,
        CancellationToken ct)
    {
        var sw = Stopwatch.StartNew();
        var fileResults = new List<FileResult>(files.Count);

        await using var conn = await _dataSource.OpenConnectionAsync(ct).ConfigureAwait(false);
        await using var tx = await conn.BeginTransactionAsync(ct).ConfigureAwait(false);

        // Set search_path so unqualified objects in the migration land in
        // the right schema. The pool's default search_path doesn't apply
        // here because Npgsql connects to the database, not the schema.
        await using (var setSearchPath = new NpgsqlCommand(
            $"SET LOCAL search_path TO {SchemaQuoted}", conn, tx))
        {
            await setSearchPath.ExecuteNonQueryAsync(ct).ConfigureAwait(false);
        }

        for (var idx = 0; idx < files.Count; idx++)
        {
            var f = files[idx];
            var fileSw = Stopwatch.StartNew();
            await using var fileCmd = new NpgsqlCommand(f.Body, conn, tx);
            var rowsAffected = await fileCmd.ExecuteNonQueryAsync(ct).ConfigureAwait(false);
            fileResults.Add(new FileResult
            {
                File = f.Name,
                Index = idx + 1,
                DurationMs = fileSw.ElapsedMilliseconds,
                RowsAffected = rowsAffected,
            });
        }

        var totalMs = sw.ElapsedMilliseconds;
        var insertSql = $@"INSERT INTO {SchemaQuoted}.{TrackingTableQuoted}
                              (version, content_hash, duration_ms)
                          VALUES ($1, $2, $3)
                          ON CONFLICT (version) DO UPDATE SET
                              content_hash = EXCLUDED.content_hash,
                              duration_ms  = EXCLUDED.duration_ms,
                              applied_at   = NOW()";
        await using (var insertCmd = new NpgsqlCommand(insertSql, conn, tx))
        {
            insertCmd.Parameters.AddWithValue(version);
            insertCmd.Parameters.AddWithValue(contentHash);
            insertCmd.Parameters.AddWithValue(totalMs);
            await insertCmd.ExecuteNonQueryAsync(ct).ConfigureAwait(false);
        }

        await tx.CommitAsync(ct).ConfigureAwait(false);

        return new RunnerResult(fileResults, totalMs);
    }

    /// <summary>
    /// Applies the bundle without wrapping it in a transaction. Required
    /// when any file contains <c>CONCURRENTLY</c>; safe for everything else
    /// because each statement carries its own implicit tx via PG autocommit.
    /// </summary>
    private async Task<RunnerResult> ApplyNoTxAsync(
        string version,
        string contentHash,
        IReadOnlyList<SqlFile> files,
        CancellationToken ct)
    {
        var sw = Stopwatch.StartNew();
        var fileResults = new List<FileResult>(files.Count);

        await using var conn = await _dataSource.OpenConnectionAsync(ct).ConfigureAwait(false);

        await using (var setSearchPath = new NpgsqlCommand(
            $"SET search_path TO {SchemaQuoted}", conn))
        {
            await setSearchPath.ExecuteNonQueryAsync(ct).ConfigureAwait(false);
        }

        try
        {
            for (var idx = 0; idx < files.Count; idx++)
            {
                var f = files[idx];
                var fileSw = Stopwatch.StartNew();
                long rowsAffected = 0;
                foreach (var stmt in SqlStatementSplitter.Split(f.Body))
                {
                    await using var stmtCmd = new NpgsqlCommand(stmt, conn);
                    rowsAffected += await stmtCmd.ExecuteNonQueryAsync(ct).ConfigureAwait(false);
                }
                fileResults.Add(new FileResult
                {
                    File = f.Name,
                    Index = idx + 1,
                    DurationMs = fileSw.ElapsedMilliseconds,
                    RowsAffected = rowsAffected,
                });
            }

            var totalMs = sw.ElapsedMilliseconds;
            var insertSql = $@"INSERT INTO {SchemaQuoted}.{TrackingTableQuoted}
                                  (version, content_hash, duration_ms)
                              VALUES ($1, $2, $3)
                              ON CONFLICT (version) DO UPDATE SET
                                  content_hash = EXCLUDED.content_hash,
                                  duration_ms  = EXCLUDED.duration_ms,
                                  applied_at   = NOW()";
            await using (var insertCmd = new NpgsqlCommand(insertSql, conn))
            {
                insertCmd.Parameters.AddWithValue(version);
                insertCmd.Parameters.AddWithValue(contentHash);
                insertCmd.Parameters.AddWithValue(totalMs);
                await insertCmd.ExecuteNonQueryAsync(ct).ConfigureAwait(false);
            }

            return new RunnerResult(fileResults, totalMs);
        }
        finally
        {
            // Best-effort reset so the pooled connection doesn't leak the
            // migration's search_path back to other users.
            try
            {
                await using var resetCmd = new NpgsqlCommand("RESET search_path", conn);
                await resetCmd.ExecuteNonQueryAsync(CancellationToken.None).ConfigureAwait(false);
            }
            catch
            {
                // Reset is best-effort; if the connection is in a bad state
                // the pool will close it on dispose.
            }
        }
    }

    /// <summary>
    /// Reports whether the bundle contains any <c>CONCURRENTLY</c> statement,
    /// which forces autocommit (no-tx) mode for the whole apply.
    /// </summary>
    internal static bool NeedsNoTx(IReadOnlyList<SqlFile> files)
    {
        foreach (var f in files)
        {
            if (ConcurrentlyPattern.IsMatch(f.Body)) return true;
        }
        return false;
    }
}

internal sealed class AppliedMigration
{
    public required string Version { get; init; }
    public required string ContentHash { get; init; }
    public required DateTime AppliedAt { get; init; }
    public required long DurationMs { get; init; }
    public required bool Dirty { get; init; }
}

internal sealed record RunnerResult(IReadOnlyList<FileResult> Files, long TotalDurationMs);
