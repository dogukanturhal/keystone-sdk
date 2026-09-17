// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 HexxLock

namespace HexxLock.Keystone.Sdk;

/// <summary>
/// Bundle of arguments the <see cref="Keystone.ApplyAsync"/> entry point
/// needs to run a versioned migration against a caller-supplied
/// <see cref="Npgsql.NpgsqlDataSource"/>. The data source's connections MUST
/// belong to the target database; the runner issues
/// <c>SET LOCAL search_path</c> to <see cref="Schema"/> per apply.
/// </summary>
public sealed class ApplyOptions
{
    /// <summary>
    /// PG schema the runner operates against. Identifier-validated before any
    /// DDL is issued; must match <c>^[a-z_][a-z0-9_]{0,62}$</c>.
    /// </summary>
    public required string Schema { get; init; }

    /// <summary>
    /// Migration version. Recorded in the tracking table (see
    /// <see cref="TrackingTable"/>) along with a content hash. Applying twice
    /// with the same (Version, ContentHash) pair is a no-op; (Version,
    /// different ContentHash) is refused with a clear error — bump Version
    /// to ship changed SQL.
    /// </summary>
    public required string Version { get; init; }

    /// <summary>
    /// Ordered list of SQL files the runner applies. Each file's content is
    /// dispatched as a single batch — multi-statement bodies are fine.
    /// </summary>
    public required IReadOnlyList<SqlFile> Files { get; init; }

    /// <summary>
    /// Override for the default <c>schema_migrations</c> tracking table name.
    /// Useful when adopting Keystone in a database that already uses the
    /// default name for a different tool (e.g. golang-migrate). <c>null</c>
    /// or empty means <c>schema_migrations</c>.
    /// </summary>
    public string? TrackingTable { get; init; }
}
