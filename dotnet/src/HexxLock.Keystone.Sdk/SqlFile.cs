// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 HexxLock

namespace HexxLock.Keystone.Sdk;

/// <summary>
/// One migration file the SDK ingests. The file order is the caller's
/// responsibility; the runner applies files in the slice order. <see cref="Name"/>
/// is displayed in lint diagnostics and stored on the tracking row, so use
/// something traceable (e.g. <c>001_init.up.sql</c>).
/// </summary>
public sealed class SqlFile
{
    /// <summary>
    /// Displayed in diagnostics and stored in the tracking table. Typically a
    /// filename like <c>001_init.up.sql</c>.
    /// </summary>
    public required string Name { get; init; }

    /// <summary>
    /// SQL text. Apply wraps the whole file in a single transaction (or a
    /// single autocommit batch when the bundle contains <c>CONCURRENTLY</c>),
    /// so multiple statements are fine.
    /// </summary>
    public required string Body { get; init; }
}
