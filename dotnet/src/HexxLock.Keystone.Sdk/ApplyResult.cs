// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 HexxLock

namespace HexxLock.Keystone.Sdk;

/// <summary>
/// What actually ran during <see cref="Keystone.ApplyAsync"/>. <see cref="ContentHash"/>
/// is the SHA-256 the runner recorded — stable across identical file
/// contents and the primary anti-replay token.
/// </summary>
public sealed record ApplyResult
{
    /// <summary>Mirrors the input for the caller's convenience.</summary>
    public required string Version { get; init; }

    /// <summary>SHA-256 hex recorded in the tracking table.</summary>
    public required string ContentHash { get; init; }

    /// <summary>Wall-clock time across all files, in milliseconds.</summary>
    public required long TotalDurationMs { get; init; }

    /// <summary>
    /// Per-file timings in apply order. Empty when the call was a no-op
    /// (version already applied with the same content hash).
    /// </summary>
    public required IReadOnlyList<FileResult> Files { get; init; }
}
