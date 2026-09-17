// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 HexxLock

namespace HexxLock.Keystone.Sdk;

/// <summary>One SQL file's execution outcome.</summary>
public sealed record FileResult
{
    /// <summary>The <see cref="SqlFile.Name"/> of the file applied.</summary>
    public required string File { get; init; }

    /// <summary>1-based position in <see cref="ApplyOptions.Files"/>.</summary>
    public required int Index { get; init; }

    /// <summary>Wall-clock time for this file's execution, in milliseconds.</summary>
    public required long DurationMs { get; init; }

    /// <summary>
    /// Sum of <c>RowsAffected</c> across the statements in the file. -1 when
    /// the file contained no statement that returned a row count (most DDL).
    /// </summary>
    public required long RowsAffected { get; init; }
}
