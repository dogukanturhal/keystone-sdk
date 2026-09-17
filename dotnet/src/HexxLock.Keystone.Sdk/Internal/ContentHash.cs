// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 HexxLock

using System.Security.Cryptography;
using System.Text;

namespace HexxLock.Keystone.Sdk.Internal;

/// <summary>
/// Content hashing for migration bundles. Wire-compatible with the Go SDK's
/// <c>migration.HashFiles</c> — required so the same bundle produces the
/// same <c>schema_migrations.content_hash</c> regardless of which language
/// applied it.
/// </summary>
internal static class ContentHash
{
    /// <summary>
    /// Returns the lowercase SHA-256 hex over the byte stream
    /// <c>(name‖0x00‖body‖0x00)</c> for each file in the supplied order.
    /// Deterministic given consistent ordering; mirrors Go's
    /// <c>migration.HashFiles(files, names)</c>.
    /// </summary>
    public static string Compute(IReadOnlyList<SqlFile> files)
    {
        using var sha = SHA256.Create();
        foreach (var file in files)
        {
            var nameBytes = Encoding.UTF8.GetBytes(file.Name);
            var bodyBytes = Encoding.UTF8.GetBytes(file.Body);
            sha.TransformBlock(nameBytes, 0, nameBytes.Length, null, 0);
            sha.TransformBlock(_zero, 0, 1, null, 0);
            sha.TransformBlock(bodyBytes, 0, bodyBytes.Length, null, 0);
            sha.TransformBlock(_zero, 0, 1, null, 0);
        }
        sha.TransformFinalBlock([], 0, 0);
        // ToHexStringLower is net9.0+; ToHexString().ToLowerInvariant() works on net8.0.
        return Convert.ToHexString(sha.Hash!).ToLowerInvariant();
    }

    private static readonly byte[] _zero = [0x00];
}
