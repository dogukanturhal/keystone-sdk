// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 HexxLock

using System.Text.RegularExpressions;

namespace HexxLock.Keystone.Sdk.Internal;

/// <summary>
/// Identifier helpers: validate + double-quote PostgreSQL identifiers.
/// Mirrors <c>internal/postgres/quote.go</c> in the Go operator. The tracking-
/// table runner uses these on every identifier (schema, tracking table name)
/// before composing DDL — defence in depth even when the caller already
/// validated.
/// </summary>
internal static class Identifier
{
    /// <summary>
    /// PG NAMEDATALEN is 64 → identifier max is 63 bytes; pattern lowercase
    /// letter or underscore, then lowercase alphanumeric/underscore.
    /// </summary>
    private static readonly Regex ValidPattern = new(
        @"^[a-z_][a-z0-9_]{0,62}$",
        RegexOptions.Compiled | RegexOptions.CultureInvariant);

    /// <summary>
    /// Throws <see cref="ArgumentException"/> with a stable message format if
    /// <paramref name="name"/> is not a valid PG identifier.
    /// </summary>
    public static void Validate(string kind, string name)
    {
        if (!ValidPattern.IsMatch(name ?? string.Empty))
        {
            throw new ArgumentException(
                $"invalid {kind} identifier \"{name}\": must match ^[a-z_][a-z0-9_]{{0,62}}$",
                nameof(name));
        }
    }

    /// <summary>
    /// Returns the input wrapped per PostgreSQL identifier rules — double
    /// quotes around the value with embedded double quotes doubled. Use this
    /// for EVERY identifier passed into DDL: schema name, table name.
    /// PostgreSQL parameter binding (<c>$1, $2, …</c>) does NOT apply to DDL
    /// identifiers.
    /// </summary>
    public static string Quote(string name) => "\"" + (name ?? string.Empty).Replace("\"", "\"\"") + "\"";
}
