// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 HexxLock

using System.Text.RegularExpressions;

namespace HexxLock.Keystone.Sdk.EntityFrameworkCore.Tool;

/// <summary>
/// Post-processing that turns EF Core's create script into the shape
/// Keystone's dev-database normaliser expects: schema-relative DDL.
/// <para/>
/// Keystone applies the DDL under a throwaway scratch schema's
/// <c>search_path</c> and inspects the result. Unqualified object names
/// therefore land in the scratch schema and diff cleanly against the real
/// target schema. A model that declares a default schema makes EF emit
/// <c>"app"."Todos"</c> instead, which would pin every object to a schema
/// that is not the one being diffed — so the qualifier is removed, along
/// with the now-pointless <c>CREATE SCHEMA</c> that accompanies it.
/// </summary>
internal static class Rewrite
{
    /// <summary>
    /// Applies the schema-relative rewrite when <paramref name="stripSchema"/>
    /// is set; otherwise returns <paramref name="ddl"/> unchanged.
    /// </summary>
    internal static string Apply(string ddl, string? stripSchema)
    {
        if (string.IsNullOrEmpty(stripSchema))
        {
            return ddl;
        }

        var name = Regex.Escape(stripSchema);

        // 1. Drop the whole `DO $EF$ … END $EF$;` guard block Npgsql emits to
        //    create the default schema idempotently:
        //
        //      DO $EF$
        //      BEGIN
        //          IF NOT EXISTS(SELECT 1 FROM pg_namespace WHERE nspname = 'app') THEN
        //              CREATE SCHEMA app;
        //          END IF;
        //      END $EF$;
        //
        //    Removing only the inner CREATE SCHEMA would leave `IF … THEN`
        //    with an empty body, which PL/pgSQL rejects outright — so the
        //    block goes as a unit. Scoped to blocks that actually create the
        //    schema being stripped, so a DO block carrying real DDL survives.
        ddl = Regex.Replace(
            ddl,
            @"^[ \t]*DO\s+\$(?<tag>\w*)\$.*?\$\k<tag>\$\s*;[ \t]*\r?\n?",
            m => Regex.IsMatch(
                     m.Value,
                     $@"CREATE\s+SCHEMA\s+(?:IF\s+NOT\s+EXISTS\s+)?(?:""{name}""|{name})\b",
                     RegexOptions.IgnoreCase)
                 ? string.Empty
                 : m.Value,
            RegexOptions.IgnoreCase | RegexOptions.Multiline | RegexOptions.Singleline);

        // 2. Drop the plain `CREATE SCHEMA [IF NOT EXISTS] <schema>;` spelling
        //    too — other providers and older EF versions emit it unguarded.
        //    Left in place it would create a real schema on the dev database,
        //    while objects still land in the scratch schema via search_path.
        ddl = Regex.Replace(
            ddl,
            $"""^[ \t]*CREATE\s+SCHEMA\s+(?:IF\s+NOT\s+EXISTS\s+)?(?:"{name}"|{name})\s*;[ \t]*\r?\n?""",
            string.Empty,
            RegexOptions.IgnoreCase | RegexOptions.Multiline);

        // 3. Remove the qualifier itself. The quoted form is unambiguous.
        ddl = ddl.Replace($"\"{stripSchema}\".", string.Empty, StringComparison.Ordinal);

        // 4. The bare form needs an identifier boundary so a schema called
        //    "app" does not also rewrite a column named "snapp.". Best-effort
        //    by nature: a string literal containing `app.` is indistinguishable
        //    from a qualifier at this layer. Prefer a model with no default
        //    schema, which emits unqualified DDL and needs no rewriting at all.
        ddl = Regex.Replace(ddl, $@"(?<![A-Za-z0-9_""]){name}\.", string.Empty);

        // Removing the leading guard block leaves the script starting on a
        // run of blank lines; trim so the emitted DDL reads like a file a
        // human wrote.
        return ddl.TrimStart('\r', '\n');
    }
}
