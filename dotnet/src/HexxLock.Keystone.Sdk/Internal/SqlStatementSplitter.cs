// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 HexxLock

using System.Text;

namespace HexxLock.Keystone.Sdk.Internal;

/// <summary>
/// Splits a SQL script into individual statements on top-level semicolons,
/// ignoring semicolons inside single-quoted strings, double-quoted
/// identifiers, dollar-quoted strings, line comments (<c>-- … \n</c>) and
/// block comments (<c>/* … */</c>).
/// <para/>
/// Used by the no-tx apply path to send each statement in its own
/// <c>ExecuteNonQuery</c> call. PostgreSQL's simple-query protocol wraps
/// multi-statement bodies in an implicit transaction; <c>CONCURRENTLY</c>
/// statements refuse to run in any transaction (implicit or explicit), so
/// the runner must dispatch one statement per round-trip.
/// <para/>
/// The splitter does not validate SQL syntax; it returns whatever the
/// caller supplies, trimmed of surrounding whitespace, with empty
/// statements (e.g. a file ending in <c>;\n</c>) discarded. Trailing
/// semicolons are preserved on each returned statement. Wire-faithful port
/// of <c>internal/migration/sqlsplit.go</c>.
/// </summary>
internal static class SqlStatementSplitter
{
    private enum State
    {
        Normal,
        LineComment,
        BlockComment,
        SingleQuote,
        DoubleQuote,
        DollarQuote,
    }

    public static List<string> Split(string sql)
    {
        var stmts = new List<string>();
        var b = new StringBuilder();
        var state = State.Normal;
        var dollarTag = string.Empty; // set when state == DollarQuote, e.g. "$$" or "$body$"
        var n = sql.Length;

        for (var i = 0; i < n; i++)
        {
            var r = sql[i];

            switch (state)
            {
                case State.LineComment:
                    b.Append(r);
                    if (r == '\n') state = State.Normal;
                    continue;

                case State.BlockComment:
                    b.Append(r);
                    if (r == '*' && i + 1 < n && sql[i + 1] == '/')
                    {
                        b.Append(sql[i + 1]);
                        i++;
                        state = State.Normal;
                    }
                    continue;

                case State.SingleQuote:
                    b.Append(r);
                    if (r == '\'')
                    {
                        if (i + 1 < n && sql[i + 1] == '\'')
                        {
                            // `''` escaped single quote inside literal.
                            b.Append(sql[i + 1]);
                            i++;
                            continue;
                        }
                        state = State.Normal;
                    }
                    continue;

                case State.DoubleQuote:
                    b.Append(r);
                    if (r == '"')
                    {
                        if (i + 1 < n && sql[i + 1] == '"')
                        {
                            b.Append(sql[i + 1]);
                            i++;
                            continue;
                        }
                        state = State.Normal;
                    }
                    continue;

                case State.DollarQuote:
                    b.Append(r);
                    if (r == '$' && TagAt(sql, i, dollarTag))
                    {
                        for (var k = 1; k < dollarTag.Length; k++)
                        {
                            b.Append(sql[i + k]);
                        }
                        i += dollarTag.Length - 1;
                        state = State.Normal;
                        dollarTag = string.Empty;
                    }
                    continue;
            }

            // state == Normal
            if (r == '-' && i + 1 < n && sql[i + 1] == '-')
            {
                b.Append(r);
                b.Append(sql[i + 1]);
                i++;
                state = State.LineComment;
            }
            else if (r == '/' && i + 1 < n && sql[i + 1] == '*')
            {
                b.Append(r);
                b.Append(sql[i + 1]);
                i++;
                state = State.BlockComment;
            }
            else if (r == '\'')
            {
                b.Append(r);
                state = State.SingleQuote;
            }
            else if (r == '"')
            {
                b.Append(r);
                state = State.DoubleQuote;
            }
            else if (r == '$')
            {
                if (TryReadDollarTag(sql, i, out var tag))
                {
                    for (var k = 0; k < tag.Length; k++)
                    {
                        b.Append(sql[i + k]);
                    }
                    i += tag.Length - 1;
                    state = State.DollarQuote;
                    dollarTag = tag;
                }
                else
                {
                    b.Append(r);
                }
            }
            else if (r == ';')
            {
                b.Append(r);
                var stmt = b.ToString().Trim();
                if (stmt.Length > 0 && stmt != ";")
                {
                    stmts.Add(stmt);
                }
                b.Clear();
            }
            else
            {
                b.Append(r);
            }
        }

        var tail = b.ToString().Trim();
        if (tail.Length > 0)
        {
            stmts.Add(tail);
        }

        return stmts;
    }

    /// <summary>
    /// Matches a <c>$tag$</c> opening at <c>sql[i]</c>; tag body is empty or
    /// <c>[A-Za-z_][A-Za-z0-9_]*</c>. Returns the full opening including both
    /// <c>$</c> characters (e.g. <c>$$</c> or <c>$body$</c>) on a successful
    /// match.
    /// </summary>
    private static bool TryReadDollarTag(string sql, int i, out string tag)
    {
        tag = string.Empty;
        if (i >= sql.Length || sql[i] != '$') return false;

        var j = i + 1;
        while (j < sql.Length)
        {
            var r = sql[j];
            if (r == '$')
            {
                tag = sql.Substring(i, j - i + 1);
                return true;
            }
            var isLetterOrUnderscore = r == '_' || (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z');
            var isDigit = r >= '0' && r <= '9';
            if (!(isLetterOrUnderscore || (j > i + 1 && isDigit)))
            {
                return false;
            }
            j++;
        }
        return false;
    }

    /// <summary>Reports whether <c>sql[i..]</c> starts with <paramref name="tag"/>.</summary>
    private static bool TagAt(string sql, int i, string tag)
    {
        if (i + tag.Length > sql.Length) return false;
        for (var k = 0; k < tag.Length; k++)
        {
            if (sql[i + k] != tag[k]) return false;
        }
        return true;
    }
}
