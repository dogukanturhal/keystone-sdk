// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 HexxLock

using Npgsql;

namespace HexxLock.Keystone.Sdk.Internal;

/// <summary>
/// Read-only schema introspection. Mirrors <c>internal/drift/inspector.go</c>
/// for the subset the SDK exposes — base tables + views, columns, indexes,
/// constraints. Queries <c>information_schema</c> for shape data and
/// <c>pg_catalog</c> for index/constraint definitions.
/// </summary>
internal static class Inspector
{
    public static async Task<IReadOnlyList<Table>> LoadTablesAsync(
        NpgsqlDataSource source, string schema, CancellationToken ct)
    {
        // Step 1 — list base tables and views in the schema.
        var tableShells = new List<(string Name, string Kind)>();
        const string tablesSql = @"
            SELECT table_name, table_type
              FROM information_schema.tables
             WHERE table_schema = $1
               AND table_type IN ('BASE TABLE', 'VIEW')
             ORDER BY table_name";
        await using (var cmd = source.CreateCommand(tablesSql))
        {
            cmd.Parameters.AddWithValue(schema);
            await using var reader = await cmd.ExecuteReaderAsync(ct).ConfigureAwait(false);
            while (await reader.ReadAsync(ct).ConfigureAwait(false))
            {
                tableShells.Add((reader.GetString(0), reader.GetString(1)));
            }
        }

        // Step 2 — load columns for every (schema, table) in one query, then
        // bucket per-table.
        var columnsByTable = new Dictionary<string, List<Column>>(StringComparer.Ordinal);
        const string columnsSql = @"
            SELECT table_name, column_name, ordinal_position, data_type, udt_name,
                   is_nullable, COALESCE(column_default, '')
              FROM information_schema.columns
             WHERE table_schema = $1
             ORDER BY table_name, ordinal_position";
        await using (var cmd = source.CreateCommand(columnsSql))
        {
            cmd.Parameters.AddWithValue(schema);
            await using var reader = await cmd.ExecuteReaderAsync(ct).ConfigureAwait(false);
            while (await reader.ReadAsync(ct).ConfigureAwait(false))
            {
                var table = reader.GetString(0);
                if (!columnsByTable.TryGetValue(table, out var list))
                {
                    list = new List<Column>();
                    columnsByTable[table] = list;
                }
                list.Add(new Column
                {
                    Name = reader.GetString(1),
                    Ordinal = reader.GetInt32(2),
                    DataType = reader.GetString(3),
                    UdtName = reader.GetString(4),
                    Nullable = reader.GetString(5) == "YES",
                    Default = reader.GetString(6),
                });
            }
        }

        var result = new List<Table>(tableShells.Count);
        foreach (var (name, kind) in tableShells)
        {
            result.Add(new Table
            {
                Name = name,
                Kind = kind,
                Columns = columnsByTable.TryGetValue(name, out var cols)
                    ? cols
                    : Array.Empty<Column>(),
            });
        }
        return result;
    }

    public static async Task<IReadOnlyList<ObjectDdl>> LoadIndexesAsync(
        NpgsqlDataSource source, string schema, CancellationToken ct)
    {
        const string sql = @"
            SELECT i.indexname AS name,
                   i.tablename  AS table_name,
                   CASE WHEN ix.indisunique THEN 'UNIQUE' ELSE 'INDEX' END AS type,
                   i.indexdef   AS definition
              FROM pg_catalog.pg_indexes i
              JOIN pg_catalog.pg_class c
                ON c.relname = i.indexname
               AND c.relnamespace = (SELECT oid FROM pg_catalog.pg_namespace WHERE nspname = i.schemaname)
              JOIN pg_catalog.pg_index ix ON ix.indexrelid = c.oid
             WHERE i.schemaname = $1
             ORDER BY i.tablename, i.indexname";
        await using var cmd = source.CreateCommand(sql);
        cmd.Parameters.AddWithValue(schema);
        await using var reader = await cmd.ExecuteReaderAsync(ct).ConfigureAwait(false);
        var list = new List<ObjectDdl>();
        while (await reader.ReadAsync(ct).ConfigureAwait(false))
        {
            list.Add(new ObjectDdl
            {
                Name = reader.GetString(0),
                Table = reader.GetString(1),
                Type = reader.GetString(2),
                Definition = reader.GetString(3),
            });
        }
        return list;
    }

    public static async Task<IReadOnlyList<ObjectDdl>> LoadConstraintsAsync(
        NpgsqlDataSource source, string schema, CancellationToken ct)
    {
        const string sql = @"
            SELECT con.conname    AS name,
                   rel.relname    AS table_name,
                   con.contype::text AS type,
                   pg_catalog.pg_get_constraintdef(con.oid, true) AS definition
              FROM pg_catalog.pg_constraint con
              JOIN pg_catalog.pg_class     rel ON rel.oid = con.conrelid
              JOIN pg_catalog.pg_namespace nsp ON nsp.oid = con.connamespace
             WHERE nsp.nspname = $1
             ORDER BY rel.relname, con.conname";
        await using var cmd = source.CreateCommand(sql);
        cmd.Parameters.AddWithValue(schema);
        await using var reader = await cmd.ExecuteReaderAsync(ct).ConfigureAwait(false);
        var list = new List<ObjectDdl>();
        while (await reader.ReadAsync(ct).ConfigureAwait(false))
        {
            list.Add(new ObjectDdl
            {
                Name = reader.GetString(0),
                Table = reader.GetString(1),
                Type = reader.GetString(2),
                Definition = reader.GetString(3),
            });
        }
        return list;
    }
}
