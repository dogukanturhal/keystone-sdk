// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 HexxLock

namespace HexxLock.Keystone.Sdk;

/// <summary>
/// Introspected structural shape of a live schema. Tables are ordered by
/// name; columns are ordered by ordinal.
/// </summary>
public sealed record Snapshot
{
    /// <summary>Schema this snapshot was taken against.</summary>
    public required string Schema { get; init; }

    /// <summary>Base tables and views in the schema, ordered by name.</summary>
    public required IReadOnlyList<Table> Tables { get; init; }

    /// <summary>Indexes in the schema, ordered by (table, name).</summary>
    public required IReadOnlyList<ObjectDdl> Indexes { get; init; }

    /// <summary>Constraints in the schema, ordered by (table, name).</summary>
    public required IReadOnlyList<ObjectDdl> Constraints { get; init; }
}

/// <summary>One base table or view.</summary>
public sealed record Table
{
    /// <summary>Table name (unquoted).</summary>
    public required string Name { get; init; }

    /// <summary>e.g. <c>BASE TABLE</c>, <c>VIEW</c>.</summary>
    public required string Kind { get; init; }

    /// <summary>Columns ordered by ordinal position.</summary>
    public required IReadOnlyList<Column> Columns { get; init; }
}

/// <summary>One column's shape.</summary>
public sealed record Column
{
    /// <summary>Column name (unquoted).</summary>
    public required string Name { get; init; }

    /// <summary>1-based <c>information_schema.columns.ordinal_position</c>.</summary>
    public required int Ordinal { get; init; }

    /// <summary><c>information_schema.columns.data_type</c> — the SQL standard form (e.g. <c>character varying</c>).</summary>
    public required string DataType { get; init; }

    /// <summary><c>information_schema.columns.udt_name</c> — the PG-native type form (e.g. <c>varchar</c>, <c>uuid</c>).</summary>
    public required string UdtName { get; init; }

    /// <summary><c>true</c> when the column has no <c>NOT NULL</c> constraint.</summary>
    public required bool Nullable { get; init; }

    /// <summary><c>information_schema.columns.column_default</c>; empty string when there is no default.</summary>
    public required string Default { get; init; }
}

/// <summary>Generic <c>(name, table, type, definition)</c> shape used for indexes and constraints.</summary>
public sealed record ObjectDdl
{
    /// <summary>Object name (index name or constraint name, unquoted).</summary>
    public required string Name { get; init; }

    /// <summary>Owning table name.</summary>
    public required string Table { get; init; }

    /// <summary>Discriminator: <c>UNIQUE</c>/<c>INDEX</c> for indexes, <c>p</c>/<c>u</c>/<c>f</c>/<c>c</c> for constraints (matches <c>pg_constraint.contype</c>).</summary>
    public required string Type { get; init; }

    /// <summary>Reconstructed DDL: <c>pg_indexes.indexdef</c> for indexes, <c>pg_get_constraintdef</c> output for constraints.</summary>
    public required string Definition { get; init; }
}
