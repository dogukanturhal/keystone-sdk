// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 HexxLock

using FluentAssertions;
using Xunit;

namespace HexxLock.Keystone.Sdk.Tests;

[Collection(nameof(PostgresCollection))]
public class ApplyTests
{
    private readonly PostgresFixture _pg;

    public ApplyTests(PostgresFixture pg) => _pg = pg;

    /// <summary>
    /// Each test uses a fresh schema so the shared container can host them
    /// in parallel without cross-talk. xunit assigns unique short names via
    /// the test's <c>nameof</c>; suffix with a counter when needed.
    /// </summary>
    private static string FreshSchema() => $"sdk_t_{Guid.NewGuid():N}".Substring(0, 32);

    [Fact]
    public async Task Apply_HappyPath_CreatesTablesAndRecordsVersion()
    {
        var schema = FreshSchema();
        await CreateSchema(schema);

        var result = await Keystone.ApplyAsync(_pg.DataSource, new ApplyOptions
        {
            Schema = schema,
            Version = "v1",
            Files = new[]
            {
                new SqlFile
                {
                    Name = "001_init.up.sql",
                    Body = "CREATE TABLE items (id uuid PRIMARY KEY, name text NOT NULL);",
                },
            },
        });

        result.Version.Should().Be("v1");
        result.ContentHash.Should().MatchRegex("^[0-9a-f]{64}$");
        result.Files.Should().HaveCount(1);
        result.Files[0].File.Should().Be("001_init.up.sql");

        // Tracking row exists with the same hash
        var (recordedHash, dirty) = await ReadTrackingRow(schema, "v1");
        recordedHash.Should().Be(result.ContentHash);
        dirty.Should().BeFalse();

        // Schema actually changed
        (await TableExists(schema, "items")).Should().BeTrue();
    }

    [Fact]
    public async Task Apply_SameVersionSameHash_IsIdempotentNoOp()
    {
        var schema = FreshSchema();
        await CreateSchema(schema);

        var files = new[]
        {
            new SqlFile { Name = "001.sql", Body = "CREATE TABLE a (id int);" },
        };
        var first = await Keystone.ApplyAsync(_pg.DataSource, new ApplyOptions
        {
            Schema = schema, Version = "v1", Files = files,
        });

        var second = await Keystone.ApplyAsync(_pg.DataSource, new ApplyOptions
        {
            Schema = schema, Version = "v1", Files = files,
        });

        second.ContentHash.Should().Be(first.ContentHash);
        second.Files.Should().BeEmpty("no files re-run on no-op replay");
    }

    [Fact]
    public async Task Apply_SameVersionDifferentHash_Refuses()
    {
        var schema = FreshSchema();
        await CreateSchema(schema);

        await Keystone.ApplyAsync(_pg.DataSource, new ApplyOptions
        {
            Schema = schema, Version = "v1",
            Files = new[] { new SqlFile { Name = "001.sql", Body = "CREATE TABLE a (id int);" } },
        });

        var act = async () => await Keystone.ApplyAsync(_pg.DataSource, new ApplyOptions
        {
            Schema = schema, Version = "v1",
            Files = new[] { new SqlFile { Name = "001.sql", Body = "CREATE TABLE a (id bigint);" } },
        });

        await act.Should().ThrowAsync<InvalidOperationException>()
            .WithMessage("*already applied*bump Version*");
    }

    [Fact]
    public async Task Apply_ConcurrentlyKeyword_UsesNoTxPath()
    {
        var schema = FreshSchema();
        await CreateSchema(schema);

        // CONCURRENTLY refuses to run inside a transaction. If the runner
        // doesn't switch to no-tx mode, this Apply throws SQLSTATE 25001.
        var result = await Keystone.ApplyAsync(_pg.DataSource, new ApplyOptions
        {
            Schema = schema, Version = "v1",
            Files = new[]
            {
                new SqlFile
                {
                    Name = "001.sql",
                    Body = @"
                        CREATE TABLE t (id int, name text);
                        CREATE INDEX CONCURRENTLY ix_t_name ON t (name);
                    ",
                },
            },
        });

        result.Files.Should().HaveCount(1);
        (await TableExists(schema, "t")).Should().BeTrue();
    }

    [Fact]
    public async Task Apply_TrackingTableFollowsCustomName()
    {
        var schema = FreshSchema();
        await CreateSchema(schema);

        await Keystone.ApplyAsync(_pg.DataSource, new ApplyOptions
        {
            Schema = schema, Version = "v1",
            TrackingTable = "ks_history",
            Files = new[] { new SqlFile { Name = "001.sql", Body = "CREATE TABLE a (id int);" } },
        });

        (await TableExists(schema, "ks_history")).Should().BeTrue();
        (await TableExists(schema, "schema_migrations")).Should().BeFalse();
    }

    [Fact]
    public async Task Apply_RejectsInvalidSchema()
    {
        var act = async () => await Keystone.ApplyAsync(_pg.DataSource, new ApplyOptions
        {
            Schema = "Bad-Name",
            Version = "v1",
            Files = new[] { new SqlFile { Name = "001.sql", Body = "SELECT 1;" } },
        });

        await act.Should().ThrowAsync<ArgumentException>()
            .WithMessage("*invalid schema identifier*");
    }

    private async Task CreateSchema(string schema)
    {
        await using var cmd = _pg.DataSource.CreateCommand($"CREATE SCHEMA \"{schema}\"");
        await cmd.ExecuteNonQueryAsync();
    }

    private async Task<bool> TableExists(string schema, string table)
    {
        await using var cmd = _pg.DataSource.CreateCommand(@"
            SELECT 1 FROM information_schema.tables
             WHERE table_schema = $1 AND table_name = $2");
        cmd.Parameters.AddWithValue(schema);
        cmd.Parameters.AddWithValue(table);
        var result = await cmd.ExecuteScalarAsync();
        return result is not null;
    }

    private async Task<(string hash, bool dirty)> ReadTrackingRow(string schema, string version)
    {
        await using var cmd = _pg.DataSource.CreateCommand(
            $"SELECT content_hash, dirty FROM \"{schema}\".schema_migrations WHERE version = $1");
        cmd.Parameters.AddWithValue(version);
        await using var reader = await cmd.ExecuteReaderAsync();
        await reader.ReadAsync();
        return (reader.GetString(0), reader.GetBoolean(1));
    }
}
