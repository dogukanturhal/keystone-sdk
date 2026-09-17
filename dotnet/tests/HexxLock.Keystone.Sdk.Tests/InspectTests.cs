// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 HexxLock

using FluentAssertions;
using Xunit;

namespace HexxLock.Keystone.Sdk.Tests;

[Collection(nameof(PostgresCollection))]
public class InspectTests
{
    private readonly PostgresFixture _pg;

    public InspectTests(PostgresFixture pg) => _pg = pg;

    [Fact]
    public async Task Inspect_ReturnsTablesColumnsIndexesAndConstraints()
    {
        var schema = $"sdk_i_{Guid.NewGuid():N}".Substring(0, 32);
        await using (var cmd = _pg.DataSource.CreateCommand($"CREATE SCHEMA \"{schema}\""))
        {
            await cmd.ExecuteNonQueryAsync();
        }

        await Keystone.ApplyAsync(_pg.DataSource, new ApplyOptions
        {
            Schema = schema, Version = "v1",
            Files = new[]
            {
                new SqlFile
                {
                    Name = "001.sql",
                    Body = @"
                        CREATE TABLE customers (
                            id uuid PRIMARY KEY,
                            email text NOT NULL UNIQUE
                        );
                        CREATE INDEX ix_customers_email ON customers (email);
                    ",
                },
            },
        });

        var snap = await Keystone.InspectAsync(_pg.DataSource, schema);

        snap.Schema.Should().Be(schema);
        snap.Tables.Should().Contain(t => t.Name == "customers");
        var customers = snap.Tables.First(t => t.Name == "customers");
        customers.Kind.Should().Be("BASE TABLE");
        customers.Columns.Should().HaveCountGreaterOrEqualTo(2);
        customers.Columns.Should().Contain(c => c.Name == "id" && !c.Nullable);
        customers.Columns.Should().Contain(c => c.Name == "email" && !c.Nullable);

        snap.Indexes.Should().Contain(i => i.Name == "ix_customers_email");
        snap.Constraints.Should().Contain(c => c.Type == "p"); // primary key
    }
}
