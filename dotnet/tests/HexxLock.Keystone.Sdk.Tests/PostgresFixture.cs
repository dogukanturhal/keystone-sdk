// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 HexxLock

using Npgsql;
using Testcontainers.PostgreSql;
using Xunit;

namespace HexxLock.Keystone.Sdk.Tests;

/// <summary>
/// xunit collection fixture: one Postgres container per test assembly
/// run, shared by every test class in the <see cref="PostgresCollection"/>.
/// Avoids paying container start (~3-5s) for each test class.
/// </summary>
public sealed class PostgresFixture : IAsyncLifetime
{
    private readonly PostgreSqlContainer _container;
    public NpgsqlDataSource DataSource { get; private set; } = null!;
    public string ConnectionString { get; private set; } = string.Empty;

    public PostgresFixture()
    {
        // Testcontainers 4.15 obsoleted the parameterless builder: the image
        // is a constructor argument so the default can no longer drift.
        _container = new PostgreSqlBuilder("postgres:16-alpine")
            .WithDatabase("keystone_sdk_test")
            .WithUsername("test")
            .WithPassword("test")
            .Build();
    }

    public async Task InitializeAsync()
    {
        await _container.StartAsync();
        ConnectionString = _container.GetConnectionString();
        DataSource = NpgsqlDataSource.Create(ConnectionString);
    }

    public async Task DisposeAsync()
    {
        await DataSource.DisposeAsync();
        await _container.DisposeAsync();
    }
}

[CollectionDefinition(nameof(PostgresCollection))]
public sealed class PostgresCollection : ICollectionFixture<PostgresFixture>;
