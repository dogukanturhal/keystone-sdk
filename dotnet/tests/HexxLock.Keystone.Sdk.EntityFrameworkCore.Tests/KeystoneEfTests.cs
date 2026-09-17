// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 HexxLock

using FluentAssertions;
using HexxLock.Keystone.Sdk.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using Xunit;

namespace HexxLock.Keystone.Sdk.EntityFrameworkCore.Tests;

public sealed class KeystoneEfTests
{
    // A minimal model. GenerateCreateScript renders DDL from this metadata
    // alone — no database connection is opened.
    private sealed class ShopContext : DbContext
    {
        public DbSet<Customer> Customers => Set<Customer>();
        public DbSet<Order> Orders => Set<Order>();

        protected override void OnConfiguring(DbContextOptionsBuilder options)
            => options.UseNpgsql("Host=unused;Database=unused");

        protected override void OnModelCreating(ModelBuilder b)
        {
            b.Entity<Customer>().HasIndex(c => c.Email).IsUnique();
            b.Entity<Order>()
                .HasOne<Customer>()
                .WithMany()
                .HasForeignKey(o => o.CustomerId);
        }
    }

    private sealed class Customer
    {
        public long Id { get; set; }
        public string Email { get; set; } = "";
    }

    private sealed class Order
    {
        public long Id { get; set; }
        public long CustomerId { get; set; }
        public long AmountCents { get; set; }
    }

    [Fact]
    public void ExportCreateScript_RendersTablesIndexesAndForeignKeys()
    {
        using var ctx = new ShopContext();

        var sql = KeystoneEf.ExportCreateScript(ctx);

        sql.Should().Contain("CREATE TABLE").And.Contain("Customers");
        sql.Should().Contain("Orders");
        // The unique index and the FK both come through.
        sql.Should().Contain("CREATE UNIQUE INDEX");
        sql.Should().Contain("FOREIGN KEY");
    }

    [Fact]
    public void ExportCreateScript_StripSchema_RemovesQualifier()
    {
        using var ctx = new SchemaQualifiedContext();

        // EF qualifies the table as `shop."Customers"` (schema emitted bare
        // because it is a valid lowercase identifier).
        var withSchema = KeystoneEf.ExportCreateScript(ctx);
        withSchema.Should().Contain("shop.\"Customers\"", "the model declares a default schema");

        var relative = KeystoneEf.ExportCreateScript(ctx, stripSchema: "shop");
        relative.Should().NotContain("shop.\"Customers\"", "stripSchema makes the table DDL schema-relative");
        relative.Should().Contain("\"Customers\"").And.Contain("CREATE TABLE");
    }

    private sealed class SchemaQualifiedContext : DbContext
    {
        public DbSet<Customer> Customers => Set<Customer>();

        protected override void OnConfiguring(DbContextOptionsBuilder options)
            => options.UseNpgsql("Host=unused;Database=unused");

        protected override void OnModelCreating(ModelBuilder b)
            => b.HasDefaultSchema("shop");
    }
}
