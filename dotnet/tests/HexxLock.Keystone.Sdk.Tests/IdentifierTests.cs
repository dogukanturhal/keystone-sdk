// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 HexxLock

using FluentAssertions;
using HexxLock.Keystone.Sdk.Internal;
using Xunit;

namespace HexxLock.Keystone.Sdk.Tests;

public class IdentifierTests
{
    [Theory]
    [InlineData("public")]
    [InlineData("schema_migrations")]
    [InlineData("hr")]
    [InlineData("a")]
    [InlineData("_private")]
    [InlineData("a1b2c3")]
    public void Validate_AcceptsValidIdentifiers(string id)
    {
        var act = () => Identifier.Validate("schema", id);
        act.Should().NotThrow();
    }

    [Theory]
    [InlineData("")]
    [InlineData("1startsWithDigit")]
    [InlineData("UPPERCASE")]
    [InlineData("with-hyphen")]
    [InlineData("with space")]
    [InlineData("with;semicolon")]
    [InlineData("\"quoted\"")]
    public void Validate_RejectsInvalidIdentifiers(string id)
    {
        var act = () => Identifier.Validate("schema", id);
        act.Should().Throw<ArgumentException>()
            .WithMessage($"*invalid schema identifier \"{id}\"*");
    }

    [Fact]
    public void Validate_RejectsIdentifierLongerThan63Bytes()
    {
        var tooLong = new string('a', 64);
        var act = () => Identifier.Validate("schema", tooLong);
        act.Should().Throw<ArgumentException>();
    }

    [Fact]
    public void Quote_WrapsAndDoublesEmbeddedQuotes()
    {
        Identifier.Quote("public").Should().Be("\"public\"");
        Identifier.Quote("a\"b").Should().Be("\"a\"\"b\"");
        Identifier.Quote("").Should().Be("\"\"");
    }
}
