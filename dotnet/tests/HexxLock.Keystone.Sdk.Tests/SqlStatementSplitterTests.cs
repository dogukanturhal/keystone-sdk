// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 HexxLock

using FluentAssertions;
using HexxLock.Keystone.Sdk.Internal;
using Xunit;

namespace HexxLock.Keystone.Sdk.Tests;

/// <summary>
/// Parity tests with <c>internal/migration/sqlsplit_test.go</c> in the Go
/// SDK. Each case represents a hazard the splitter must navigate without
/// false-splitting on a semicolon inside a quoted region or comment.
/// </summary>
public class SqlStatementSplitterTests
{
    [Fact]
    public void EmptyInput_ReturnsEmpty()
    {
        SqlStatementSplitter.Split("").Should().BeEmpty();
        SqlStatementSplitter.Split("   \n\t  ").Should().BeEmpty();
        SqlStatementSplitter.Split(";").Should().BeEmpty();
    }

    [Fact]
    public void SimpleSplit_OnTopLevelSemicolon()
    {
        var parts = SqlStatementSplitter.Split("SELECT 1; SELECT 2;");
        parts.Should().Equal("SELECT 1;", "SELECT 2;");
    }

    [Fact]
    public void TrailingStatementWithoutSemicolon_IsKept()
    {
        var parts = SqlStatementSplitter.Split("SELECT 1; SELECT 2");
        parts.Should().Equal("SELECT 1;", "SELECT 2");
    }

    [Fact]
    public void SemicolonInsideSingleQuote_IsNotASplit()
    {
        var parts = SqlStatementSplitter.Split("INSERT INTO t VALUES ('a;b'); SELECT 1");
        parts.Should().Equal("INSERT INTO t VALUES ('a;b');", "SELECT 1");
    }

    [Fact]
    public void EscapedSingleQuote_IsTransparent()
    {
        var parts = SqlStatementSplitter.Split("INSERT INTO t VALUES ('it''s; fine'); SELECT 1");
        parts.Should().Equal("INSERT INTO t VALUES ('it''s; fine');", "SELECT 1");
    }

    [Fact]
    public void SemicolonInsideDoubleQuote_IsNotASplit()
    {
        var parts = SqlStatementSplitter.Split("SELECT 1 FROM \"weird;name\"; SELECT 2");
        parts.Should().Equal("SELECT 1 FROM \"weird;name\";", "SELECT 2");
    }

    [Fact]
    public void DollarQuoting_BareDollarDollar()
    {
        var parts = SqlStatementSplitter.Split("DO $$ BEGIN SELECT 1; END $$; SELECT 2");
        parts.Should().Equal("DO $$ BEGIN SELECT 1; END $$;", "SELECT 2");
    }

    [Fact]
    public void DollarQuoting_TaggedBody()
    {
        var parts = SqlStatementSplitter.Split("CREATE FUNCTION f() RETURNS int AS $body$ SELECT 1; $body$ LANGUAGE sql; SELECT 2");
        parts.Should().Equal(
            "CREATE FUNCTION f() RETURNS int AS $body$ SELECT 1; $body$ LANGUAGE sql;",
            "SELECT 2");
    }

    [Fact]
    public void LineComment_DoesNotSplit()
    {
        var parts = SqlStatementSplitter.Split("SELECT 1; -- a; b\nSELECT 2");
        parts.Should().Equal("SELECT 1;", "-- a; b\nSELECT 2");
    }

    [Fact]
    public void BlockComment_DoesNotSplit()
    {
        var parts = SqlStatementSplitter.Split("SELECT 1 /* a;b;c */; SELECT 2");
        parts.Should().Equal("SELECT 1 /* a;b;c */;", "SELECT 2");
    }

    [Fact]
    public void TrimsSurroundingWhitespace()
    {
        var parts = SqlStatementSplitter.Split("\n\nSELECT 1;\n\n\nSELECT 2;\n");
        parts.Should().Equal("SELECT 1;", "SELECT 2;");
    }
}
