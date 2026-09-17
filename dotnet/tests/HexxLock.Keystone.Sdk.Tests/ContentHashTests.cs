// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 HexxLock

using System.Security.Cryptography;
using System.Text;
using FluentAssertions;
using HexxLock.Keystone.Sdk.Internal;
using Xunit;

namespace HexxLock.Keystone.Sdk.Tests;

/// <summary>
/// Parity tests for <see cref="ContentHash"/>. The Go SDK's
/// <c>migration.HashFiles</c> hashes <c>name‖0x00‖body‖0x00</c> per file in
/// supplied order via <c>sha256.New().Sum(nil)</c>, hex-encoded lowercase.
/// These tests pin that contract in C# so the Go and .NET SDKs produce
/// byte-identical content hashes for the same bundle.
/// </summary>
public class ContentHashTests
{
    [Fact]
    public void Compute_SingleFile_MatchesGoldenSha256()
    {
        var files = new[]
        {
            new SqlFile { Name = "001_init.up.sql", Body = "CREATE TABLE t (id int);" }
        };

        var actual = ContentHash.Compute(files);

        var expected = ComputeReferenceHash(files);
        actual.Should().Be(expected);
        actual.Should().MatchRegex("^[0-9a-f]{64}$");
    }

    [Fact]
    public void Compute_PreservesFileOrder()
    {
        var a = new SqlFile { Name = "a.sql", Body = "alpha" };
        var b = new SqlFile { Name = "b.sql", Body = "beta" };

        var ab = ContentHash.Compute(new[] { a, b });
        var ba = ContentHash.Compute(new[] { b, a });

        ab.Should().NotBe(ba, "ordering is part of the hash domain");
    }

    [Fact]
    public void Compute_NameAndBodyAreNotInterchangeable()
    {
        var x = ContentHash.Compute(new[] { new SqlFile { Name = "a", Body = "b" } });
        var y = ContentHash.Compute(new[] { new SqlFile { Name = "b", Body = "a" } });
        x.Should().NotBe(y, "the NUL separator distinguishes name from body");
    }

    [Fact]
    public void Compute_EmptyContent_IsStable()
    {
        var emptyName = new[] { new SqlFile { Name = "", Body = "" } };
        var hash = ContentHash.Compute(emptyName);
        // sha256(0x00 0x00) — two NUL bytes
        hash.Should().Be("96a296d224f285c67bee93c30f8a309157f0daa35dc5b87e410b78630a09cfc7");
    }

    /// <summary>
    /// Re-implement the Go contract directly so the two implementations
    /// can be cross-checked without spawning a Go process. If this drifts,
    /// either the Go SDK or the C# SDK changed the algorithm.
    /// </summary>
    private static string ComputeReferenceHash(IReadOnlyList<SqlFile> files)
    {
        using var sha = SHA256.Create();
        var nul = new byte[] { 0x00 };
        foreach (var f in files)
        {
            var name = Encoding.UTF8.GetBytes(f.Name);
            var body = Encoding.UTF8.GetBytes(f.Body);
            sha.TransformBlock(name, 0, name.Length, null, 0);
            sha.TransformBlock(nul, 0, 1, null, 0);
            sha.TransformBlock(body, 0, body.Length, null, 0);
            sha.TransformBlock(nul, 0, 1, null, 0);
        }
        sha.TransformFinalBlock(Array.Empty<byte>(), 0, 0);
        return Convert.ToHexString(sha.Hash!).ToLowerInvariant();
    }
}
