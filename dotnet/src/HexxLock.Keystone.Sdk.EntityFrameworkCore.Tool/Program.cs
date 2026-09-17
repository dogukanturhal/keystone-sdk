// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 HexxLock

// keystone-ef — the Keystone schema provider for Entity Framework Core.
//
// Prints an EF Core model's desired schema as PostgreSQL DDL on stdout so
// Keystone can consume it through the exec:// source scheme:
//
//     dotnet new tool-manifest
//     dotnet tool install --local keystone-ef
//     keystonectl migrate diff add_customer \
//         --desired 'exec://dotnet keystone-ef' \
//         --dev-url postgres://…/devdb --dir migrations
//
// Why a tool and not just the library: HexxLock.Keystone.Sdk.EntityFrameworkCore
// exposes ExportCreateScript(DbContext), but calling it requires the caller
// to write a Program.cs that constructs their own DbContext. A provider has
// to be runnable against an arbitrary project with no code changes, which is
// what `dotnet ef` already solves — it builds the startup project, resolves
// the design-time DbContext (IDesignTimeDbContextFactory, the host builder,
// or the parameterless constructor) and runs inside it. So this tool drives
// `dotnet ef dbcontext script`, which renders the model's full CREATE DDL
// while bypassing migrations entirely, and then makes the result safe to
// pipe: EF's build chatter is kept off stdout, and the DDL is optionally
// rewritten to be schema-relative for Keystone's scratch-schema normaliser.

using System.Diagnostics;
using System.Reflection;
using System.Text;

namespace HexxLock.Keystone.Sdk.EntityFrameworkCore.Tool;

internal static class Program
{
    /// <summary>
    /// The package version, read from the assembly rather than duplicated as
    /// a constant — CI stamps it from the <c>dotnet-vX.Y.Z</c> tag, and a
    /// hand-maintained copy would drift from what NuGet actually serves.
    /// </summary>
    private static string Version =>
        (typeof(Program).Assembly
            .GetCustomAttribute<AssemblyInformationalVersionAttribute>()
            ?.InformationalVersion ?? "0.0.0")
        .Split('+')[0];

    internal static async Task<int> Main(string[] args)
    {
        try
        {
            return await RunAsync(args).ConfigureAwait(false);
        }
        catch (UsageException ex)
        {
            Console.Error.WriteLine($"keystone-ef: {ex.Message}");
            Console.Error.WriteLine("try `keystone-ef --help`");
            return 2;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"keystone-ef: {ex.Message}");
            return 1;
        }
    }

    private static async Task<int> RunAsync(string[] args)
    {
        var opts = Options.Parse(args);

        if (opts.ShowHelp)
        {
            Console.Error.WriteLine(HelpText);
            return 0;
        }
        if (opts.ShowVersion)
        {
            Console.Out.WriteLine(Version);
            return 0;
        }

        // `dotnet ef` writes build progress ("Build started...", "Build
        // succeeded.") to stdout alongside the SQL. Routing the script to a
        // temp file via --output keeps stdout clean by construction rather
        // than by pattern-matching EF's chatter, which changes between
        // releases and is localised.
        var scriptPath = Path.Combine(Path.GetTempPath(), $"keystone-ef-{Guid.NewGuid():N}.sql");
        try
        {
            var exit = await RunDotnetEfAsync(opts, scriptPath).ConfigureAwait(false);
            if (exit != 0)
            {
                return exit;
            }
            if (!File.Exists(scriptPath))
            {
                throw new InvalidOperationException(
                    "`dotnet ef dbcontext script` reported success but produced no script. " +
                    "Confirm the project references Microsoft.EntityFrameworkCore.Design and that a DbContext is discoverable (`dotnet ef dbcontext list`).");
            }

            var ddl = await File.ReadAllTextAsync(scriptPath).ConfigureAwait(false);
            ddl = Rewrite.Apply(ddl, opts.StripSchema);

            if (string.IsNullOrWhiteSpace(ddl))
            {
                throw new InvalidOperationException(
                    "the generated schema is empty — the DbContext resolved but declares no entities.");
            }

            await Console.Out.WriteAsync(ddl).ConfigureAwait(false);
            if (!ddl.EndsWith('\n'))
            {
                await Console.Out.WriteLineAsync().ConfigureAwait(false);
            }
            await Console.Out.FlushAsync().ConfigureAwait(false);
            return 0;
        }
        finally
        {
            try
            {
                if (File.Exists(scriptPath))
                {
                    File.Delete(scriptPath);
                }
            }
            catch (IOException)
            {
                // A leftover temp file is not worth failing the run over.
            }
        }
    }

    /// <summary>
    /// Invokes `dotnet ef dbcontext script`, forwarding the project-selection
    /// options verbatim. EF's stdout is redirected to this process's stderr so
    /// build output stays visible to a human without contaminating the DDL
    /// stream a caller is capturing.
    /// </summary>
    private static async Task<int> RunDotnetEfAsync(Options opts, string scriptPath)
    {
        var psi = new ProcessStartInfo("dotnet")
        {
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
        };
        foreach (var a in new[] { "ef", "dbcontext", "script", "--output", scriptPath })
        {
            psi.ArgumentList.Add(a);
        }
        foreach (var a in opts.EfPassThrough)
        {
            psi.ArgumentList.Add(a);
        }

        using var proc = new Process { StartInfo = psi };
        var stderr = new StringBuilder();
        proc.OutputDataReceived += (_, e) =>
        {
            if (e.Data is not null)
            {
                Console.Error.WriteLine(e.Data);
            }
        };
        proc.ErrorDataReceived += (_, e) =>
        {
            if (e.Data is not null)
            {
                stderr.AppendLine(e.Data);
                Console.Error.WriteLine(e.Data);
            }
        };

        try
        {
            proc.Start();
        }
        catch (Exception ex)
        {
            throw new InvalidOperationException(
                $"could not run `dotnet ef`: {ex.Message}. Install it with `dotnet tool install --global dotnet-ef` " +
                "and add Microsoft.EntityFrameworkCore.Design to the project.", ex);
        }

        proc.BeginOutputReadLine();
        proc.BeginErrorReadLine();
        await proc.WaitForExitAsync().ConfigureAwait(false);

        if (proc.ExitCode != 0)
        {
            Console.Error.WriteLine(
                $"keystone-ef: `dotnet ef dbcontext script` exited {proc.ExitCode}; see the output above.");
        }
        return proc.ExitCode;
    }

    private const string HelpText = """
        keystone-ef — export an EF Core model as Keystone schema-as-code.

        Prints the DbContext's desired schema as PostgreSQL DDL on stdout.
        Diagnostics and build output go to stderr, so stdout is always
        pipeable as pure DDL.

        USAGE
          keystone-ef [options]

        OPTIONS
          --strip-schema <name>    Remove the "<name>". qualifier EF Core emits
                                   when the model declares a default schema, and
                                   drop the matching CREATE SCHEMA statement.
                                   Keystone applies DDL under a scratch schema's
                                   search_path, so schema-relative is the shape
                                   it wants.
          --context <name>         DbContext to use (-c). Required when the
                                   project declares more than one.
          --project <path>         Target project folder (-p).
          --startup-project <path> Startup project folder (-s).
          --framework <tfm>        Target framework, for multi-targeted projects.
          --configuration <cfg>    Build configuration (Debug/Release).
          --no-build               Skip the build; use when it is up to date.
          --verbose                Forward -v to dotnet ef.
          --version                Print the provider version and exit.
          -h, --help               Show this help.

        KEYSTONE USAGE
          keystonectl migrate diff add_customer \
              --desired 'exec://dotnet keystone-ef' \
              --dev-url postgres://localhost/devdb --dir migrations

          …or, in keystone.yaml:

            desired:
              program: [dotnet, keystone-ef]

        REQUIREMENTS
          dotnet-ef tool (`dotnet tool install --global dotnet-ef`) and a
          Microsoft.EntityFrameworkCore.Design reference in the project. No
          database connection is needed — the schema comes from the model.
        """;
}

/// <summary>Signals a bad command line, reported with usage rather than a stack.</summary>
internal sealed class UsageException(string message) : Exception(message);

/// <summary>Parsed command line for the provider.</summary>
internal sealed record Options
{
    public bool ShowHelp { get; private init; }
    public bool ShowVersion { get; private init; }
    public string? StripSchema { get; private init; }

    /// <summary>Options forwarded to `dotnet ef` unchanged.</summary>
    public IReadOnlyList<string> EfPassThrough { get; private init; } = [];

    public static Options Parse(string[] args)
    {
        var help = false;
        var version = false;
        string? stripSchema = null;
        var passThrough = new List<string>();

        for (var i = 0; i < args.Length; i++)
        {
            var a = args[i];
            switch (a)
            {
                case "-h" or "--help":
                    help = true;
                    break;
                case "--version":
                    version = true;
                    break;
                case "--strip-schema":
                    stripSchema = Next(args, ref i, a);
                    break;

                // Project selection is EF's job, so forward it verbatim
                // rather than re-deriving semantics EF already defines.
                case "-c" or "--context":
                    passThrough.Add("--context");
                    passThrough.Add(Next(args, ref i, a));
                    break;
                case "-p" or "--project":
                    passThrough.Add("--project");
                    passThrough.Add(Next(args, ref i, a));
                    break;
                case "-s" or "--startup-project":
                    passThrough.Add("--startup-project");
                    passThrough.Add(Next(args, ref i, a));
                    break;
                case "--framework":
                    passThrough.Add("--framework");
                    passThrough.Add(Next(args, ref i, a));
                    break;
                case "--configuration":
                    passThrough.Add("--configuration");
                    passThrough.Add(Next(args, ref i, a));
                    break;
                case "--no-build":
                    passThrough.Add("--no-build");
                    break;
                case "-v" or "--verbose":
                    passThrough.Add("--verbose");
                    break;
                default:
                    throw new UsageException($"unknown option {a}");
            }
        }

        return new Options
        {
            ShowHelp = help,
            ShowVersion = version,
            StripSchema = stripSchema,
            EfPassThrough = passThrough,
        };
    }

    private static string Next(string[] args, ref int i, string flag)
    {
        if (i + 1 >= args.Length)
        {
            throw new UsageException($"{flag} requires a value");
        }
        return args[++i];
    }
}
