# keystone-sdk

[![CI](https://github.com/dogukanturhal/keystone-sdk/actions/workflows/ci.yml/badge.svg)](https://github.com/dogukanturhal/keystone-sdk/actions/workflows/ci.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/dogukanturhal/keystone-sdk/go.svg)](https://pkg.go.dev/github.com/dogukanturhal/keystone-sdk/go)
[![License](https://img.shields.io/badge/license-Apache--2.0%20%2B%20AGPL--3.0-blue.svg)](#license)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/dogukanturhal/keystone-sdk/badge)](https://scorecard.dev/viewer/?uri=github.com/dogukanturhal/keystone-sdk)

Go, Rust and .NET libraries that apply versioned SQL migrations to PostgreSQL
the same way the [Keystone](https://github.com/dogukanturhal/keystone)
operator does, without running the operator.

## Who it is for

Teams that want Keystone's migration behaviour (content-hashed versions, a
tracking table, `CONCURRENTLY`-aware execution, lint rules) inside a test
suite, a seeder, a CLI or an application start-up path. If you run
Kubernetes and want migrations reconciled from Git, use the operator
instead.

## What is usable today

Nothing here is published to a package registry except possibly a Go module
tag. Read this table before you add a dependency.

| SDK | Path | What it does | How to use it today |
|---|---|---|---|
| Go | [`go/`](./go) | `Apply`, `Lint`, `Inspect`, `Diff`, `Enroll` client plus the runner, analyzer, differ and drift inspector packages; a GORM schema provider. | The module is `github.com/dogukanturhal/keystone-sdk/go`. Tag `go/v0.4.0` exists on GitHub, so `go get github.com/dogukanturhal/keystone-sdk/go@v0.4.0` works; later changes on `main` are not tagged yet. pkg.go.dev may not have rendered it. |
| Rust | [`rust/`](./rust) | `keystone-sdk` crate (apply, inspect, lint, diff, authoring, schema sources) and a `keystonectl` CLI crate. | **Not on crates.io.** Build from source (`cargo build` in `rust/`) or depend on this repository by git URL. |
| .NET | [`dotnet/`](./dotnet) | `HexxLock.Keystone.Sdk` (Apply, Inspect), an EF Core schema provider and the `keystone-ef` dotnet tool. | **Not on NuGet.** An earlier version went to an internal package registry that is not reachable from outside. Build from source (`dotnet build`) and reference the project or a locally packed `.nupkg`. |

Plan, in order: tag the current Go state and confirm it resolves through the
module proxy; publish the Rust crates to crates.io; publish the .NET packages
to NuGet.org under a package id that is not tied to a company name (the
current `HexxLock.Keystone.Sdk` id will probably change, so treat it as
unstable). No dates.

The Go SDK was originally part of the operator repository; its move into
this repository is complete and recorded in [MIGRATION.md](MIGRATION.md).

## Features

- **Apply:** versioned migrations, run in a transaction by default, with an
  autocommit path for statements such as `CREATE INDEX CONCURRENTLY`. A
  tracking table records each version and its content hash. Re-applying the
  same version and hash is a no-op; the same version with different SQL is
  refused.
- **Inspect:** a structural snapshot of a database (tables, columns,
  indexes, constraints) read from the system catalogs.
- **Lint:** a rule pack that flags risky migration SQL (Go and Rust).
- **Diff:** compare an observed schema with a declared one and produce
  forward and reverse SQL (Go and Rust).
- **Authoring (Go, Rust):** write `NNN_name.up.sql` / `.down.sql` and a
  `keystone.sum` integrity file from a desired schema given as YAML, SQL or a
  live database.
- **ORM bridges:** `keystone-gorm` (Go) and `keystone-ef` (.NET) print the
  desired schema of your models as DDL, for use as a schema source.

The Go SDK has the most surface; the Rust SDK covers most of it; the .NET SDK
has Apply and Inspect only.

## Compatibility between SDKs

The three SDKs agree byte for byte on a few things, so one can apply a bundle
another already recorded:

1. Tracking-table DDL.
2. Content hash: SHA-256 over `name`, a zero byte, `body`, a zero byte, for
   each file in the supplied order, lowercase hex.
3. Identifier rule: `^[a-z_][a-z0-9_]{0,62}$`.
4. `CONCURRENTLY` detection switches to autocommit, per statement.
5. Upsert on the tracking insert.
6. The same wording when a version is re-applied with different SQL.

A change to any of these must land in all SDKs in one pull request.

## Quickstart (Go, about 5 minutes)

You need Go and a PostgreSQL you can write to. A throwaway container is fine:

```sh
docker run -d --name ks-pg -e POSTGRES_PASSWORD=pw -p 5432:5432 postgres:17
mkdir demo && cd demo && go mod init demo
go get github.com/dogukanturhal/keystone-sdk/go@v0.4.0
```

`main.go`:

```go
package main

import (
	"context"
	"fmt"
	"log"

	"github.com/jackc/pgx/v5/pgxpool"

	ks "github.com/dogukanturhal/keystone-sdk/go/keystone"
)

func main() {
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, "postgres://postgres:pw@localhost:5432/postgres")
	if err != nil {
		log.Fatal(err)
	}
	defer pool.Close()

	res, err := ks.Apply(ctx, pool, ks.ApplyOptions{
		Schema:  "public",
		Version: "v1",
		Files: []ks.SQLFile{{
			Name: "001_init.up.sql",
			Body: "CREATE TABLE IF NOT EXISTS items (id bigserial PRIMARY KEY, name text NOT NULL);",
		}},
	})
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("applied", res.Version, res.ContentHash)
}
```

```sh
go mod tidy && go run .
```

Run it twice: the second run is a no-op. Change the SQL without changing
`Version` and it is refused. The exact option and result fields are in
[go/keystone/README.md](go/keystone/README.md); this example follows it but
has not been compiled against `v0.4.0`, so check the README if the build
complains. Rust and .NET quickstarts are in
[rust/keystone-sdk/README.md](rust/keystone-sdk/README.md) and
[dotnet/README.md](dotnet/README.md).

Run the test suites from a clone:

```sh
(cd go && go test ./...)
(cd rust && cargo test --workspace)
(cd dotnet && dotnet test HexxLock.Keystone.Sdk.slnx)
```

Integration tests need PostgreSQL: set `KEYSTONE_TEST_DSN` and run
`go test -tags integration ./...` in `go/`. The .NET integration tests use
Testcontainers and need Docker.

## How it compares

- **Flyway, Liquibase:** mature, many databases, large ecosystems. These
  SDKs are narrower (PostgreSQL only) and exist mainly to share behaviour
  with the Keystone operator.
- **Atlas:** the Go library and CLI are stronger at schema diffing across
  engines. `keystone-sdk` offers a similar "desired schema in code, diff to a
  migration" flow for PostgreSQL, with SQL linting built in.
- **golang-migrate, goose:** simpler runners. They do not content-hash
  versions or lint.

## Architecture

```
 your code / CI / CLI
        │
 ┌──────▼───────┐     ┌────────────┐     ┌─────────────┐
 │  Go SDK      │     │  Rust SDK  │     │  .NET SDK   │   same hashes, same
 │  keystone    │     │  keystone- │     │  HexxLock.  │   tracking table
 │  migration   │     │  sdk       │     │  Keystone.  │
 │  analyze ... │     │            │     │  Sdk        │
 └──────┬───────┘     └─────┬──────┘     └──────┬──────┘
        └───────────────────┼───────────────────┘
                     ┌──────▼──────┐
                     │ PostgreSQL  │  schema_migrations tracking table
                     └─────────────┘
```

## Status and limitations

Pre-1.0 and not yet published (see the table above). APIs can change between
minor versions, whatever the Go `go/keystone` README says about stability.
The Go integration tests and the .NET Testcontainers suites need PostgreSQL
or Docker. The Go `keystone` client has a mixed licence (below), which rules
it out for some projects. Lint rule counts differ slightly between the
language READMEs; the code is the source of truth.

## License

This repository mixes two licences, per package:

- Apache-2.0 ([LICENSE](LICENSE)): the Rust crates, the .NET packages, and in
  Go the `keystone`, `sqlquote`, `authoring`, `schemaspec` and `schemasource`
  packages and the `keystone-gorm` command.
- AGPL-3.0-or-later ([LICENSE-AGPL](LICENSE-AGPL)): in Go, the `migration`,
  `analyze`, `declarative` and `drift` packages.

The SPDX header on each file is the authority where this summary and a file
disagree.

The Go `keystone` package imports the AGPL packages, so a program that links
it takes on the AGPL. For an Apache-only dependency use the Rust or .NET SDK.
The Go `go/README.md` has the details.

## Security

Report vulnerabilities privately as described in [SECURITY.md](SECURITY.md).

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Commits need a DCO sign-off
(`git commit -s`). Conduct: [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).
