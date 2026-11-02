# Contributing to keystone-sdk

Thanks for helping. This repository holds the Go, Rust and .NET SDKs for
[Keystone](https://github.com/dogukanturhal/keystone). See the README for the
licence of each part (Apache-2.0, plus AGPL-3.0-or-later for some Go
packages).

## Before you start

- Open an issue first for anything that changes behaviour, public API, or the
  wire-compatibility rules in the README. Small fixes, tests and docs can go
  straight to a pull request.
- Anything that changes the content hash, the tracking-table DDL, identifier
  validation, `CONCURRENTLY` detection, the tracking upsert or the
  re-apply error text must be changed in **all three SDKs in the same pull
  request**, with a test in each.
- Security issues do not belong in issues: see [SECURITY.md](SECURITY.md).

## Sign off your commits (DCO)

Every commit needs a `Signed-off-by` line, which certifies the
[Developer Certificate of Origin](https://developercertificate.org/):

```sh
git commit -s -m "go/migration: handle empty files"
```

To fix a missing sign-off: `git commit --amend -s`, or
`git rebase --signoff main` for several commits.

## Development setup

Go (`go/`; version in `go/go.mod`):

```sh
cd go
go vet ./...
go test -race ./...
# integration tests need PostgreSQL:
KEYSTONE_TEST_DSN='postgres://user:pw@localhost:5432/postgres?sslmode=disable' \
  go test -tags integration -p 1 ./...
```

Rust (`rust/`; MSRV 1.80):

```sh
cd rust
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace
```

.NET (`dotnet/`; .NET 8 and 10):

```sh
cd dotnet
dotnet build HexxLock.Keystone.Sdk.slnx --configuration Release
dotnet test HexxLock.Keystone.Sdk.slnx --configuration Release   # needs Docker
```

## Pull requests

- Branch from `main`; keep the change focused.
- Commit messages: short imperative subject prefixed with the area
  (`rust/lint: ...`), body says why.
- Add or update tests, in every SDK the change touches.
- Update `CHANGELOG.md` under `## Unreleased`.
- New source files carry an `SPDX-License-Identifier` header matching the
  package they live in.

A maintainer will review. Contributions are licensed under the licence of the
part of the tree they touch.

## Keep pull requests small

This project has one maintainer who reads every line before merging. Large pull requests can't be reviewed properly, so they are not accepted.

- **One change per pull request.** One bug fix, one feature, or one refactor. Don't mix formatting or unrelated clean-ups into it.
- **Size limit: 400 changed lines and 15 files** (additions plus deletions; `go.sum`, `package-lock.json`, `Cargo.lock` and generated files don't count). Aim for under 200. An automated check fails pull requests over the limit.
- **Bigger change? Open an issue first.** Describe the plan and we'll agree on how to split it into a series of small pull requests that each build and pass tests on their own.
- Exceptions (for example, a large test fixture) only with a maintainer's agreement in the issue.

## AI-assisted contributions

You may use AI tools, under these conditions:

- **Say so** in the pull request description, and name what the tool did (for example "tests drafted with an AI assistant, then reviewed and edited").
- **You are the author.** You must understand every line and be able to explain and change it during review. "The tool wrote it" is not an answer to a review question.
- **Same rules as everyone:** the size limit above, tests, and the licence/sign-off requirements. You confirm you have the right to submit the code.
- Pull requests that look generated without review (code that doesn't fit the codebase, invented APIs, a PR description that doesn't match the diff, or no answers to review questions) are closed without detailed review.

## How your contribution lands

This GitHub repository is a mirror of our main development repository. When a pull request is merged here, we import it there with your authorship and sign-off preserved, and it comes back in the next sync. You don't need to do anything extra.

## Conduct

Participation is covered by the [Code of Conduct](CODE_OF_CONDUCT.md).
