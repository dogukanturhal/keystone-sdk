# Schema round-trip conformance corpus

Each `testdata/*.sql` file is a schema the harness must be able to
inspect, describe, re-author and re-apply without losing anything.

`TestConvergence` asserts three properties per file. See the test's doc
comment for what each one catches and which production bug motivated it.

## Adding an entry

Add a `.sql` file. It is picked up automatically — there is no list to
update.

Two rules:

- **Schema-relative DDL only.** No `myschema.` qualifiers. The harness
  applies each file under a throwaway scratch schema's `search_path`, so
  a qualifier would point somewhere that does not exist.
- **Self-contained.** No dependency on another corpus file; each is
  materialised into its own scratch schema.

## When a bug escapes to production, add it here

That is the point of the corpus. Before this existed, 8 of the last 17
commits touching the differ were single-symptom fixes found in the field
— a trailing semicolon on a matview body, a missing comma before a
composite primary key, `IN (list)` not matching `= ANY (ARRAY[...])`.
Each was a whole class discovered one instance at a time.

Reproduce the schema shape here first; the harness should go red. Then
fix it.

## Running locally

```console
# against a throwaway container (needs Docker)
go test -tags integration -count=1 ./conformance/

# against a database you already have
KEYSTONE_TEST_DSN='postgres://user:pw@localhost:5432/devdb?sslmode=disable' \
  go test -tags integration -count=1 -run TestConvergence/orm_quoted ./conformance/
```

The harness **skips** when it finds neither, so that a laptop without a
Docker daemon can still run `go test -tags integration ./...`. CI
therefore asserts `KEYSTONE_TEST_DSN` is set before running — a gate that
reports success while testing nothing is worse than no gate.

## Known corpus gaps

- **Extensions installed outside the schema.** The inspector scopes
  extensions to the schema being inspected; one a schema depends on but
  does not own — `pgcrypto` in `public`, say — is provisioned by
  `LogicalDatabase.spec.extensions`, a layer this harness does not cover.
- **Partitioned tables, inheritance, foreign tables, collations, domains,
  exclusion constraints.** Not represented yet.
