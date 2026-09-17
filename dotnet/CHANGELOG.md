# HexxLock.Keystone.Sdk changelog

## 0.1.0 — initial release

- `Keystone.ApplyAsync(NpgsqlDataSource, ApplyOptions)` — versioned,
  content-hashed SQL migration runner. `schema_migrations` bookkeeping,
  in-tx by default with autocommit fallback when the bundle contains
  `CONCURRENTLY`.
- `Keystone.InspectAsync(NpgsqlDataSource, string)` — read-only
  structural snapshot (tables, columns, indexes, constraints) from
  `information_schema` + `pg_catalog`.
- Wire-compatible with the Go SDK at
  `github.com/dogukanturhal/keystone/pkg/sdk/keystone` — same
  tracking-table DDL, same SHA-256 algorithm over
  `(name‖0x00‖body‖0x00)`, same `CONCURRENTLY` detection regex, same
  UPSERT semantics on the tracking row.
- Targets `net8.0` and `net10.0`.
- Single dependency: `Npgsql 9.x`.
