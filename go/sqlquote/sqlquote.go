// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 HexxLock
//
// This file was extracted from
// github.com/dogukanturhal/keystone/internal/postgres/quote.go
// and re-licensed under Apache-2.0 by the copyright holder so the SDK
// can ship its quoting helpers as a stable, narrow public surface.

// Package sqlquote provides PostgreSQL identifier and literal quoting
// helpers used by the Keystone SDK and its operator. The functions are
// kept intentionally small and stable so external consumers can depend
// on them without taking on the full migration / drift surface.
package sqlquote

import (
	"fmt"
	"regexp"
	"strings"
)

// QuoteIdentifier returns the input wrapped per PostgreSQL identifier
// rules — double quotes around the value with embedded double quotes
// doubled. Use this for EVERY identifier passed into DDL: database name,
// role name, schema name, extension name. PostgreSQL parameter binding
// ($1, $2, …) does NOT apply to DDL identifiers.
//
// Mirrors pq.QuoteIdentifier; the reason it lives here is that pgx
// dropped the helper and we don't want to import lib/pq just for this
// 6-line function.
func QuoteIdentifier(name string) string {
	return `"` + strings.ReplaceAll(name, `"`, `""`) + `"`
}

// QuoteString returns the input wrapped in PostgreSQL string literal
// quoting (single-quote with embedded singles doubled). Used only when
// no parameter binding is available — e.g. inside DO blocks. Prefer
// parameterized queries everywhere else.
func QuoteString(s string) string {
	return `'` + strings.ReplaceAll(s, `'`, `''`) + `'`
}

// validIdentifier matches the API-validated pattern for PostgreSQL
// identifiers: lowercase letter or underscore, then lowercase
// alphanumeric or underscore, max 63 bytes (PG NAMEDATALEN-1).
var validIdentifier = regexp.MustCompile(`^[a-z_][a-z0-9_]{0,62}$`)

// validExtension is the relaxed pattern for PostgreSQL extension names.
// Extension names follow PG's filesystem-based naming (the .control file
// in $libdir/extension/), which allows hyphens — most notably
// "uuid-ossp" (uuid generators v1/v3/v4/v5), but also pgx-prelude,
// pg_stat_kcache (no hyphen), etc. Without this relaxation the
// validator rejects "uuid-ossp" with:
//
//	invalid extension identifier "uuid-ossp": must match ^[a-z_][a-z0-9_]{0,62}$
//
// which blocks LogicalDatabase reconcile when spec.extensions
// references it. CREATE EXTENSION "uuid-ossp" is the canonical SQL
// syntax (extension name quoted because of the hyphen) and PostgreSQL
// accepts it.
var validExtension = regexp.MustCompile(`^[a-z_][a-z0-9_-]{0,62}$`)

// ValidateIdentifier defends in depth — even though admission webhooks
// reject invalid identifiers at API level, the controller verifies again
// before issuing DDL. This catches bypass scenarios (CR applied via stale
// validating webhook, manually-injected resource, etc.).
//
// "extension" kind is checked against validExtension (allows hyphens
// like uuid-ossp); all other kinds (database, role, schema) use the
// strict SQL-identifier pattern.
func ValidateIdentifier(kind, name string) error {
	pat := validIdentifier
	patStr := `^[a-z_][a-z0-9_]{0,62}$`
	if kind == "extension" {
		pat = validExtension
		patStr = `^[a-z_][a-z0-9_-]{0,62}$`
	}
	if !pat.MatchString(name) {
		return fmt.Errorf(
			"invalid %s identifier %q: must match %s",
			kind, name, patStr,
		)
	}
	return nil
}
