// SPDX-License-Identifier: Apache-2.0

// Package authoring renders a declarative.Plan into a versioned,
// reversible Keystone migration bundle: an `NNN_name.up.sql` /
// `NNN_name.down.sql` pair that satisfies the five migration-authoring
// standards (statement_timeout header, leading comment, schema-relative
// DDL, idempotent IF EXISTS rollbacks, paired up/down) by construction.
//
// It is the bridge between schema-as-code and the GitOps bundle format:
// `keystonectl migrate diff` and `keystonectl scaffold` both call
// RenderUpDown to turn a computed diff into files an author commits. The
// package is pure — no database, no filesystem, no Kubernetes — so it is
// trivially unit-testable and reusable by any tool that already has a
// *declarative.Plan in hand.
//
// The forward statements come from plan.Statements verbatim; the down
// file replays plan.ReverseStatements in reverse order (so a rollback
// undoes the most-recent change first). Statements the differ marked
// irreversible (empty reverse) are rendered as explicit comment markers
// rather than silently dropped, keeping the down file an honest record
// of what can and cannot be rolled back.
package authoring

import (
	"fmt"
	"path/filepath"
	"regexp"
	"strings"
	"sync"

	"github.com/dogukanturhal/keystone-sdk/go/declarative"
	pg "github.com/dogukanturhal/keystone-sdk/go/sqlquote"
)

// DefaultStatementTimeout is prepended to every rendered file as
// `SET LOCAL statement_timeout = '<this>';` per migration-authoring §2.
// 30s fails fast on an accidental non-CONCURRENTLY index build against a
// large table rather than blasting a production lock.
const DefaultStatementTimeout = "30s"

// Options controls how a Plan is rendered into a bundle.
type Options struct {
	// Name is the human-readable change slug (e.g. "add_users_email_index").
	// Sanitised into the filename; non [a-z0-9_] runes become underscores.
	Name string

	// Version is the zero-padded ordinal prefix (e.g. "002"). Use
	// NextVersion to derive it from an existing directory.
	Version string

	// Schema is the target schema name, recorded in the file header for
	// reviewers. Does not affect the SQL (migrations are schema-relative;
	// the runner sets search_path).
	Schema string

	// StatementTimeout overrides DefaultStatementTimeout when non-empty.
	StatementTimeout string

	// GeneratedBy is a provenance string for the header comment
	// (e.g. "keystonectl v0.2.0").
	GeneratedBy string

	// StripSchema, when non-empty, rewrites the generated SQL to be
	// schema-relative by removing the `"<StripSchema>".` qualifier the
	// differ emits (it qualifies every object with observed.Schema). This
	// yields portable migrations the runner can apply against any target
	// schema via search_path, per migration-authoring §4. Set it to the
	// schema the diff was computed against.
	StripSchema string
}

// Bundle is the rendered file set for a single migration.
type Bundle struct {
	Version  string // "002"
	Name     string // sanitised slug, "add_users_email_index"
	UpFile   string // "002_add_users_email_index.up.sql"
	DownFile string // "002_add_users_email_index.down.sql"
	Up       string // up.sql contents
	Down     string // down.sql contents
}

// Files returns the bundle as a filename→content map suitable for
// writing to disk and for migration.BuildSum (which the caller uses to
// regenerate keystone.sum over the whole directory).
func (b Bundle) Files() map[string]string {
	return map[string]string{
		b.UpFile:   b.Up,
		b.DownFile: b.Down,
	}
}

// RenderUpDown renders plan into a Bundle. The forward file applies
// plan.Statements in order; the down file applies plan.ReverseStatements
// in reverse order so rollback unwinds most-recent-first. A nil plan
// yields empty Up/Down bodies (header only).
func RenderUpDown(plan *declarative.Plan, opts Options) Bundle {
	timeout := opts.StatementTimeout
	if timeout == "" {
		timeout = DefaultStatementTimeout
	}
	slug := sanitizeSlug(opts.Name)
	base := opts.Version
	if base != "" && slug != "" {
		base = base + "_" + slug
	} else if slug != "" {
		base = slug
	}

	b := Bundle{
		Version:  opts.Version,
		Name:     slug,
		UpFile:   base + ".up.sql",
		DownFile: base + ".down.sql",
	}

	var up, down []entry
	if plan != nil {
		for _, s := range plan.Statements {
			if s = strings.TrimSpace(stripSchema(s, opts.StripSchema)); s != "" {
				up = append(up, entry{sql: s})
			}
		}
		// Reverse order: ReverseStatements[i] undoes Statements[i], so a
		// rollback must run the LAST change's reverse first.
		for i := len(plan.ReverseStatements) - 1; i >= 0; i-- {
			r := strings.TrimSpace(stripSchema(plan.ReverseStatements[i], opts.StripSchema))
			if r == "" {
				// Irreversible forward op (e.g. DROP COLUMN data loss).
				fwd := ""
				if i < len(plan.Statements) {
					fwd = firstLine(plan.Statements[i])
				}
				down = append(down, entry{comment: "irreversible: no automatic rollback for: " + fwd})
				continue
			}
			down = append(down, entry{sql: r})
		}
	}

	// A down file with no executable statements (fully irreversible, or an
	// empty plan) still needs a valid, non-empty body so the rollback
	// orchestrator does not fail on a missing/empty file (§5).
	if !hasSQL(down) {
		down = append(down, entry{
			sql: "SELECT 'irreversible: see migration notes for the rollback procedure' AS rollback_note",
		})
	}

	b.Up = renderFile(opts, slug, "up", timeout, up)
	b.Down = renderFile(opts, slug, "down", timeout, down)
	return b
}

// NextVersion returns the next zero-padded ordinal given the names of
// existing migrations (filenames or bare version strings). It reads the
// leading run of digits of each, takes the max, and increments — padding
// to at least three digits, or wider if any existing version already is.
// An empty input yields "001".
func NextVersion(existing []string) string {
	maxN, width := 0, 3
	for _, e := range existing {
		b := filepath.Base(e)
		j := 0
		for j < len(b) && b[j] >= '0' && b[j] <= '9' {
			j++
		}
		if j == 0 {
			continue
		}
		digits := b[:j]
		n := 0
		for _, c := range digits {
			n = n*10 + int(c-'0')
		}
		if len(digits) > width {
			width = len(digits)
		}
		if n > maxN {
			maxN = n
		}
	}
	return fmt.Sprintf("%0*d", width, maxN+1)
}

// entry is one line of a rendered file: either a SQL statement (gets a
// trailing semicolon) or a standalone comment (emitted verbatim).
type entry struct {
	sql     string
	comment string
}

func hasSQL(entries []entry) bool {
	for _, e := range entries {
		if e.sql != "" {
			return true
		}
	}
	return false
}

// renderFile assembles the file body: provenance comment header, the
// mandatory SET LOCAL statement_timeout, then the statements/comments
// separated by blank lines.
func renderFile(opts Options, slug, direction, timeout string, entries []entry) string {
	var sb strings.Builder

	// Leading comment (satisfies require-migration-comment; gives
	// reviewers intent + provenance at a glance).
	title := slug
	if title == "" {
		title = "migration"
	}
	fmt.Fprintf(&sb, "-- %s (%s)\n", title, direction)
	gen := opts.GeneratedBy
	if gen == "" {
		gen = "keystone authoring"
	}
	fmt.Fprintf(&sb, "-- generated by %s from a declarative schema diff; edit the SchemaDefinition, not this file.\n", gen)
	if opts.Schema != "" {
		fmt.Fprintf(&sb, "-- target schema: %s\n", opts.Schema)
	}
	sb.WriteByte('\n')

	// Mandatory per-file statement timeout (migration-authoring §2).
	fmt.Fprintf(&sb, "SET LOCAL statement_timeout = '%s';\n", timeout)

	for _, e := range entries {
		sb.WriteByte('\n')
		if e.comment != "" {
			fmt.Fprintf(&sb, "-- %s\n", e.comment)
			continue
		}
		sb.WriteString(e.sql)
		// The differ emits bare statements without a terminator; add one.
		if !strings.HasSuffix(strings.TrimRight(e.sql, " \t"), ";") {
			sb.WriteByte(';')
		}
		sb.WriteByte('\n')
	}
	return sb.String()
}

// sanitizeSlug lowercases and replaces any rune outside [a-z0-9_] with an
// underscore, collapsing runs and trimming leading/trailing underscores.
func sanitizeSlug(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	var sb strings.Builder
	prevUnderscore := false
	for _, r := range s {
		switch {
		case (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9'):
			sb.WriteRune(r)
			prevUnderscore = false
		default:
			if !prevUnderscore {
				sb.WriteByte('_')
				prevUnderscore = true
			}
		}
	}
	return strings.Trim(sb.String(), "_")
}

// stripSchema removes the `"<schema>".` qualifier the differ prepends to
// every object, yielding schema-relative DDL. A no-op when schema is
// empty. The differ always quotes the schema (pg.QuoteIdentifier), so the
// token is unambiguous and will not collide with unqualified identifiers.
// StripSchemaQualifier removes the `"<schema>".` qualifier from a single
// statement, yielding schema-relative SQL.
//
// Exported for exec:// schema providers (cmd/keystone-gorm and friends),
// which render DDL through the differ and must hand Keystone unqualified
// statements: the dev-database normaliser applies them under a scratch
// schema's search_path, and a qualifier would pin every object to a
// schema that is not the one being diffed. Shares the one implementation
// with RenderUpDown so authored migrations and provider output can never
// disagree about what "schema-relative" means.
func StripSchemaQualifier(sql, schema string) string { return stripSchema(sql, schema) }

func stripSchema(sql, schema string) string {
	if schema == "" || sql == "" {
		return sql
	}
	// Quoted form: what the differ emits, since it quotes every
	// identifier it renders.
	sql = strings.ReplaceAll(sql, pg.QuoteIdentifier(schema)+".", "")

	// Unquoted form: what PostgreSQL's own deparsers emit. A view body
	// comes back from pg_get_viewdef as `SELECT ... FROM app.orders`,
	// with no quotes on a lowercase identifier, so the replacement above
	// misses it entirely and the qualifier is written into the authored
	// migration. Applying that bundle anywhere the authoring schema does
	// not exist fails with 42P01, and applying it where the schema does
	// exist is worse — the statement silently reads and writes the wrong
	// schema instead of the one the bundle was fanned out to.
	//
	// The boundary check keeps a schema named `app` from also rewriting
	// `myapp.` or a qualified `other.app.` reference. Go's regexp has no
	// lookbehind, so the preceding character is captured and put back.
	return unquotedSchemaRef(schema).ReplaceAllString(sql, "$1")
}

// unquotedSchemaRefCache memoises the per-schema pattern; stripSchema is
// called once per statement per rendered file.
var (
	unquotedSchemaRefCache sync.Map // schema string -> *regexp.Regexp
)

func unquotedSchemaRef(schema string) *regexp.Regexp {
	if re, ok := unquotedSchemaRefCache.Load(schema); ok {
		return re.(*regexp.Regexp)
	}
	re := regexp.MustCompile(`(^|[^A-Za-z0-9_."])` + regexp.QuoteMeta(schema) + `\.`)
	unquotedSchemaRefCache.Store(schema, re)
	return re
}

func firstLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return strings.TrimSpace(s[:i])
	}
	return s
}
