// SPDX-License-Identifier: AGPL-3.0-or-later

package analyze

import (
	"context"
	"regexp"
	"strings"

	keystonev1alpha1 "github.com/dogukanturhal/keystone/api/v1alpha1"
)

// Phase A2 — PostgreSQL type and schema-declaration conventions.
//
// These rules push authors toward the modern PG types that every
// production team eventually converges on. Calibrated as warnings /
// notices — they are not blockers, but persistent violation signals an
// author unaware of the PG edge cases.

// -- Rule: no-varchar-without-limit ------------------------------------

// NoVarcharWithoutLimit flags VARCHAR (a.k.a. CHARACTER VARYING) used
// without a length specifier. Unbounded VARCHAR has the same storage as
// TEXT but carries a length-check bit of overhead on assignment. The
// PostgreSQL documentation explicitly recommends TEXT when no bound is
// needed and VARCHAR(N) when there is one.
type NoVarcharWithoutLimit struct{}

func (NoVarcharWithoutLimit) ID() string { return "no-varchar-without-limit" }
func (NoVarcharWithoutLimit) Description() string {
	return "unbounded VARCHAR has no advantage over TEXT; be explicit"
}

// RE2 has no negative lookahead; use the two-regex pattern already
// established for timestamp-vs-timestamptz. reVarcharAny matches every
// occurrence; reVarcharBounded matches the bounded `VARCHAR(N)` form —
// we flag lines where the former matches and the latter does not.
var reVarcharAny = regexp.MustCompile(`(?i)\b(VARCHAR|CHARACTER\s+VARYING)\b`)
var reVarcharBounded = regexp.MustCompile(`(?i)\b(VARCHAR|CHARACTER\s+VARYING)\s*\(`)

func (a *NoVarcharWithoutLimit) Check(_ context.Context, m *Migration) ([]Finding, error) {
	var out []Finding
	for _, f := range m.Files {
		for i, line := range strings.Split(f.Body, "\n") {
			if !reVarcharAny.MatchString(line) {
				continue
			}
			// If every VARCHAR on this line is followed by `(`, the
			// count of bounded matches equals the count of total
			// matches — nothing to flag. We re-scan with the bounded
			// regex because a single line may mix both forms.
			anyCount := len(reVarcharAny.FindAllStringIndex(line, -1))
			boundedCount := len(reVarcharBounded.FindAllStringIndex(line, -1))
			if boundedCount >= anyCount {
				continue
			}
			out = append(out, Finding{
				Rule:     a.ID(),
				Severity: keystonev1alpha1.LintLevelNotice,
				File:     f.Name,
				Line:     int32(i + 1),
				Message: "unbounded VARCHAR / CHARACTER VARYING has no advantage over TEXT. " +
					"Use TEXT when the length is unbounded, VARCHAR(N) when it isn't.",
			})
		}
	}
	return out, nil
}

// -- Rule: prefer-jsonb-over-json --------------------------------------

// PreferJsonbOverJson flags `json` column type in favour of `jsonb`.
// `json` stores the original text verbatim — no indexing, no
// normalization, repeated key lookups re-parse on every query.
// `jsonb` stores a decomposed binary form, supports GIN indexes, and
// is the right default for almost every new column.
type PreferJsonbOverJson struct{}

func (PreferJsonbOverJson) ID() string { return "prefer-jsonb-over-json" }
func (PreferJsonbOverJson) Description() string {
	return "use JSONB for indexability and parse-once storage; JSON only for strict round-trip"
}

// Match `json` as a column type only — `json` can appear elsewhere
// (comments, function names, identifier "json"). We anchor on the
// "<name> json" pattern inside DDL: column name followed by
// whitespace followed by the word JSON. `\bJSON\b` does NOT match the
// leading JSON of JSONB (J→S→O→N→B is all word chars, so there's no
// word boundary between N and B) — no negative-lookahead needed.
var reJsonType = regexp.MustCompile(`(?i)\b\w+\s+JSON\b`)

// Narrow the match to DDL contexts only — don't flag SELECT using
// json_build_object etc. A quick and cheap check: skip files that
// have no CREATE TABLE / ADD COLUMN / ALTER COLUMN.
func hasColumnDeclaration(body string) bool {
	return regexp.MustCompile(`(?i)\b(CREATE\s+TABLE|ADD\s+COLUMN|ALTER\s+COLUMN)\b`).MatchString(body)
}

func (a *PreferJsonbOverJson) Check(_ context.Context, m *Migration) ([]Finding, error) {
	var out []Finding
	for _, f := range m.Files {
		if !hasColumnDeclaration(f.Body) {
			continue
		}
		for i, line := range strings.Split(f.Body, "\n") {
			if !reJsonType.MatchString(line) {
				continue
			}
			out = append(out, Finding{
				Rule:     a.ID(),
				Severity: keystonev1alpha1.LintLevelNotice,
				File:     f.Name,
				Line:     int32(i + 1),
				Message: "column typed as JSON. JSONB is binary-decomposed, indexable " +
					"(GIN / path-ops), and parses once at INSERT. JSON preserves " +
					"whitespace + key order — useful only for strict byte-round-trip.",
			})
		}
	}
	return out, nil
}

// -- Rule: no-numeric-without-precision --------------------------------

// NoNumericWithoutPrecision flags NUMERIC / DECIMAL columns declared
// without a precision spec. Unbounded NUMERIC has variable-precision
// arbitrary-digit storage; it's slow, big, and almost always wrong
// for a column that represents "money", "percentage", or any real-
// world metric. Explicit NUMERIC(p, s) forces the author to think
// about the range.
type NoNumericWithoutPrecision struct{}

func (NoNumericWithoutPrecision) ID() string { return "no-numeric-without-precision" }
func (NoNumericWithoutPrecision) Description() string {
	return "NUMERIC without precision is arbitrary-digit; declare (p, s) explicitly"
}

// Same two-regex pattern as VARCHAR.
var reNumericAny = regexp.MustCompile(`(?i)\b\w+\s+(NUMERIC|DECIMAL)\b`)
var reNumericBounded = regexp.MustCompile(`(?i)\b\w+\s+(NUMERIC|DECIMAL)\s*\(`)

func (a *NoNumericWithoutPrecision) Check(_ context.Context, m *Migration) ([]Finding, error) {
	var out []Finding
	for _, f := range m.Files {
		if !hasColumnDeclaration(f.Body) {
			continue
		}
		for i, line := range strings.Split(f.Body, "\n") {
			if !reNumericAny.MatchString(line) {
				continue
			}
			anyCount := len(reNumericAny.FindAllStringIndex(line, -1))
			boundedCount := len(reNumericBounded.FindAllStringIndex(line, -1))
			if boundedCount >= anyCount {
				continue
			}
			out = append(out, Finding{
				Rule:     a.ID(),
				Severity: keystonev1alpha1.LintLevelNotice,
				File:     f.Name,
				Line:     int32(i + 1),
				Message: "unbounded NUMERIC / DECIMAL stores arbitrary-precision digits — slow, " +
					"heavy, and usually wrong. Declare the intended range: " +
					"NUMERIC(12, 2) for money, NUMERIC(5, 4) for probabilities, etc.",
			})
		}
	}
	return out, nil
}

// -- Rule: require-if-not-exists-on-create-table -----------------------

// RequireIfNotExistsOnCreateTable flags CREATE TABLE without IF NOT
// EXISTS. Under GitOps + retry loops, a migration may be re-applied
// after a partial failure; IF NOT EXISTS makes CREATE TABLE idempotent
// so the retry doesn't error. Not universally required — some shops
// prefer strict mode — so this is a Notice.
type RequireIfNotExistsOnCreateTable struct{}

func (RequireIfNotExistsOnCreateTable) ID() string { return "require-if-not-exists-on-create-table" }
func (RequireIfNotExistsOnCreateTable) Description() string {
	return "CREATE TABLE IF NOT EXISTS makes migrations idempotent under retry"
}

var reCreateTableStrict = regexp.MustCompile(`(?i)\bCREATE\s+TABLE\s+(\w+)\b`)
var reCreateTableIfNotExists = regexp.MustCompile(`(?i)\bCREATE\s+TABLE\s+IF\s+NOT\s+EXISTS\b`)

func (a *RequireIfNotExistsOnCreateTable) Check(_ context.Context, m *Migration) ([]Finding, error) {
	var out []Finding
	for _, f := range m.Files {
		for i, line := range strings.Split(f.Body, "\n") {
			if !reCreateTableStrict.MatchString(line) {
				continue
			}
			if reCreateTableIfNotExists.MatchString(line) {
				continue
			}
			out = append(out, Finding{
				Rule:     a.ID(),
				Severity: keystonev1alpha1.LintLevelNotice,
				File:     f.Name,
				Line:     int32(i + 1),
				Message: "CREATE TABLE without IF NOT EXISTS. Retries after partial failure " +
					"re-run the whole file — add IF NOT EXISTS to make creation idempotent.",
			})
		}
	}
	return out, nil
}

// -- Rule: no-uuid-generate-v1 -----------------------------------------

// NoUuidGenerateV1 flags uuid_generate_v1() / v1mc(). V1 UUIDs encode
// the host MAC address and a timestamp — leaking both in every row's
// primary key. Since PG 13, `gen_random_uuid()` is in core and
// produces v4 UUIDs with no leak.
type NoUuidGenerateV1 struct{}

func (NoUuidGenerateV1) ID() string { return "no-uuid-generate-v1" }
func (NoUuidGenerateV1) Description() string {
	return "uuid_generate_v1 leaks host MAC + timestamp; use gen_random_uuid()"
}

var reUuidV1 = regexp.MustCompile(`(?i)\buuid_generate_v1(mc)?\s*\(`)

func (a *NoUuidGenerateV1) Check(_ context.Context, m *Migration) ([]Finding, error) {
	return statementMatches(m, reUuidV1, keystonev1alpha1.LintLevelWarning,
		a.ID(),
		"uuid_generate_v1 / v1mc encode host MAC address + timestamp, leaking both "+
			"in every row's identifier. On PG 13+, gen_random_uuid() produces "+
			"v4 UUIDs with no leakage and no extension required."), nil
}
