// SPDX-License-Identifier: AGPL-3.0-or-later

package analyze

import (
	"context"
	"regexp"
	"strings"

	keystonev1alpha1 "github.com/dogukanturhal/keystone/api/v1alpha1"
)

// Phase A2 — identifier hygiene rules.
//
// PostgreSQL allows identifiers up to NAMEDATALEN - 1 = 63 bytes and
// reserves any identifier starting with `pg_` for system use. Both
// limits are easy to run into with tooling-generated names — index
// names in particular can exceed the limit when concatenating table +
// column + suffix.

// -- Rule: max-identifier-length ---------------------------------------

// MaxIdentifierLength flags identifiers inside CREATE / ALTER / INDEX
// / CONSTRAINT declarations that are 60+ characters long. PostgreSQL
// silently truncates at 63 bytes, which is rarely what the author
// wanted — a truncated suffix collides with other identifiers. Default
// threshold is 60 (leaving 3 bytes of headroom).
type MaxIdentifierLength struct {
	// Threshold is the maximum length below which a name is fine.
	// Default 60. Set 63 to match PG exactly.
	Threshold int
}

func (MaxIdentifierLength) ID() string { return "max-identifier-length" }
func (MaxIdentifierLength) Description() string {
	return "PostgreSQL truncates identifiers at 63 bytes; warn at 60+"
}

// Capture identifiers in the common DDL positions.
var reNamedObjects = regexp.MustCompile(`(?i)\b(CREATE\s+(?:UNIQUE\s+)?INDEX(?:\s+CONCURRENTLY)?|CREATE\s+TABLE(?:\s+IF\s+NOT\s+EXISTS)?|CREATE\s+(?:MATERIALIZED\s+)?VIEW|CREATE\s+SEQUENCE|CREATE\s+FUNCTION|ALTER\s+TABLE|CONSTRAINT|REFERENCES)\s+(?:IF\s+NOT\s+EXISTS\s+)?"?([a-zA-Z_][a-zA-Z0-9_]*)"?`)

func (a *MaxIdentifierLength) Check(_ context.Context, m *Migration) ([]Finding, error) {
	threshold := a.Threshold
	if threshold == 0 {
		threshold = 60
	}
	var out []Finding
	for _, f := range m.Files {
		for _, match := range reNamedObjects.FindAllStringSubmatchIndex(f.Body, -1) {
			// match[2]..match[3] = subgroup 1 (keyword), match[4]..match[5] = subgroup 2 (identifier)
			if match[4] < 0 {
				continue
			}
			name := f.Body[match[4]:match[5]]
			if len(name) < threshold {
				continue
			}
			out = append(out, Finding{
				Rule:     a.ID(),
				Severity: keystonev1alpha1.LintLevelWarning,
				File:     f.Name,
				Line:     int32(lineOfOffset(f.Body, match[4])),
				Message: "identifier " + name + " is " + itoa(len(name)) + " chars; " +
					"PostgreSQL truncates at 63 bytes and a truncated suffix can collide " +
					"with other objects. Shorten to < " + itoa(threshold) + ".",
			})
		}
	}
	return out, nil
}

// -- Rule: no-pg-prefix-identifier -------------------------------------

// NoPgPrefixIdentifier flags user objects named with a `pg_` prefix.
// PostgreSQL reserves that prefix for system catalogues and will
// refuse to create some object kinds with the prefix at all; worse,
// future PG versions may add a system object with the same name and
// break user code that depended on it.
type NoPgPrefixIdentifier struct{}

func (NoPgPrefixIdentifier) ID() string { return "no-pg-prefix-identifier" }
func (NoPgPrefixIdentifier) Description() string {
	return "user objects named `pg_*` collide with system namespace"
}

// Match identifiers starting with pg_ in creation positions (table,
// index, view, function, sequence, constraint, role, schema). Keep
// narrow — we don't want to flag references to existing pg_ tables.
var rePgPrefix = regexp.MustCompile(`(?i)\b(CREATE\s+(?:UNIQUE\s+)?INDEX(?:\s+CONCURRENTLY)?|CREATE\s+TABLE|CREATE\s+(?:MATERIALIZED\s+)?VIEW|CREATE\s+SEQUENCE|CREATE\s+FUNCTION|CREATE\s+ROLE|CREATE\s+SCHEMA|ALTER\s+TABLE|CONSTRAINT)\s+(?:IF\s+NOT\s+EXISTS\s+)?"?(pg_\w+)"?`)

func (a *NoPgPrefixIdentifier) Check(_ context.Context, m *Migration) ([]Finding, error) {
	var out []Finding
	for _, f := range m.Files {
		for _, match := range rePgPrefix.FindAllStringSubmatchIndex(f.Body, -1) {
			if match[4] < 0 {
				continue
			}
			name := f.Body[match[4]:match[5]]
			if !strings.HasPrefix(strings.ToLower(name), "pg_") {
				continue
			}
			out = append(out, Finding{
				Rule:     a.ID(),
				Severity: keystonev1alpha1.LintLevelWarning,
				File:     f.Name,
				Line:     int32(lineOfOffset(f.Body, match[4])),
				Message: "object named " + name + " uses the reserved `pg_` prefix. " +
					"Future PostgreSQL versions may add a system object with the same " +
					"name and collide. Rename to a project-specific prefix.",
			})
		}
	}
	return out, nil
}
