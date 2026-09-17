// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 HexxLock

package sqlquote

import (
	"strings"
	"testing"
)

// Validation is the security-critical hot path between the API surface
// and DDL. Every identifier passed into the admin helpers MUST flow
// through ValidateIdentifier first; these tests pin the contract.
func TestValidateIdentifier(t *testing.T) {
	cases := []struct {
		name    string
		input   string
		wantErr bool
	}{
		// Happy path
		{"simple lowercase", "crm", false},
		{"underscore prefix", "_temp", false},
		{"underscore middle", "hexxlock_erp", false},
		{"digits after letter", "schema_2", false},
		{"max length 63", strings.Repeat("a", 63), false},

		// Reject paths
		{"empty", "", true},
		{"uppercase", "CRM", true},
		{"hyphen", "hexx-lock", true},
		{"starts with digit", "1schema", true},
		{"contains space", "my schema", true},
		{"contains semicolon", "crm;DROP", true},
		{"contains quote", `crm"or"1`, true},
		{"contains apostrophe", "crm'OR'1", true},
		{"contains backslash", `crm\x00`, true},
		{"contains null", "crm\x00", true},
		{"too long (64)", strings.Repeat("a", 64), true},
		{"unicode letter", "schémá", true},
		{"emoji", "🔥schema", true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateIdentifier("schema", tc.input)
			gotErr := err != nil
			if gotErr != tc.wantErr {
				t.Fatalf("ValidateIdentifier(%q) error = %v, wantErr=%v",
					tc.input, err, tc.wantErr)
			}
		})
	}
}

// TestValidateIdentifier_ExtensionAllowsHyphen — extension names follow
// PG's filesystem-based naming and the canonical "uuid-ossp" extension
// has a hyphen. The strict SQL-identifier validator rejects it; the
// "extension" kind opts into the relaxed pattern.
//
// Regression for the 2026-05-04 e2e: the realm-DB tenant SD called
// uuid_generate_v4(), the LogicalDatabase needed extensions:
// [uuid-ossp, pgcrypto], but the LD reconciler refused with:
//
//	invalid extension identifier "uuid-ossp": must match
//	^[a-z_][a-z0-9_]{0,62}$
//
// blocking the entire SD fan-out.
func TestValidateIdentifier_ExtensionAllowsHyphen(t *testing.T) {
	cases := []struct {
		kind, input string
		wantErr     bool
	}{
		// extension kind — hyphens allowed
		{"extension", "uuid-ossp", false},
		{"extension", "pgcrypto", false},
		{"extension", "pg_stat_statements", false},
		{"extension", "btree_gin", false},
		// extension kind still rejects bad inputs
		{"extension", "", true},
		{"extension", "1uuid", true},
		{"extension", "uuid;DROP", true},
		{"extension", "uuid'OR'1", true},
		{"extension", strings.Repeat("a", 64), true},
		// other kinds still reject hyphens
		{"schema", "uuid-ossp", true},
		{"role", "uuid-ossp", true},
		{"database", "uuid-ossp", true},
	}
	for _, tc := range cases {
		t.Run(tc.kind+"/"+tc.input, func(t *testing.T) {
			err := ValidateIdentifier(tc.kind, tc.input)
			gotErr := err != nil
			if gotErr != tc.wantErr {
				t.Fatalf("ValidateIdentifier(%q,%q) error = %v, wantErr=%v",
					tc.kind, tc.input, err, tc.wantErr)
			}
		})
	}
}

// QuoteIdentifier MUST handle embedded quotes by doubling them. A naive
// strings.Replace that misses this would let attacker-controlled
// identifier bytes break out of the quote context.
func TestQuoteIdentifier(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"crm", `"crm"`},
		{"hexxlock_erp", `"hexxlock_erp"`},
		// Even though ValidateIdentifier rejects these, QuoteIdentifier
		// must still escape them safely as a defence-in-depth layer.
		{`"`, `""""`},
		{`a"b`, `"a""b"`},
		{`""""`, `""""""""""`},
		{``, `""`},
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			if got := QuoteIdentifier(tc.in); got != tc.want {
				t.Errorf("QuoteIdentifier(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

// QuoteString must double single quotes and not consume backslashes
// (PostgreSQL's standard_conforming_strings=on default treats backslash
// as a literal character).
func TestQuoteString(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"hello", `'hello'`},
		{"O'Reilly", `'O''Reilly'`},
		{`a\nb`, `'a\nb'`},
		{`it's a "test"`, `'it''s a "test"'`},
		{``, `''`},
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			if got := QuoteString(tc.in); got != tc.want {
				t.Errorf("QuoteString(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}
