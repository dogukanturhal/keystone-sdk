// SPDX-License-Identifier: AGPL-3.0-or-later

package migration

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

func sampleFiles() map[string]string {
	return map[string]string{
		"001_init.up.sql":  "CREATE TABLE users (id bigserial primary key);",
		"002_users.up.sql": "ALTER TABLE users ADD COLUMN email text;",
		"003_index.up.sql": "CREATE INDEX CONCURRENTLY ON users (email);",
	}
}

func TestBuildSumDeterministic(t *testing.T) {
	files := sampleFiles()
	a := BuildSum(files)
	b := BuildSum(files)
	if a.RootHash != b.RootHash {
		t.Fatalf("build is not deterministic: %s vs %s", a.RootHash, b.RootHash)
	}
	if len(a.Entries) != 3 {
		t.Fatalf("expected 3 entries, got %d", len(a.Entries))
	}
	// Entries must be sorted so VCS diffs are stable.
	for i := 1; i < len(a.Entries); i++ {
		if a.Entries[i-1].Name > a.Entries[i].Name {
			t.Fatalf("entries not sorted: %q then %q", a.Entries[i-1].Name, a.Entries[i].Name)
		}
	}
}

func TestBuildSumIgnoresSumFile(t *testing.T) {
	files := sampleFiles()
	raw := MarshalSum(BuildSum(files))
	// Adding keystone.sum as a resolved file must not change the sum.
	files[SumFilename] = string(raw)
	got := BuildSum(files)
	if len(got.Entries) != 3 {
		t.Fatalf("BuildSum included keystone.sum in entries: got %d", len(got.Entries))
	}
	for _, e := range got.Entries {
		if e.Name == SumFilename {
			t.Fatalf("entries must never list keystone.sum itself")
		}
	}
}

func TestMarshalParseRoundTrip(t *testing.T) {
	in := BuildSum(sampleFiles())
	raw := MarshalSum(in)
	out, err := ParseSum(raw)
	if err != nil {
		t.Fatalf("ParseSum failed: %v", err)
	}
	if out.RootHash != in.RootHash {
		t.Fatalf("root hash drift: want %s got %s", in.RootHash, out.RootHash)
	}
	if len(out.Entries) != len(in.Entries) {
		t.Fatalf("entry count drift: want %d got %d", len(in.Entries), len(out.Entries))
	}
	for i := range in.Entries {
		if in.Entries[i] != out.Entries[i] {
			t.Fatalf("entry %d drift: want %+v got %+v", i, in.Entries[i], out.Entries[i])
		}
	}
	if !bytes.Equal(raw, MarshalSum(out)) {
		t.Fatalf("MarshalSum not idempotent across parse/marshal")
	}
}

func TestMarshalShape(t *testing.T) {
	// Sanity — the serialised form must match the documented canonical
	// shape so tooling outside Keystone (git diff, GitLab UI, code review
	// bots) can count on it.
	s := BuildSum(map[string]string{"a.sql": "SELECT 1;"})
	raw := string(MarshalSum(s))
	lines := strings.Split(strings.TrimRight(raw, "\n"), "\n")
	if len(lines) != 2 {
		t.Fatalf("expected 2 lines, got %d: %q", len(lines), raw)
	}
	if !strings.HasPrefix(lines[0], "h1:") {
		t.Fatalf("line 1 missing h1: prefix: %q", lines[0])
	}
	if !strings.HasPrefix(lines[1], "a.sql h1:") {
		t.Fatalf("line 2 shape wrong: %q", lines[1])
	}
	if !strings.HasSuffix(raw, "\n") {
		t.Fatalf("sum file must end with newline")
	}
}

func TestVerifySumValid(t *testing.T) {
	files := sampleFiles()
	sum := BuildSum(files)
	if err := VerifySum(sum, files); err != nil {
		t.Fatalf("VerifySum on pristine bundle returned: %v", err)
	}
}

func TestVerifySumContentTamper(t *testing.T) {
	files := sampleFiles()
	sum := BuildSum(files)
	files["002_users.up.sql"] = "DROP TABLE users; -- sneaky"

	err := VerifySum(sum, files)
	if err == nil {
		t.Fatal("VerifySum accepted tampered content")
	}
	var mm *SumMismatch
	if !errors.As(err, &mm) {
		t.Fatalf("expected *SumMismatch, got %T: %v", err, err)
	}
	if mm.Kind != "content" || mm.Name != "002_users.up.sql" {
		t.Fatalf("unexpected mismatch: %+v", mm)
	}
	if mm.Expected == mm.Actual {
		t.Fatal("expected != actual — tamper should flip one of them")
	}
}

func TestVerifySumExtraFile(t *testing.T) {
	files := sampleFiles()
	sum := BuildSum(files)
	files["999_added.up.sql"] = "CREATE TABLE stowaway (id int);"

	err := VerifySum(sum, files)
	if err == nil {
		t.Fatal("VerifySum accepted extra file not listed in sum")
	}
	var mm *SumMismatch
	if !errors.As(err, &mm) {
		t.Fatalf("expected *SumMismatch, got %T", err)
	}
	if mm.Kind != "extra" || mm.Name != "999_added.up.sql" {
		t.Fatalf("unexpected mismatch: %+v", mm)
	}
}

func TestVerifySumMissingFile(t *testing.T) {
	files := sampleFiles()
	sum := BuildSum(files)
	delete(files, "003_index.up.sql")

	err := VerifySum(sum, files)
	if err == nil {
		t.Fatal("VerifySum accepted bundle missing a listed file")
	}
	var mm *SumMismatch
	if !errors.As(err, &mm) {
		t.Fatalf("expected *SumMismatch, got %T", err)
	}
	if mm.Kind != "missing" || mm.Name != "003_index.up.sql" {
		t.Fatalf("unexpected mismatch: %+v", mm)
	}
}

func TestVerifySumRootHashTamper(t *testing.T) {
	sum := BuildSum(sampleFiles())
	// Flip a byte in the stored root hash. VerifyRoot should catch it
	// before content checks begin.
	flipped := []byte(sum.RootHash)
	if flipped[0] == '0' {
		flipped[0] = '1'
	} else {
		flipped[0] = '0'
	}
	sum.RootHash = string(flipped)

	err := VerifySum(sum, sampleFiles())
	if err == nil {
		t.Fatal("VerifySum accepted tampered root hash")
	}
	var mm *SumMismatch
	if !errors.As(err, &mm) || mm.Kind != "root" {
		t.Fatalf("expected root Kind mismatch, got %v", err)
	}
}

func TestParseSumRejectsMalformed(t *testing.T) {
	cases := []struct {
		name string
		raw  string
	}{
		{"empty", ""},
		{"missing h1 prefix", "abc\n001.sql h1:0000000000000000000000000000000000000000000000000000000000000000\n"},
		{"short root hash", "h1:abc\n"},
		{"non-hex root", "h1:zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz\n"},
		{"missing space in entry", "h1:" + strings.Repeat("0", 64) + "\n001.sql-h1:" + strings.Repeat("0", 64) + "\n"},
		{"entry missing h1 prefix", "h1:" + strings.Repeat("0", 64) + "\n001.sql " + strings.Repeat("0", 64) + "\n"},
		{"entry hash too short", "h1:" + strings.Repeat("0", 64) + "\n001.sql h1:00\n"},
		{"self-reference", "h1:" + strings.Repeat("0", 64) + "\n" + SumFilename + " h1:" + strings.Repeat("0", 64) + "\n"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := ParseSum([]byte(tc.raw)); err == nil {
				t.Fatalf("ParseSum accepted malformed input: %q", tc.raw)
			}
		})
	}
}

func TestParseSumRejectsOutOfOrder(t *testing.T) {
	// Hand-built sum with entries in the wrong order — ParseSum must
	// refuse rather than silently normalise. Canonical ordering is a
	// review invariant (reviewers should see identical diffs regardless
	// of who generated the sum).
	h := strings.Repeat("0", 64)
	raw := "h1:" + h + "\n002.sql h1:" + h + "\n001.sql h1:" + h + "\n"
	if _, err := ParseSum([]byte(raw)); err == nil {
		t.Fatal("ParseSum accepted out-of-order entries")
	}
}

func TestParseSumRejectsDuplicates(t *testing.T) {
	h := strings.Repeat("0", 64)
	raw := "h1:" + h + "\n001.sql h1:" + h + "\n001.sql h1:" + h + "\n"
	if _, err := ParseSum([]byte(raw)); err == nil {
		t.Fatal("ParseSum accepted duplicate entry")
	}
}

func TestParseSumTolerantTrailingNewlines(t *testing.T) {
	// An extra trailing newline (common in editors that auto-add one) is
	// acceptable — we strip trailing \n before parsing.
	files := sampleFiles()
	raw := MarshalSum(BuildSum(files))
	_, err := ParseSum(append(raw, '\n', '\n'))
	if err != nil {
		t.Fatalf("ParseSum rejected extra trailing newlines: %v", err)
	}
}

func TestFileHashStableAcrossRuns(t *testing.T) {
	// Lock the primitive — if anyone changes the hash formula, every
	// committed keystone.sum in every Git tree breaks.
	got := FileHash("migrations/001_init.up.sql", "CREATE TABLE t (id int);")
	want := "662665dd2588e4710126a3a68923f0932a4a7ebecc8acb21a0876fc461a8d425"
	if got != want {
		t.Fatalf("FileHash drifted: got %s want %s", got, want)
	}
}
