// SPDX-License-Identifier: AGPL-3.0-or-later

package migration

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
)

// SumFilename is the well-known file name for a bundle's integrity sum.
// By convention this file is committed to Git alongside the *.sql files
// and shipped inside the MigrationSource (ConfigMap data key, OCI
// artifact entry, or Git path). The resolver strips it out of Files
// before hashing so it is never treated as a migration statement.
const SumFilename = "keystone.sum"

// SumHashPrefix tags every hash in keystone.sum with its algorithm so
// the format can evolve (e.g. h2: for a future BLAKE3 migration) without
// ambiguity. Matches Atlas's `h1:` convention for familiarity.
const SumHashPrefix = "h1:"

// SumStatus reports the outcome of verifying a resolved bundle against
// its committed keystone.sum. The webhook and controller surface it on
// the MigrationBundle's IntegrityVerified condition.
type SumStatus string

const (
	// SumStatusValid — keystone.sum is present, parses cleanly, and every
	// per-file hash matches the resolved content. Root hash matches.
	SumStatusValid SumStatus = "Valid"

	// SumStatusMissing — no keystone.sum in the resolved source. Not an
	// error on its own; policy decides whether to require it.
	SumStatusMissing SumStatus = "Missing"

	// SumStatusMalformed — keystone.sum exists but fails to parse. Always
	// an error; the committer shipped a broken file.
	SumStatusMalformed SumStatus = "Malformed"

	// SumStatusMismatch — keystone.sum exists and parses, but at least
	// one file's hash disagrees with the committed sum (tamper, merge
	// botch, or author forgot to regenerate). Always an error.
	SumStatusMismatch SumStatus = "Mismatch"
)

// SumEntry is one `<name> h1:<hex>` line in a keystone.sum document.
type SumEntry struct {
	Name string
	Hash string // hex-encoded SHA-256 (no h1: prefix)
}

// SumFile is the parsed representation of a keystone.sum document.
//
// Canonical serialisation:
//
//	h1:<hex64>                     ← root hash (sha256 of body bytes)
//	<name-1> h1:<hex64>
//	<name-2> h1:<hex64>
//	...
//
// Entries are sorted lexicographically by Name. The body is every line
// after the root line (terminating newlines included); the root hash is
// SHA-256(body) in hex. Any edit to any byte changes the root, which
// forces a VCS merge conflict when two branches both add migrations.
type SumFile struct {
	// RootHash is the hex-encoded SHA-256 of the body (lines 2..end of
	// the canonical form). Empty in a zero-value SumFile.
	RootHash string

	// Entries are sorted by Name. Empty-entry SumFiles are legal (an
	// empty directory has root hash SHA-256("") = e3b0…b855).
	Entries []SumEntry
}

// FileHash returns the per-file hash stored in a keystone.sum entry. It
// deliberately mirrors HashFiles's streaming primitive on a single file
// so the root hash and ContentHash share a mental model: both are
// SHA-256 over (name || NUL || content || NUL) tuples.
func FileHash(name, content string) string {
	h := sha256.New()
	h.Write([]byte(name))
	h.Write([]byte{0})
	h.Write([]byte(content))
	h.Write([]byte{0})
	return hex.EncodeToString(h.Sum(nil))
}

// BuildSum computes the SumFile for the given files. Names are sorted
// before hashing; callers do not need to pre-sort. Any file named
// SumFilename is ignored (you don't list keystone.sum inside itself).
func BuildSum(files map[string]string) SumFile {
	names := make([]string, 0, len(files))
	for n := range files {
		if n == SumFilename {
			continue
		}
		names = append(names, n)
	}
	sort.Strings(names)

	entries := make([]SumEntry, 0, len(names))
	for _, n := range names {
		entries = append(entries, SumEntry{
			Name: n,
			Hash: FileHash(n, files[n]),
		})
	}

	body := sumBody(entries)
	root := sha256.Sum256(body)
	return SumFile{
		RootHash: hex.EncodeToString(root[:]),
		Entries:  entries,
	}
}

// MarshalSum serialises a SumFile to its canonical byte form. The
// output always ends in a newline. MarshalSum(BuildSum(files)) is
// idempotent byte-for-byte given the same inputs.
func MarshalSum(s SumFile) []byte {
	var buf bytes.Buffer
	buf.WriteString(SumHashPrefix)
	buf.WriteString(s.RootHash)
	buf.WriteByte('\n')
	buf.Write(sumBody(s.Entries))
	return buf.Bytes()
}

// ParseSum parses a keystone.sum document. Tolerant of trailing
// whitespace and trailing newline; intolerant of everything else —
// malformed files surface as SumStatusMalformed rather than being
// silently "repaired".
func ParseSum(raw []byte) (SumFile, error) {
	if len(raw) == 0 {
		return SumFile{}, fmt.Errorf("empty sum file")
	}
	// Split on '\n' but keep an eye on the fact that the root hash line
	// is BEFORE the body — so the root hashes everything after it.
	lines := strings.Split(strings.TrimRight(string(raw), "\n"), "\n")
	if len(lines) == 0 {
		return SumFile{}, fmt.Errorf("empty sum file")
	}

	// Line 1: root. `h1:<hex64>`.
	rootLine := strings.TrimSpace(lines[0])
	if !strings.HasPrefix(rootLine, SumHashPrefix) {
		return SumFile{}, fmt.Errorf("line 1: root hash must start with %q", SumHashPrefix)
	}
	root := strings.TrimPrefix(rootLine, SumHashPrefix)
	if err := validateHex256(root); err != nil {
		return SumFile{}, fmt.Errorf("line 1: invalid root hash: %w", err)
	}

	// Lines 2..end: per-file entries.
	entries := make([]SumEntry, 0, len(lines)-1)
	for i, line := range lines[1:] {
		ln := i + 2
		if strings.TrimSpace(line) == "" {
			return SumFile{}, fmt.Errorf("line %d: blank line not permitted inside sum body", ln)
		}
		// `<name> h1:<hex64>` — name is everything up to the LAST space
		// (filenames may contain embedded spaces; the hash token cannot).
		idx := strings.LastIndex(line, " ")
		if idx < 1 {
			return SumFile{}, fmt.Errorf("line %d: missing space separator", ln)
		}
		name := line[:idx]
		hashTok := strings.TrimSpace(line[idx+1:])
		if !strings.HasPrefix(hashTok, SumHashPrefix) {
			return SumFile{}, fmt.Errorf("line %d: hash must start with %q", ln, SumHashPrefix)
		}
		h := strings.TrimPrefix(hashTok, SumHashPrefix)
		if err := validateHex256(h); err != nil {
			return SumFile{}, fmt.Errorf("line %d: %w", ln, err)
		}
		if name == SumFilename {
			return SumFile{}, fmt.Errorf("line %d: keystone.sum must not list itself", ln)
		}
		entries = append(entries, SumEntry{Name: name, Hash: h})
	}

	// Reject duplicate filenames and enforce sorted order; BuildSum
	// always emits sorted, so out-of-order input is a hand-edited sum
	// we refuse to accept.
	for i := 1; i < len(entries); i++ {
		if entries[i-1].Name == entries[i].Name {
			return SumFile{}, fmt.Errorf("duplicate entry for %q", entries[i].Name)
		}
		if entries[i-1].Name > entries[i].Name {
			return SumFile{}, fmt.Errorf("entries not sorted: %q before %q", entries[i-1].Name, entries[i].Name)
		}
	}

	return SumFile{RootHash: root, Entries: entries}, nil
}

// VerifyRoot checks that the SumFile's RootHash matches SHA-256 of its
// own body. Defends against hand-edited sum files where someone changed
// a per-file hash but forgot to recompute the root. Called internally by
// VerifySum; exported for callers that already have a parsed SumFile.
func (s SumFile) VerifyRoot() error {
	want := sha256.Sum256(sumBody(s.Entries))
	got := hex.EncodeToString(want[:])
	if got != s.RootHash {
		return fmt.Errorf("root hash mismatch: body hashes to %s but sum declares %s", got, s.RootHash)
	}
	return nil
}

// SumMismatch describes the first divergence found between resolved
// files and a committed keystone.sum. Exactly one of the fields is
// populated per mismatch instance; wrap with errors.As to pick it apart.
type SumMismatch struct {
	// Kind is one of: "extra", "missing", "content", "root".
	Kind string
	// Name of the offending file (empty for Kind=root).
	Name string
	// Expected / Actual hashes (hex). Empty for Kind=extra (no expected)
	// and Kind=missing (no actual).
	Expected string
	Actual   string
}

func (m *SumMismatch) Error() string {
	switch m.Kind {
	case "root":
		return fmt.Sprintf("sum root hash mismatch: expected %s, computed %s", m.Expected, m.Actual)
	case "extra":
		return fmt.Sprintf("resolved source contains %q but keystone.sum does not list it", m.Name)
	case "missing":
		return fmt.Sprintf("keystone.sum lists %q but resolved source does not contain it", m.Name)
	case "content":
		return fmt.Sprintf("file %q content hash mismatch: expected %s, computed %s",
			m.Name, m.Expected, m.Actual)
	default:
		return fmt.Sprintf("sum mismatch (%s) on %q", m.Kind, m.Name)
	}
}

// VerifySum checks resolved content against a parsed SumFile. Returns
// nil iff every file's hash matches, the committed set equals the
// resolved set, and the sum's root hash matches its body. On first
// divergence returns a *SumMismatch — the caller can print its Error()
// verbatim for operators.
func VerifySum(sum SumFile, files map[string]string) error {
	if err := sum.VerifyRoot(); err != nil {
		// Shape into SumMismatch so callers can distinguish this from a
		// content-level divergence via errors.As.
		want := sha256.Sum256(sumBody(sum.Entries))
		return &SumMismatch{
			Kind:     "root",
			Expected: sum.RootHash,
			Actual:   hex.EncodeToString(want[:]),
		}
	}

	// Index the sum for O(1) lookups.
	expect := make(map[string]string, len(sum.Entries))
	for _, e := range sum.Entries {
		expect[e.Name] = e.Hash
	}

	// Pass 1: every resolved file must appear in the sum with a matching
	// per-file hash. Sorted names so errors are deterministic.
	names := make([]string, 0, len(files))
	for n := range files {
		if n == SumFilename {
			continue
		}
		names = append(names, n)
	}
	sort.Strings(names)

	for _, n := range names {
		want, ok := expect[n]
		if !ok {
			return &SumMismatch{Kind: "extra", Name: n}
		}
		got := FileHash(n, files[n])
		if got != want {
			return &SumMismatch{Kind: "content", Name: n, Expected: want, Actual: got}
		}
	}

	// Pass 2: every sum entry must have a matching file. Already covered
	// implicitly if the name sets are equal-sized, but a second pass
	// catches the (rare) case where two different sum lines reduce to
	// the same resolved name — parser rejects that — plus makes the
	// "missing" error report the exact name.
	for _, e := range sum.Entries {
		if _, ok := files[e.Name]; !ok {
			return &SumMismatch{Kind: "missing", Name: e.Name}
		}
	}

	return nil
}

// sumBody emits the deterministic byte representation of the entries
// (sorted by Name, one per line, `<name> h1:<hash>\n`). This is what
// RootHash hashes over.
func sumBody(entries []SumEntry) []byte {
	var buf bytes.Buffer
	for _, e := range entries {
		buf.WriteString(e.Name)
		buf.WriteByte(' ')
		buf.WriteString(SumHashPrefix)
		buf.WriteString(e.Hash)
		buf.WriteByte('\n')
	}
	return buf.Bytes()
}

// validateHex256 rejects anything that isn't 64 lowercase hex chars.
// Upstream conventions (Git, Atlas) also accept uppercase, but Keystone
// canonicalises to lowercase so byte-identical sums round-trip.
func validateHex256(s string) error {
	if len(s) != 64 {
		return fmt.Errorf("expected 64 hex chars, got %d", len(s))
	}
	for i, r := range s {
		if !(r >= '0' && r <= '9') && !(r >= 'a' && r <= 'f') {
			return fmt.Errorf("invalid hex char %q at position %d", r, i)
		}
	}
	return nil
}
