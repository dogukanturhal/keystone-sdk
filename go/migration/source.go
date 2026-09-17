// SPDX-License-Identifier: AGPL-3.0-or-later

// Package migration owns the SQL apply pipeline:
//   - Source resolution (ConfigMap today; OCI + Git in Phase 4+)
//   - Statement extraction
//   - Transactional apply against a target schema
//   - schema_migrations bookkeeping
//
// The package is intentionally Kubernetes-aware only at the source-
// resolution boundary so that the runner itself stays unit-testable
// against a sql.DB.
package migration

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"path/filepath"
	"sort"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	keystonev1alpha1 "github.com/dogukanturhal/keystone/api/v1alpha1"
)

// ResolvedSource is the materialised SQL content for a MigrationBundle.
// Files are returned in the order the runner should apply them
// (lexicographic by name, mirroring golang-migrate's convention).
type ResolvedSource struct {
	// Files maps filename → SQL content, ordered by Names below. The
	// well-known SumFilename ("keystone.sum") is stripped before this
	// map is populated — it is an integrity sidecar, not a migration.
	Files map[string]string

	// Names is the apply order (sorted slice of Files keys). Excludes
	// SumFilename.
	Names []string

	// ContentHash is the SHA-256 over (name + content) for every file
	// in deterministic order. Used as the version-pinning anti-replay
	// token: if a bundle's hash changes, admission can detect it tried
	// to swap the SQL behind a previously-applied version.
	ContentHash string

	// IntegritySum is the parsed keystone.sum document when one was
	// present in the source, zero-valued otherwise. Callers read
	// IntegrityStatus to decide whether it is trustworthy.
	IntegritySum SumFile

	// IntegrityStatus classifies the outcome of verifying Files against
	// IntegritySum:
	//   - SumStatusValid: keystone.sum is present, parses cleanly, and
	//     every per-file + root hash matches.
	//   - SumStatusMissing: no keystone.sum in the source. The resolver
	//     does not treat this as an error; policy decides.
	//   - SumStatusMalformed: keystone.sum exists but won't parse. Always
	//     an error. IntegrityError has the parse diagnostic.
	//   - SumStatusMismatch: parse succeeded but hashes diverge. Always
	//     an error. IntegrityError is a *SumMismatch.
	IntegrityStatus SumStatus

	// IntegrityError is the diagnostic for Malformed / Mismatch. nil for
	// Valid and Missing.
	IntegrityError error
}

// SourceResolver dereferences a MigrationSource into ResolvedSource.
// Single implementation today (ConfigMap); the type stays an interface
// so Phase 4+ can plug OCI + Git resolvers without touching the runner.
type SourceResolver interface {
	Resolve(ctx context.Context, namespace string, src keystonev1alpha1.MigrationSource) (*ResolvedSource, error)
}

// configMapResolver reads SQL files from a ConfigMap.
type configMapResolver struct {
	c client.Reader
}

// NewConfigMapResolver returns a resolver bound to a controller-runtime
// reader. The reader must have List/Get permissions on ConfigMaps in
// the bundle's namespace; the keystone-manager ClusterRole grants that.
//
// Pass `mgr.GetAPIReader()` rather than `mgr.GetClient()` so the
// resolver bypasses the operator's per-type ConfigMap cache. The cache
// is scoped to ConfigMaps carrying the
// `keystone.hexxlock.io/schemadefinition` label (the SD reconciler's
// auto-emitted bundles); user-authored ConfigMap-sourced bundles do
// NOT carry that label and are therefore not in the cache. Routing
// the resolver through APIReader keeps both authoring paths working
// while letting the operator hold a much smaller in-memory ConfigMap
// set. See cmd/manager/main.go cache.Options.ByObject for the cache
// scope wiring.
//
// Argument is `client.Reader` (the read-only sub-interface of
// `client.Client`) so a cached `client.Client` still satisfies it
// when the caller deliberately wants the cache (e.g. tests with an
// envtest fake client where APIReader and Client point at the same
// store).
func NewConfigMapResolver(c client.Reader) SourceResolver {
	return &configMapResolver{c: c}
}

func (r *configMapResolver) Resolve(ctx context.Context, namespace string, src keystonev1alpha1.MigrationSource) (*ResolvedSource, error) {
	if src.Type != keystonev1alpha1.SourceConfigMap {
		return nil, fmt.Errorf("configMapResolver received %s source", src.Type)
	}
	if src.ConfigMapRef == nil {
		return nil, fmt.Errorf("source.type=ConfigMap requires source.configMapRef")
	}

	var cm corev1.ConfigMap
	if err := r.c.Get(ctx, types.NamespacedName{
		Namespace: namespace, Name: src.ConfigMapRef.Name,
	}, &cm); err != nil {
		return nil, fmt.Errorf("read ConfigMap %s/%s: %w",
			namespace, src.ConfigMapRef.Name, err)
	}

	pattern := src.ConfigMapRef.FilePattern
	if pattern == "" {
		pattern = "*.up.sql"
	}

	out := &ResolvedSource{Files: make(map[string]string)}
	// Separate pass for the integrity sidecar — keystone.sum never
	// matches FilePattern (the pattern targets SQL) but we always want
	// to pick it up when committed alongside the migrations.
	var rawSum []byte
	if s, ok := cm.Data[SumFilename]; ok {
		rawSum = []byte(s)
	}
	for name, content := range cm.Data {
		if name == SumFilename {
			continue
		}
		matched, err := filepath.Match(pattern, name)
		if err != nil {
			return nil, fmt.Errorf("invalid file pattern %q: %w", pattern, err)
		}
		if !matched {
			continue
		}
		out.Files[name] = content
		out.Names = append(out.Names, name)
	}
	sort.Strings(out.Names)
	out.ContentHash = HashFiles(out.Files, out.Names)
	applyIntegrity(out, rawSum)
	return out, nil
}

// applyIntegrity parses + verifies the optional keystone.sum sidecar
// and stamps the result onto the ResolvedSource. Missing sum is a
// non-error; malformed or mismatched sums ARE errors surfaced via
// IntegrityError so the controller / webhook can decide how to react
// without this package knowing about SchemaPolicy gates.
func applyIntegrity(out *ResolvedSource, rawSum []byte) {
	if len(rawSum) == 0 {
		out.IntegrityStatus = SumStatusMissing
		return
	}
	sum, err := ParseSum(rawSum)
	if err != nil {
		out.IntegrityStatus = SumStatusMalformed
		out.IntegrityError = err
		return
	}
	out.IntegritySum = sum
	if err := VerifySum(sum, out.Files); err != nil {
		out.IntegrityStatus = SumStatusMismatch
		out.IntegrityError = err
		return
	}
	out.IntegrityStatus = SumStatusValid
}

// HashFiles returns the SHA-256 hex over (name || NUL || content || NUL)
// for each file in the provided order. Deterministic given consistent
// ordering.
func HashFiles(files map[string]string, names []string) string {
	h := sha256.New()
	for _, n := range names {
		h.Write([]byte(n))
		h.Write([]byte{0})
		h.Write([]byte(files[n]))
		h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil))
}
