// SPDX-License-Identifier: AGPL-3.0-or-later

package migration

import (
	"context"
	"errors"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	keystonev1alpha1 "github.com/dogukanturhal/keystone/api/v1alpha1"
)

// newFakeClient returns a controller-runtime fake client seeded with the
// given ConfigMap under the "default" namespace. Kept local so these
// unit tests don't depend on envtest.
func newFakeClient(t *testing.T, cm *corev1.ConfigMap) client.Client {
	t.Helper()
	s := runtime.NewScheme()
	if err := corev1.AddToScheme(s); err != nil {
		t.Fatalf("add corev1 to scheme: %v", err)
	}
	return fake.NewClientBuilder().WithScheme(s).WithObjects(cm).Build()
}

func newCM(name string, data map[string]string) *corev1.ConfigMap {
	return &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: name},
		Data:       data,
	}
}

func configMapSource(name string) keystonev1alpha1.MigrationSource {
	return keystonev1alpha1.MigrationSource{
		Type: keystonev1alpha1.SourceConfigMap,
		ConfigMapRef: &keystonev1alpha1.MigrationConfigMapSource{
			Name: name,
		},
	}
}

// TestResolveUnlabeledConfigMap pins the post-Layer-2 contract that
// `NewConfigMapResolver(reader)` resolves a ConfigMap that does NOT
// carry the `keystone.hexxlock.io/schemadefinition` label — exactly
// the user-authored bundle CM case that falls outside the operator's
// label-scoped ConfigMap cache. Production wires the resolver against
// `mgr.GetAPIReader()` (uncached) so this path goes direct to the
// apiserver; unit tests pass a fake `client.Client` which satisfies
// `client.Reader` and trivially returns the CM.
//
// Without this test, a future refactor that re-introduces a label
// requirement on the resolver would silently break user-authored
// bundles in production while every existing test still passed (they
// also use unlabeled CMs but don't make that property explicit).
func TestResolveUnlabeledConfigMap(t *testing.T) {
	cm := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "default",
			Name:      "user-authored-bundle",
			// Labels intentionally empty — pin the contract.
		},
		Data: map[string]string{
			"001_user_init.up.sql": "CREATE TABLE u (id int);",
		},
	}
	if len(cm.Labels) != 0 {
		t.Fatalf("fixture must be unlabeled to pin the contract; got %v", cm.Labels)
	}

	r := NewConfigMapResolver(newFakeClient(t, cm))
	src, err := r.Resolve(context.Background(), "default", configMapSource("user-authored-bundle"))
	if err != nil {
		t.Fatalf("unlabeled CM should resolve via the reader; got %v", err)
	}
	if len(src.Names) != 1 || src.Names[0] != "001_user_init.up.sql" {
		t.Fatalf("unexpected resolved files: %v", src.Names)
	}
}

func TestResolveSumMissing(t *testing.T) {
	cm := newCM("migrations", map[string]string{
		"001_init.up.sql": "CREATE TABLE t (id int);",
	})
	r := NewConfigMapResolver(newFakeClient(t, cm))
	src, err := r.Resolve(context.Background(), "default", configMapSource("migrations"))
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if src.IntegrityStatus != SumStatusMissing {
		t.Fatalf("want Missing, got %s", src.IntegrityStatus)
	}
	if src.IntegrityError != nil {
		t.Fatalf("missing sum must not produce an error, got %v", src.IntegrityError)
	}
	if len(src.Names) != 1 {
		t.Fatalf("want 1 file, got %d", len(src.Names))
	}
}

func TestResolveSumValid(t *testing.T) {
	files := map[string]string{
		"001_init.up.sql":  "CREATE TABLE t (id int);",
		"002_index.up.sql": "CREATE INDEX CONCURRENTLY ON t (id);",
	}
	sum := string(MarshalSum(BuildSum(files)))
	data := make(map[string]string, len(files)+1)
	for k, v := range files {
		data[k] = v
	}
	data[SumFilename] = sum

	cm := newCM("migrations", data)
	r := NewConfigMapResolver(newFakeClient(t, cm))
	src, err := r.Resolve(context.Background(), "default", configMapSource("migrations"))
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if src.IntegrityStatus != SumStatusValid {
		t.Fatalf("want Valid, got %s (err=%v)", src.IntegrityStatus, src.IntegrityError)
	}
	if _, listed := src.Files[SumFilename]; listed {
		t.Fatalf("keystone.sum must be stripped from Files, still present")
	}
	if len(src.Names) != 2 {
		t.Fatalf("want 2 SQL files, got %d (%v)", len(src.Names), src.Names)
	}
	if src.IntegritySum.RootHash == "" {
		t.Fatalf("IntegritySum.RootHash not populated")
	}
}

func TestResolveSumMismatch(t *testing.T) {
	files := map[string]string{
		"001_init.up.sql":  "CREATE TABLE t (id int);",
		"002_index.up.sql": "CREATE INDEX CONCURRENTLY ON t (id);",
	}
	sum := string(MarshalSum(BuildSum(files)))
	// Tamper with 002 after the sum was generated — classic "author
	// changed SQL but forgot to regenerate keystone.sum" flow.
	files["002_index.up.sql"] = "DROP INDEX CONCURRENTLY t_id_idx;"
	data := make(map[string]string, len(files)+1)
	for k, v := range files {
		data[k] = v
	}
	data[SumFilename] = sum

	cm := newCM("migrations", data)
	r := NewConfigMapResolver(newFakeClient(t, cm))
	src, err := r.Resolve(context.Background(), "default", configMapSource("migrations"))
	if err != nil {
		t.Fatalf("resolve itself must not fail on mismatch (callers gate on status): %v", err)
	}
	if src.IntegrityStatus != SumStatusMismatch {
		t.Fatalf("want Mismatch, got %s", src.IntegrityStatus)
	}
	var mm *SumMismatch
	if !errors.As(src.IntegrityError, &mm) {
		t.Fatalf("want *SumMismatch, got %T: %v", src.IntegrityError, src.IntegrityError)
	}
	if mm.Kind != "content" || mm.Name != "002_index.up.sql" {
		t.Fatalf("unexpected mismatch: %+v", mm)
	}
}

func TestResolveSumMalformed(t *testing.T) {
	cm := newCM("migrations", map[string]string{
		"001_init.up.sql": "CREATE TABLE t (id int);",
		SumFilename:       "this is not a sum file",
	})
	r := NewConfigMapResolver(newFakeClient(t, cm))
	src, err := r.Resolve(context.Background(), "default", configMapSource("migrations"))
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if src.IntegrityStatus != SumStatusMalformed {
		t.Fatalf("want Malformed, got %s", src.IntegrityStatus)
	}
	if src.IntegrityError == nil {
		t.Fatalf("malformed sum must set IntegrityError")
	}
}

func TestResolveSumExtraFile(t *testing.T) {
	files := map[string]string{
		"001_init.up.sql": "CREATE TABLE t (id int);",
	}
	sum := string(MarshalSum(BuildSum(files)))
	// Someone added a second file without regenerating the sum.
	files["002_sneaky.up.sql"] = "DROP TABLE t;"
	data := make(map[string]string, len(files)+1)
	for k, v := range files {
		data[k] = v
	}
	data[SumFilename] = sum

	cm := newCM("migrations", data)
	r := NewConfigMapResolver(newFakeClient(t, cm))
	src, err := r.Resolve(context.Background(), "default", configMapSource("migrations"))
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if src.IntegrityStatus != SumStatusMismatch {
		t.Fatalf("want Mismatch for unlisted extra file, got %s", src.IntegrityStatus)
	}
	var mm *SumMismatch
	if !errors.As(src.IntegrityError, &mm) || mm.Kind != "extra" {
		t.Fatalf("want Kind=extra, got %+v", mm)
	}
}
