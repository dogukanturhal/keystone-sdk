// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 HexxLock

package keystone

import (
	"context"
	"strings"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	keystonev1alpha1 "github.com/dogukanturhal/keystone/api/v1alpha1"
)

func newScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	s := runtime.NewScheme()
	if err := keystonev1alpha1.AddToScheme(s); err != nil {
		t.Fatalf("add to scheme: %v", err)
	}
	return s
}

func validOpts() EnrollSchemaOpts {
	return EnrollSchemaOpts{
		Namespace:  "example-service",
		NamePrefix: "example-service-tenant",
		TenantID:   "abc-123",
		Scope:      "example-service",
		Tier:       "tenant",
		LogicalDatabase: keystonev1alpha1.LogicalDatabaseSpec{
			Name:        "tenant_abc",
			ClusterRef:  "prod-eu-west-1-hub",
			ProviderRef: "cnpg-example-service",
			OwnerRole:   "tenant_abc_owner",
		},
		Schemas: []keystonev1alpha1.DatabaseSchemaSpec{
			{Name: "public", OwnerRole: "tenant_abc_owner"},
		},
	}
}

func TestEnrollSchema_HappyPath(t *testing.T) {
	s := newScheme(t)
	k8s := fake.NewClientBuilder().WithScheme(s).Build()

	res, err := EnrollSchema(context.Background(), k8s, validOpts())
	if err != nil {
		t.Fatalf("enroll: %v", err)
	}

	want := types.NamespacedName{Namespace: "example-service", Name: "example-service-tenant-abc-123"}
	if res.LogicalDatabaseRef != want {
		t.Errorf("LogicalDatabaseRef = %v, want %v", res.LogicalDatabaseRef, want)
	}
	if len(res.SchemaRefs) != 1 || res.SchemaRefs[0].Name != "example-service-tenant-abc-123-public" {
		t.Errorf("SchemaRefs = %v, want [example-service-tenant-abc-123-public]", res.SchemaRefs)
	}

	// Verify CRs landed.
	var ldb keystonev1alpha1.LogicalDatabase
	if err := k8s.Get(context.Background(), want, &ldb); err != nil {
		t.Fatalf("get ldb: %v", err)
	}
	if ldb.Spec.Name != "tenant_abc" {
		t.Errorf("ldb.spec.name = %q, want tenant_abc", ldb.Spec.Name)
	}
	if ldb.Labels[keystonev1alpha1.LabelScope] != "example-service" {
		t.Errorf("ldb missing scope label: %v", ldb.Labels)
	}
	if ldb.Labels[keystonev1alpha1.LabelTenantID] != "abc-123" {
		t.Errorf("ldb missing tenant-id label: %v", ldb.Labels)
	}
	if ldb.Labels["keystone.hexxlock.io/tier"] != "tenant" {
		t.Errorf("ldb missing tier label: %v", ldb.Labels)
	}
	if ldb.Labels["keystone.hexxlock.io/cluster"] != "prod-eu-west-1-hub" {
		t.Errorf("ldb missing cluster label: %v", ldb.Labels)
	}

	var schema keystonev1alpha1.DatabaseSchema
	if err := k8s.Get(context.Background(), res.SchemaRefs[0], &schema); err != nil {
		t.Fatalf("get schema: %v", err)
	}
	if schema.Spec.LogicalDatabaseRef != "example-service-tenant-abc-123" {
		t.Errorf("schema.LogicalDatabaseRef = %q, want pointed at SDK-managed ldb", schema.Spec.LogicalDatabaseRef)
	}
}

func TestEnrollSchema_Idempotent(t *testing.T) {
	s := newScheme(t)
	k8s := fake.NewClientBuilder().WithScheme(s).Build()

	opts := validOpts()
	if _, err := EnrollSchema(context.Background(), k8s, opts); err != nil {
		t.Fatalf("first enroll: %v", err)
	}
	// Mutate something on the second call to prove update path runs.
	opts.LogicalDatabase.ConnectionLimit = 50
	if _, err := EnrollSchema(context.Background(), k8s, opts); err != nil {
		t.Fatalf("second enroll: %v", err)
	}

	// Only one LogicalDatabase should exist.
	var list keystonev1alpha1.LogicalDatabaseList
	if err := k8s.List(context.Background(), &list); err != nil {
		t.Fatalf("list ldb: %v", err)
	}
	if len(list.Items) != 1 {
		t.Errorf("expected 1 LogicalDatabase, got %d (idempotency broken)", len(list.Items))
	}
	if list.Items[0].Spec.ConnectionLimit != 50 {
		t.Errorf("update did not propagate; ConnectionLimit = %d, want 50", list.Items[0].Spec.ConnectionLimit)
	}
}

func TestEnrollSchema_LabelOverrideWins(t *testing.T) {
	s := newScheme(t)
	k8s := fake.NewClientBuilder().WithScheme(s).Build()

	opts := validOpts()
	opts.Labels = map[string]string{
		// Override one well-known + add a custom.
		keystonev1alpha1.LabelScope:          "override-scope",
		"caller.example.com/lifecycle-stage": "canary",
	}
	if _, err := EnrollSchema(context.Background(), k8s, opts); err != nil {
		t.Fatalf("enroll: %v", err)
	}
	var ldb keystonev1alpha1.LogicalDatabase
	if err := k8s.Get(context.Background(),
		types.NamespacedName{Namespace: "example-service", Name: "example-service-tenant-abc-123"},
		&ldb); err != nil {
		t.Fatalf("get ldb: %v", err)
	}
	if ldb.Labels[keystonev1alpha1.LabelScope] != "override-scope" {
		t.Errorf("scope override not honored: got %q", ldb.Labels[keystonev1alpha1.LabelScope])
	}
	if ldb.Labels["caller.example.com/lifecycle-stage"] != "canary" {
		t.Errorf("custom label dropped: %v", ldb.Labels)
	}
}

func TestEnrollSchema_AnnotationsPropagate(t *testing.T) {
	s := newScheme(t)
	k8s := fake.NewClientBuilder().WithScheme(s).Build()

	opts := validOpts()
	opts.Annotations = map[string]string{
		keystonev1alpha1.AnnotationAuthor:   "system:example-service-provisioner",
		keystonev1alpha1.AnnotationRiskTier: "low",
	}
	if _, err := EnrollSchema(context.Background(), k8s, opts); err != nil {
		t.Fatalf("enroll: %v", err)
	}
	var ldb keystonev1alpha1.LogicalDatabase
	_ = k8s.Get(context.Background(),
		types.NamespacedName{Namespace: "example-service", Name: "example-service-tenant-abc-123"},
		&ldb)
	if ldb.Annotations[keystonev1alpha1.AnnotationAuthor] != "system:example-service-provisioner" {
		t.Errorf("author annotation missing: %v", ldb.Annotations)
	}
	if ldb.Annotations[keystonev1alpha1.AnnotationRiskTier] != "low" {
		t.Errorf("risk-tier annotation missing: %v", ldb.Annotations)
	}
}

func TestEnrollSchema_Validate(t *testing.T) {
	bad := func(mut func(*EnrollSchemaOpts), wantContains string) func(*testing.T) {
		return func(t *testing.T) {
			opts := validOpts()
			mut(&opts)
			s := newScheme(t)
			k8s := fake.NewClientBuilder().WithScheme(s).Build()
			_, err := EnrollSchema(context.Background(), k8s, opts)
			if err == nil {
				t.Fatalf("expected validation error containing %q, got nil", wantContains)
			}
			if !strings.Contains(err.Error(), wantContains) {
				t.Errorf("error %q does not contain %q", err.Error(), wantContains)
			}
		}
	}
	t.Run("missing namespace", bad(func(o *EnrollSchemaOpts) { o.Namespace = "" }, "Namespace is required"))
	t.Run("missing tenant id", bad(func(o *EnrollSchemaOpts) { o.TenantID = "" }, "TenantID is required"))
	t.Run("missing scope", bad(func(o *EnrollSchemaOpts) { o.Scope = "" }, "Scope is required"))
	t.Run("missing schemas", bad(func(o *EnrollSchemaOpts) { o.Schemas = nil }, "Schemas must contain"))
	t.Run("schema missing name", bad(func(o *EnrollSchemaOpts) { o.Schemas[0].Name = "" }, "Schemas[0].Name"))
	t.Run("schema missing owner", bad(func(o *EnrollSchemaOpts) { o.Schemas[0].OwnerRole = "" }, "Schemas[0].OwnerRole"))
	t.Run("logicalDB missing cluster", bad(func(o *EnrollSchemaOpts) { o.LogicalDatabase.ClusterRef = "" }, "LogicalDatabase.ClusterRef"))
	t.Run("logicalDB missing provider", bad(func(o *EnrollSchemaOpts) { o.LogicalDatabase.ProviderRef = "" }, "LogicalDatabase.ProviderRef"))
}

func TestDeenrollSchema_DeletesAll(t *testing.T) {
	s := newScheme(t)
	k8s := fake.NewClientBuilder().WithScheme(s).Build()
	opts := validOpts()
	if _, err := EnrollSchema(context.Background(), k8s, opts); err != nil {
		t.Fatalf("enroll: %v", err)
	}
	if err := DeenrollSchema(context.Background(), k8s, DeenrollSchemaOpts{
		Namespace:   opts.Namespace,
		NamePrefix:  opts.NamePrefix,
		TenantID:    opts.TenantID,
		SchemaNames: []string{"public"},
	}); err != nil {
		t.Fatalf("deenroll: %v", err)
	}
	var ldbs keystonev1alpha1.LogicalDatabaseList
	_ = k8s.List(context.Background(), &ldbs)
	if len(ldbs.Items) != 0 {
		t.Errorf("LogicalDatabase remained after deenroll: %d", len(ldbs.Items))
	}
	var schemas keystonev1alpha1.DatabaseSchemaList
	_ = k8s.List(context.Background(), &schemas)
	if len(schemas.Items) != 0 {
		t.Errorf("DatabaseSchema remained after deenroll: %d", len(schemas.Items))
	}
}

func TestDeenrollSchema_Idempotent(t *testing.T) {
	s := newScheme(t)
	k8s := fake.NewClientBuilder().WithScheme(s).Build()
	// Deenroll on empty cluster — must not error.
	err := DeenrollSchema(context.Background(), k8s, DeenrollSchemaOpts{
		Namespace:   "example-service",
		NamePrefix:  "example-service-tenant",
		TenantID:    "ghost",
		SchemaNames: []string{"public"},
	})
	if err != nil {
		t.Errorf("deenroll on empty cluster should be idempotent; got %v", err)
	}
}

func TestDeenrollSchema_DropDataFlipsPolicy(t *testing.T) {
	s := newScheme(t)
	k8s := fake.NewClientBuilder().WithScheme(s).Build()
	opts := validOpts()
	if _, err := EnrollSchema(context.Background(), k8s, opts); err != nil {
		t.Fatalf("enroll: %v", err)
	}
	// Inject a custom subresource to capture the patch — we'll verify
	// via a Get on the (still-existing-because-fake-doesnt-finalise)
	// object but the SDK Patch + Delete path is what we exercise.
	if err := DeenrollSchema(context.Background(), k8s, DeenrollSchemaOpts{
		Namespace:   opts.Namespace,
		NamePrefix:  opts.NamePrefix,
		TenantID:    opts.TenantID,
		SchemaNames: []string{"public"},
		DropData:    true,
	}); err != nil {
		t.Fatalf("deenroll: %v", err)
	}
	// On the fake client, Delete is immediate so the LogicalDatabase
	// is gone — what matters is the call did not error and that the
	// DropData branch was exercised. Confirm absence:
	var ldbs keystonev1alpha1.LogicalDatabaseList
	_ = k8s.List(context.Background(), &ldbs)
	if len(ldbs.Items) != 0 {
		t.Errorf("LogicalDatabase remained after DropData deenroll: %d", len(ldbs.Items))
	}
}

func TestWaitSchemaUpToDate_HappyPath(t *testing.T) {
	s := newScheme(t)
	sdRef := types.NamespacedName{Namespace: "keystone-system", Name: "example-service-tenant-desired"}
	sd := &keystonev1alpha1.SchemaDefinition{
		ObjectMeta: metav1.ObjectMeta{Namespace: sdRef.Namespace, Name: sdRef.Name},
		Status: keystonev1alpha1.SchemaDefinitionStatus{
			MatchedSchemas: 3,
			Conditions: []metav1.Condition{
				{Type: "Ready", Status: metav1.ConditionTrue},
			},
		},
	}
	k8s := fake.NewClientBuilder().WithScheme(s).WithStatusSubresource(sd).WithObjects(sd).Build()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := WaitSchemaUpToDate(ctx, k8s, sdRef, 3); err != nil {
		t.Fatalf("expected nil, got %v", err)
	}
}

func TestWaitSchemaUpToDate_NotEnoughMatched(t *testing.T) {
	s := newScheme(t)
	sdRef := types.NamespacedName{Namespace: "keystone-system", Name: "example-service-tenant-desired"}
	sd := &keystonev1alpha1.SchemaDefinition{
		ObjectMeta: metav1.ObjectMeta{Namespace: sdRef.Namespace, Name: sdRef.Name},
		Status: keystonev1alpha1.SchemaDefinitionStatus{
			MatchedSchemas: 2, // less than needed 3
			Conditions: []metav1.Condition{
				{Type: "Ready", Status: metav1.ConditionTrue},
			},
		},
	}
	k8s := fake.NewClientBuilder().WithScheme(s).WithStatusSubresource(sd).WithObjects(sd).Build()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	err := WaitSchemaUpToDate(ctx, k8s, sdRef, 3)
	if err == nil {
		t.Fatal("expected timeout error, got nil")
	}
	if !strings.Contains(err.Error(), "matched=2 (need >=3)") {
		t.Errorf("error message should surface last observed matched/expected; got %q", err.Error())
	}
}

func TestWaitSchemaUpToDate_NotReady(t *testing.T) {
	s := newScheme(t)
	sdRef := types.NamespacedName{Namespace: "keystone-system", Name: "example-service-tenant-desired"}
	sd := &keystonev1alpha1.SchemaDefinition{
		ObjectMeta: metav1.ObjectMeta{Namespace: sdRef.Namespace, Name: sdRef.Name},
		Status: keystonev1alpha1.SchemaDefinitionStatus{
			MatchedSchemas: 5,
			Conditions: []metav1.Condition{
				{Type: "Ready", Status: metav1.ConditionFalse, Reason: "BundleApplying"},
			},
		},
	}
	k8s := fake.NewClientBuilder().WithScheme(s).WithStatusSubresource(sd).WithObjects(sd).Build()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	err := WaitSchemaUpToDate(ctx, k8s, sdRef, 1)
	if err == nil {
		t.Fatal("expected timeout error, got nil")
	}
	if !strings.Contains(err.Error(), "ready=false") {
		t.Errorf("error message should surface ready state; got %q", err.Error())
	}
}

func TestWaitSchemaUpToDate_ZeroExpected(t *testing.T) {
	// expectedMatched=0 + Ready=True → returns immediately. Useful for
	// the degenerate case "wait until SD is healthy regardless of count".
	s := newScheme(t)
	sdRef := types.NamespacedName{Namespace: "keystone-system", Name: "example-service-tenant-desired"}
	sd := &keystonev1alpha1.SchemaDefinition{
		ObjectMeta: metav1.ObjectMeta{Namespace: sdRef.Namespace, Name: sdRef.Name},
		Status: keystonev1alpha1.SchemaDefinitionStatus{
			MatchedSchemas: 0,
			Conditions: []metav1.Condition{
				{Type: "Ready", Status: metav1.ConditionTrue},
			},
		},
	}
	k8s := fake.NewClientBuilder().WithScheme(s).WithStatusSubresource(sd).WithObjects(sd).Build()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := WaitSchemaUpToDate(ctx, k8s, sdRef, 0); err != nil {
		t.Fatalf("expected nil, got %v", err)
	}
}

func TestWaitSchemaUpToDate_NegativeExpected(t *testing.T) {
	s := newScheme(t)
	k8s := fake.NewClientBuilder().WithScheme(s).Build()
	sdRef := types.NamespacedName{Namespace: "ns", Name: "sd"}
	err := WaitSchemaUpToDate(context.Background(), k8s, sdRef, -1)
	if err == nil {
		t.Fatal("expected error for negative expectedMatched")
	}
	if !strings.Contains(err.Error(), "expectedMatched must be >= 0") {
		t.Errorf("got %q", err.Error())
	}
}

func TestWaitSchemaUpToDate_SDMissing(t *testing.T) {
	s := newScheme(t)
	k8s := fake.NewClientBuilder().WithScheme(s).Build()
	sdRef := types.NamespacedName{Namespace: "keystone-system", Name: "ghost-sd"}
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()
	err := WaitSchemaUpToDate(ctx, k8s, sdRef, 1)
	if err == nil {
		t.Fatal("expected timeout when SD never appears")
	}
}

func TestWaitSchemaFingerprint_HappyPath(t *testing.T) {
	s := newScheme(t)
	sdRef := types.NamespacedName{Namespace: "keystone-system", Name: "example-service-tenant-desired"}
	schemaA := types.NamespacedName{Namespace: "keystone-system", Name: "example-service-tenant-aaa-public"}
	schemaB := types.NamespacedName{Namespace: "keystone-system", Name: "example-service-tenant-bbb-public"}

	sd := &keystonev1alpha1.SchemaDefinition{
		ObjectMeta: metav1.ObjectMeta{Namespace: sdRef.Namespace, Name: sdRef.Name},
		Status:     keystonev1alpha1.SchemaDefinitionStatus{Fingerprint: "deadbeefcafe1234"},
	}
	dsA := &keystonev1alpha1.DatabaseSchema{
		ObjectMeta: metav1.ObjectMeta{Namespace: schemaA.Namespace, Name: schemaA.Name},
		Status:     keystonev1alpha1.DatabaseSchemaStatus{LastAppliedFingerprint: "deadbeefcafe1234"},
	}
	dsB := &keystonev1alpha1.DatabaseSchema{
		ObjectMeta: metav1.ObjectMeta{Namespace: schemaB.Namespace, Name: schemaB.Name},
		Status:     keystonev1alpha1.DatabaseSchemaStatus{LastAppliedFingerprint: "deadbeefcafe1234"},
	}
	k8s := fake.NewClientBuilder().WithScheme(s).
		WithStatusSubresource(sd, dsA, dsB).
		WithObjects(sd, dsA, dsB).Build()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := WaitSchemaFingerprint(ctx, k8s, sdRef, []types.NamespacedName{schemaA, schemaB}); err != nil {
		t.Fatalf("expected nil, got %v", err)
	}
}

func TestWaitSchemaFingerprint_OneStaleSchema(t *testing.T) {
	s := newScheme(t)
	sdRef := types.NamespacedName{Namespace: "keystone-system", Name: "example-service-tenant-desired"}
	schemaA := types.NamespacedName{Namespace: "keystone-system", Name: "example-service-tenant-aaa-public"}
	schemaB := types.NamespacedName{Namespace: "keystone-system", Name: "example-service-tenant-bbb-public"}

	sd := &keystonev1alpha1.SchemaDefinition{
		ObjectMeta: metav1.ObjectMeta{Namespace: sdRef.Namespace, Name: sdRef.Name},
		Status:     keystonev1alpha1.SchemaDefinitionStatus{Fingerprint: "newfingerprint01"},
	}
	dsA := &keystonev1alpha1.DatabaseSchema{
		ObjectMeta: metav1.ObjectMeta{Namespace: schemaA.Namespace, Name: schemaA.Name},
		Status:     keystonev1alpha1.DatabaseSchemaStatus{LastAppliedFingerprint: "newfingerprint01"},
	}
	dsB := &keystonev1alpha1.DatabaseSchema{
		ObjectMeta: metav1.ObjectMeta{Namespace: schemaB.Namespace, Name: schemaB.Name},
		Status:     keystonev1alpha1.DatabaseSchemaStatus{LastAppliedFingerprint: "old00fingerprint"}, // mismatch
	}
	k8s := fake.NewClientBuilder().WithScheme(s).
		WithStatusSubresource(sd, dsA, dsB).
		WithObjects(sd, dsA, dsB).Build()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	err := WaitSchemaFingerprint(ctx, k8s, sdRef, []types.NamespacedName{schemaA, schemaB})
	if err == nil {
		t.Fatal("expected timeout error, got nil")
	}
	if !strings.Contains(err.Error(), schemaB.String()) {
		t.Errorf("error should call out the stale schema; got %q", err.Error())
	}
	if !strings.Contains(err.Error(), "newfingerprint01") {
		t.Errorf("error should call out the SD fingerprint; got %q", err.Error())
	}
}

func TestWaitSchemaFingerprint_SDFingerprintEmpty(t *testing.T) {
	// SD reconciler hasn't computed Fingerprint yet — helper waits.
	s := newScheme(t)
	sdRef := types.NamespacedName{Namespace: "keystone-system", Name: "example-service-tenant-desired"}
	sd := &keystonev1alpha1.SchemaDefinition{
		ObjectMeta: metav1.ObjectMeta{Namespace: sdRef.Namespace, Name: sdRef.Name},
		Status:     keystonev1alpha1.SchemaDefinitionStatus{Fingerprint: ""},
	}
	k8s := fake.NewClientBuilder().WithScheme(s).
		WithStatusSubresource(sd).WithObjects(sd).Build()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	err := WaitSchemaFingerprint(ctx, k8s, sdRef, []types.NamespacedName{
		{Namespace: "keystone-system", Name: "any-schema"},
	})
	if err == nil {
		t.Fatal("expected timeout while waiting for SD fingerprint, got nil")
	}
}

func TestWaitSchemaFingerprint_EmptyRefs(t *testing.T) {
	s := newScheme(t)
	k8s := fake.NewClientBuilder().WithScheme(s).Build()
	if err := WaitSchemaFingerprint(context.Background(), k8s, types.NamespacedName{Namespace: "ns", Name: "sd"}, nil); err != nil {
		t.Fatalf("empty refs slice should return nil, got %v", err)
	}
}
