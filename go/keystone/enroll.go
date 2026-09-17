// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 HexxLock

package keystone

import (
	"context"
	"errors"
	"fmt"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/wait"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	keystonev1alpha1 "github.com/dogukanturhal/keystone/api/v1alpha1"
)

// EnrollSchemaOpts is the input to EnrollSchema. It declares the
// LogicalDatabase + one or more DatabaseSchemas a tenant (or any
// product instance) needs in order to be reconciled by Keystone.
//
// The caller decides what naming + labels mean in their domain. The
// SDK applies a small set of well-known labels on every created CR so
// SchemaPolicies + SchemaDefinitions written against the platform's
// label conventions (scope, tenant-id, tier, cluster) match without
// the caller having to remember them.
type EnrollSchemaOpts struct {
	// Namespace the CRs are created in. Typically a per-product
	// namespace (e.g. `example-service`); the caller's ServiceAccount must
	// have RBAC for LogicalDatabase + DatabaseSchema in this namespace.
	Namespace string

	// NamePrefix is the deterministic prefix for the LogicalDatabase
	// and DatabaseSchema metadata.name. Combined with TenantID:
	//
	//   logicalDB:    <NamePrefix>-<TenantID>
	//   schema (k):   <NamePrefix>-<TenantID>-<Schemas[k].Name>
	//
	// Repeat calls with the same (Namespace, NamePrefix, TenantID)
	// trigger CreateOrUpdate, never duplicate. NamePrefix MUST satisfy
	// the K8s name pattern; the SDK does no normalisation.
	NamePrefix string

	// TenantID is the caller's stable identity for this product
	// instance (often a UUID). Carried as a label
	// (keystone.hexxlock.io/tenant-id) so SchemaProgress entries can
	// be grouped by tenant in dashboards (see LabelTenantID memory).
	TenantID string

	// Scope is the product scope label
	// (keystone.hexxlock.io/scope) — e.g. "example-service", "hexx-erp".
	// Required; SchemaPolicies typically gate by this label.
	Scope string

	// Tier is an optional tier label (keystone.hexxlock.io/tier) —
	// e.g. "tenant", "control", "shared". Empty = label not set.
	Tier string

	// LogicalDatabase fully describes the LogicalDatabase to create.
	// Name and Namespace fields on the spec are ignored — the SDK sets
	// metadata.name from NamePrefix+TenantID.
	LogicalDatabase keystonev1alpha1.LogicalDatabaseSpec

	// Schemas is the list of DatabaseSchemas (typically one
	// "public" entry). Each SchemaSpec's LogicalDatabaseRef is
	// overwritten by the SDK to point at the LogicalDatabase it just
	// created — passing it pre-set is harmless but ignored.
	//
	// +k8s:validation:MinItems=1
	Schemas []keystonev1alpha1.DatabaseSchemaSpec

	// Labels are merged into the well-known labels (scope, tenant-id,
	// tier, cluster) and applied to every created CR. Keys with the
	// `keystone.hexxlock.io/` prefix override the SDK defaults; non-
	// prefixed keys layer on top.
	Labels map[string]string

	// Annotations are applied to every created CR. Useful for
	// AnnotationAuthor + AnnotationRiskTier so audit trails attribute
	// the enroll call correctly.
	Annotations map[string]string
}

// EnrollSchemaResult identifies the CRs the SDK created or updated.
// Callers pass these refs to WaitSchemaReady or DeenrollSchema.
type EnrollSchemaResult struct {
	LogicalDatabaseRef types.NamespacedName
	SchemaRefs         []types.NamespacedName
}

// EnrollSchema is the runtime-creation entry point for tenant or
// product-instance enrollment. It CreateOrUpdates one LogicalDatabase
// and N DatabaseSchemas in the supplied namespace, propagating well-
// known labels + caller-supplied labels/annotations. The call is
// idempotent — repeat invocations with the same (Namespace, NamePrefix,
// TenantID) update existing CRs rather than duplicating.
//
// The SDK does NOT block until reconciliation completes; that is the
// job of WaitSchemaReady, which callers compose explicitly. This
// separation lets callers pick async (return tenant-pending and poll
// later) or sync (long-poll inside their request) without the SDK
// dictating the contract.
//
// The k8s client must be configured against the target cluster. For
// multi-cluster deployments callers acquire the right client outside
// the SDK; this function never decides which cluster to talk to.
func EnrollSchema(
	ctx context.Context,
	k8s client.Client,
	opts EnrollSchemaOpts,
) (*EnrollSchemaResult, error) {
	if err := validateEnrollOpts(&opts); err != nil {
		return nil, err
	}

	logicalDBName := fmt.Sprintf("%s-%s", opts.NamePrefix, opts.TenantID)
	wellKnownLabels := wellKnownEnrollLabels(&opts)

	ldb := &keystonev1alpha1.LogicalDatabase{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: opts.Namespace,
			Name:      logicalDBName,
		},
	}
	if _, err := controllerutil.CreateOrUpdate(ctx, k8s, ldb, func() error {
		applyLabels(&ldb.ObjectMeta, wellKnownLabels, opts.Labels)
		applyAnnotations(&ldb.ObjectMeta, opts.Annotations)
		ldb.Spec = opts.LogicalDatabase
		return nil
	}); err != nil {
		return nil, fmt.Errorf("upsert LogicalDatabase %s/%s: %w",
			opts.Namespace, logicalDBName, err)
	}

	result := &EnrollSchemaResult{
		LogicalDatabaseRef: types.NamespacedName{Namespace: opts.Namespace, Name: logicalDBName},
		SchemaRefs:         make([]types.NamespacedName, 0, len(opts.Schemas)),
	}

	for i := range opts.Schemas {
		sSpec := opts.Schemas[i]
		schemaName := fmt.Sprintf("%s-%s-%s",
			opts.NamePrefix, opts.TenantID, sSpec.Name)
		schema := &keystonev1alpha1.DatabaseSchema{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: opts.Namespace,
				Name:      schemaName,
			},
		}
		if _, err := controllerutil.CreateOrUpdate(ctx, k8s, schema, func() error {
			applyLabels(&schema.ObjectMeta, wellKnownLabels, opts.Labels)
			applyAnnotations(&schema.ObjectMeta, opts.Annotations)
			// Overwrite LogicalDatabaseRef to ensure it points at the
			// SDK-managed LogicalDatabase. Caller-supplied values are
			// ignored to keep the (LogicalDatabase, Schema) pair
			// consistent.
			sSpec.LogicalDatabaseRef = logicalDBName
			schema.Spec = sSpec
			return nil
		}); err != nil {
			return nil, fmt.Errorf("upsert DatabaseSchema %s/%s: %w",
				opts.Namespace, schemaName, err)
		}
		result.SchemaRefs = append(result.SchemaRefs,
			types.NamespacedName{Namespace: opts.Namespace, Name: schemaName})
	}
	return result, nil
}

// WaitSchemaReady polls the named DatabaseSchemas until each reports
// Status.Conditions[Ready]=True or the context is cancelled. The poll
// interval starts at 1s and exponentially backs off to a 30s cap; the
// caller controls the overall deadline via ctx.
//
// Returns nil when every ref is Ready. Returns context.DeadlineExceeded
// (or whatever ctx surfaces) on timeout, with a wrapped error
// indicating which schema(s) were still not Ready.
func WaitSchemaReady(
	ctx context.Context,
	k8s client.Client,
	refs []types.NamespacedName,
) error {
	if len(refs) == 0 {
		return nil
	}
	pending := make(map[types.NamespacedName]struct{}, len(refs))
	for _, r := range refs {
		pending[r] = struct{}{}
	}

	backoff := wait.Backoff{
		Duration: 1 * time.Second,
		Factor:   1.5,
		Jitter:   0.1,
		Cap:      30 * time.Second,
		Steps:    1 << 30, // exponential climb up to Cap, then constant.
	}

	pollErr := wait.ExponentialBackoffWithContext(ctx, backoff, func(ctx context.Context) (bool, error) {
		for ref := range pending {
			var s keystonev1alpha1.DatabaseSchema
			if err := k8s.Get(ctx, ref, &s); err != nil {
				if apierrors.IsNotFound(err) {
					// CR may not have propagated to caches yet; treat
					// as not-ready and try again.
					continue
				}
				return false, fmt.Errorf("get DatabaseSchema %s: %w", ref, err)
			}
			if isReady(s.Status.Conditions) {
				delete(pending, ref)
			}
		}
		return len(pending) == 0, nil
	})
	if pollErr != nil {
		stillPending := make([]string, 0, len(pending))
		for ref := range pending {
			stillPending = append(stillPending, ref.String())
		}
		return fmt.Errorf("waiting for DatabaseSchema readiness; still pending=%v: %w",
			stillPending, pollErr)
	}
	return nil
}

// WaitSchemaUpToDate waits until the named SchemaDefinition has both
// observed `expectedMatched` schemas AND converged them to the SD's
// current desired state. Distinct from WaitSchemaReady (which only
// confirms the DatabaseSchema CR is Ready — schema present + ownership
// reconciled) — WaitSchemaUpToDate additionally guarantees the SD-
// emitted MigrationBundle apply has finished, so the realm DB has
// the canonical table set.
//
// The check is two-phase per poll tick:
//
//  1. SD.Status.MatchedSchemas >= expectedMatched
//     Confirms the SD reconciler has SEEN the freshly-enrolled schema
//     (label-selector watch propagation can lag a few hundred ms).
//
//  2. SD.Status.Conditions[Ready] == True
//     Under MixedVersionPolicy=Refuse this guarantees ALL matched
//     schemas are at the SD's desired state. Under MostBehindWins
//     it guarantees the lockstep set is — see the SD reconciler
//     semantics in internal/controller/schemadefinition_controller.go.
//
// `expectedMatched` is the matched-schema count the caller expects
// AFTER their enrollment. Common pattern:
//
//	var sd keystonev1alpha1.SchemaDefinition
//	_ = k8s.Get(ctx, sdRef, &sd)
//	prev := int(sd.Status.MatchedSchemas)
//	_, _ = EnrollSchema(ctx, k8s, opts)
//	_ = WaitSchemaReady(ctx, k8s, refs)               // schema CR healthy
//	_ = WaitSchemaUpToDate(ctx, k8s, sdRef, prev+1)   // bundle applied
//
// Note: this verifies COUNT, not identity. If two callers enroll
// concurrently and the SD's threshold is reached via the OTHER
// caller's schema, this returns prematurely from the first caller's
// perspective. For tenant-onboarding workflows where the enroll rate
// is naturally bounded (one tenant per request), the count semantic
// is sufficient. Concurrent-safe variants would need a per-schema
// fingerprint check on DatabaseSchema.Status, which the v1alpha1
// CRD doesn't expose yet — tracked as a follow-up.
//
// The poll interval starts at 1s and exponentially backs off to a 30s
// cap; the caller controls the overall deadline via ctx. Returns
// context.DeadlineExceeded (or whatever ctx surfaces) on timeout,
// with a wrapped error indicating the last observed
// matchedSchemas / Ready state.
func WaitSchemaUpToDate(
	ctx context.Context,
	k8s client.Client,
	sdRef types.NamespacedName,
	expectedMatched int,
) error {
	if expectedMatched < 0 {
		return fmt.Errorf("waitschemauptodate: expectedMatched must be >= 0, got %d", expectedMatched)
	}

	backoff := wait.Backoff{
		Duration: 1 * time.Second,
		Factor:   1.5,
		Jitter:   0.1,
		Cap:      30 * time.Second,
		Steps:    1 << 30,
	}

	var lastMatched int
	var lastReady bool

	pollErr := wait.ExponentialBackoffWithContext(ctx, backoff, func(ctx context.Context) (bool, error) {
		var sd keystonev1alpha1.SchemaDefinition
		if err := k8s.Get(ctx, sdRef, &sd); err != nil {
			if apierrors.IsNotFound(err) {
				// SD CR may not have propagated to caches yet (or the
				// caller pointed at the wrong namespace) — keep polling.
				// ctx will time out if the SD never appears.
				return false, nil
			}
			return false, fmt.Errorf("get SchemaDefinition %s: %w", sdRef, err)
		}
		lastMatched = int(sd.Status.MatchedSchemas)
		lastReady = isReady(sd.Status.Conditions)
		return lastMatched >= expectedMatched && lastReady, nil
	})
	if pollErr != nil {
		return fmt.Errorf(
			"waiting for SchemaDefinition %s to converge: last observed matched=%d (need >=%d) ready=%t: %w",
			sdRef, lastMatched, expectedMatched, lastReady, pollErr,
		)
	}
	return nil
}

// WaitSchemaFingerprint waits until the named SchemaDefinition has
// applied its CURRENT desired-state fingerprint to each of the given
// schemas. Identity-based — race-free vs WaitSchemaUpToDate's
// matchedSchemas-count baseline.
//
// How it works (v0.1.49+):
//   - SD.Status.Fingerprint is a deterministic hash of SD.spec
//     (set by the SD reconciler each pass).
//   - Each emitted MigrationBundle carries that fingerprint as the
//     annotation `keystone.hexxlock.io/sd-fingerprint`.
//   - On MigrationExecution Phase=Succeeded for a schema, the ME
//     reconciler stamps DatabaseSchema.Status.LastAppliedFingerprint
//     = annotation value.
//   - This helper polls until per-schema LastAppliedFingerprint ==
//     SD.Status.Fingerprint for every schema in `schemaRefs`.
//
// When SD.Status.Fingerprint is empty (very first reconcile of a
// freshly-applied SD), the helper waits for it to populate before
// comparing. Schemas with empty LastAppliedFingerprint are treated
// as "not yet at this SD" and stay pending.
//
// Use this helper INSTEAD of WaitSchemaUpToDate when the caller
// updates an existing schema (e.g. realm-DB migrator re-points a
// LogicalDatabase at a new cluster) — the matchedSchemas count
// doesn't change in that flow, so prevMatched+1 is the wrong
// baseline. WaitSchemaFingerprint is identity-based and correct
// for both new-enrollment and update-existing-enrollment cases.
//
// Returns context.DeadlineExceeded with a wrapped error indicating
// which schemas still don't match the SD's current fingerprint when
// ctx cancels.
//
// Same poll backoff as the other Wait* helpers (1s → 30s exponential,
// ctx-bound). NotFound on SD or any DatabaseSchema is treated as
// "keep polling" — caches may not have propagated yet; ctx times
// out if the resource never appears.
func WaitSchemaFingerprint(
	ctx context.Context,
	k8s client.Client,
	sdRef types.NamespacedName,
	schemaRefs []types.NamespacedName,
) error {
	if len(schemaRefs) == 0 {
		return nil
	}
	pending := make(map[types.NamespacedName]struct{}, len(schemaRefs))
	for _, r := range schemaRefs {
		pending[r] = struct{}{}
	}

	backoff := wait.Backoff{
		Duration: 1 * time.Second,
		Factor:   1.5,
		Jitter:   0.1,
		Cap:      30 * time.Second,
		Steps:    1 << 30,
	}

	var lastSDFingerprint string
	pollErr := wait.ExponentialBackoffWithContext(ctx, backoff, func(ctx context.Context) (bool, error) {
		var sd keystonev1alpha1.SchemaDefinition
		if err := k8s.Get(ctx, sdRef, &sd); err != nil {
			if apierrors.IsNotFound(err) {
				return false, nil
			}
			return false, fmt.Errorf("get SchemaDefinition %s: %w", sdRef, err)
		}
		lastSDFingerprint = sd.Status.Fingerprint
		if lastSDFingerprint == "" {
			// SD reconciler hasn't computed Fingerprint yet — wait.
			return false, nil
		}

		for ref := range pending {
			var schema keystonev1alpha1.DatabaseSchema
			if err := k8s.Get(ctx, ref, &schema); err != nil {
				if apierrors.IsNotFound(err) {
					continue
				}
				return false, fmt.Errorf("get DatabaseSchema %s: %w", ref, err)
			}
			if schema.Status.LastAppliedFingerprint == lastSDFingerprint {
				delete(pending, ref)
			}
		}
		return len(pending) == 0, nil
	})
	if pollErr != nil {
		stillPending := make([]string, 0, len(pending))
		for ref := range pending {
			stillPending = append(stillPending, ref.String())
		}
		return fmt.Errorf(
			"waiting for SchemaDefinition %s fingerprint=%q to apply; still pending=%v: %w",
			sdRef, lastSDFingerprint, stillPending, pollErr,
		)
	}
	return nil
}

// DeenrollSchemaOpts identifies a previously-enrolled set of CRs to
// remove. Identification is by (Namespace, NamePrefix, TenantID) — the
// same triplet the EnrollSchema call used. Schemas is required so the
// SDK knows which DatabaseSchemas to delete; passing extra entries
// that were not enrolled is a no-op.
type DeenrollSchemaOpts struct {
	Namespace  string
	NamePrefix string
	TenantID   string

	// SchemaNames mirrors the Schemas[].Name list used at enroll time.
	SchemaNames []string

	// DropData, when true, sets LogicalDatabase.spec.deletionPolicy=
	// Delete BEFORE deleting the CR — the LogicalDatabase controller
	// then drops the underlying PostgreSQL database. Default false:
	// the CR is removed but the data is retained (operator can
	// re-enroll the tenant later without data loss).
	DropData bool
}

// DeenrollSchema deletes DatabaseSchemas first, then the LogicalDatabase.
// Schemas are deleted in reverse-creation order on the off chance a
// caller has dependent schemas; LogicalDatabase removal happens last so
// the controller can drop the DB if DropData=true.
//
// Idempotent: NotFound errors on individual CRs are tolerated (already
// removed). Returns the first non-NotFound error encountered.
func DeenrollSchema(
	ctx context.Context,
	k8s client.Client,
	opts DeenrollSchemaOpts,
) error {
	if opts.Namespace == "" || opts.NamePrefix == "" || opts.TenantID == "" {
		return fmt.Errorf("deenroll: Namespace, NamePrefix, TenantID are all required")
	}
	logicalDBName := fmt.Sprintf("%s-%s", opts.NamePrefix, opts.TenantID)

	// Delete schemas in reverse order (mirrors creation order to keep
	// any dependency-ordering callers expressed by their Schemas slice).
	for i := len(opts.SchemaNames) - 1; i >= 0; i-- {
		schemaName := fmt.Sprintf("%s-%s-%s",
			opts.NamePrefix, opts.TenantID, opts.SchemaNames[i])
		schema := &keystonev1alpha1.DatabaseSchema{
			ObjectMeta: metav1.ObjectMeta{Namespace: opts.Namespace, Name: schemaName},
		}
		if err := k8s.Delete(ctx, schema); err != nil && !apierrors.IsNotFound(err) {
			return fmt.Errorf("delete DatabaseSchema %s/%s: %w",
				opts.Namespace, schemaName, err)
		}
	}

	// LogicalDatabase: optionally flip deletionPolicy=Delete so the
	// controller drops the underlying database. Done as a Patch *before*
	// Delete so the controller observes the policy when it processes
	// finalizer cleanup.
	if opts.DropData {
		ldb := &keystonev1alpha1.LogicalDatabase{}
		err := k8s.Get(ctx,
			types.NamespacedName{Namespace: opts.Namespace, Name: logicalDBName},
			ldb)
		if err != nil && !apierrors.IsNotFound(err) {
			return fmt.Errorf("get LogicalDatabase %s/%s: %w",
				opts.Namespace, logicalDBName, err)
		}
		if err == nil {
			patch := client.MergeFrom(ldb.DeepCopy())
			ldb.Spec.DeletionPolicy = "Delete"
			if err := k8s.Patch(ctx, ldb, patch); err != nil {
				return fmt.Errorf("patch deletionPolicy on %s/%s: %w",
					opts.Namespace, logicalDBName, err)
			}
		}
	}

	ldb := &keystonev1alpha1.LogicalDatabase{
		ObjectMeta: metav1.ObjectMeta{Namespace: opts.Namespace, Name: logicalDBName},
	}
	if err := k8s.Delete(ctx, ldb); err != nil && !apierrors.IsNotFound(err) {
		return fmt.Errorf("delete LogicalDatabase %s/%s: %w",
			opts.Namespace, logicalDBName, err)
	}
	return nil
}

// validateEnrollOpts is the front-door check. Surfaces the most common
// configuration mistakes with names that point at the field, so the
// caller doesn't have to dig through controller errors.
func validateEnrollOpts(opts *EnrollSchemaOpts) error {
	var errs []error
	if opts.Namespace == "" {
		errs = append(errs, fmt.Errorf("Namespace is required"))
	}
	if opts.NamePrefix == "" {
		errs = append(errs, fmt.Errorf("NamePrefix is required"))
	}
	if opts.TenantID == "" {
		errs = append(errs, fmt.Errorf("TenantID is required"))
	}
	if opts.Scope == "" {
		errs = append(errs, fmt.Errorf("Scope is required (sets keystone.hexxlock.io/scope label that SchemaPolicies typically gate by)"))
	}
	if opts.LogicalDatabase.Name == "" {
		errs = append(errs, fmt.Errorf("LogicalDatabase.Name (PG database name) is required"))
	}
	if opts.LogicalDatabase.ClusterRef == "" {
		errs = append(errs, fmt.Errorf("LogicalDatabase.ClusterRef is required"))
	}
	if opts.LogicalDatabase.ProviderRef == "" {
		errs = append(errs, fmt.Errorf("LogicalDatabase.ProviderRef is required"))
	}
	if opts.LogicalDatabase.OwnerRole == "" {
		errs = append(errs, fmt.Errorf("LogicalDatabase.OwnerRole is required"))
	}
	if len(opts.Schemas) == 0 {
		errs = append(errs, fmt.Errorf("Schemas must contain at least one entry"))
	}
	for i, s := range opts.Schemas {
		if s.Name == "" {
			errs = append(errs, fmt.Errorf("Schemas[%d].Name is required", i))
		}
		if s.OwnerRole == "" {
			errs = append(errs, fmt.Errorf("Schemas[%d].OwnerRole is required", i))
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("enroll: %w", errors.Join(errs...))
	}
	return nil
}

// wellKnownEnrollLabels builds the SDK-controlled label set that lands
// on every CR. Caller-supplied Labels can override these by setting the
// same key.
func wellKnownEnrollLabels(opts *EnrollSchemaOpts) map[string]string {
	out := map[string]string{
		keystonev1alpha1.LabelScope:    opts.Scope,
		keystonev1alpha1.LabelTenantID: opts.TenantID,
	}
	if opts.Tier != "" {
		out["keystone.hexxlock.io/tier"] = opts.Tier
	}
	if opts.LogicalDatabase.ClusterRef != "" {
		// Cluster scoping for multi-DC selectors. Future-proofing per
		// the platform's "design for scalability from day one" rule.
		out["keystone.hexxlock.io/cluster"] = opts.LogicalDatabase.ClusterRef
	}
	return out
}

func applyLabels(meta *metav1.ObjectMeta, wellKnown, override map[string]string) {
	if meta.Labels == nil {
		meta.Labels = map[string]string{}
	}
	for k, v := range wellKnown {
		meta.Labels[k] = v
	}
	for k, v := range override {
		meta.Labels[k] = v
	}
}

func applyAnnotations(meta *metav1.ObjectMeta, in map[string]string) {
	if len(in) == 0 {
		return
	}
	if meta.Annotations == nil {
		meta.Annotations = map[string]string{}
	}
	for k, v := range in {
		meta.Annotations[k] = v
	}
}

func isReady(conds []metav1.Condition) bool {
	for _, c := range conds {
		if c.Type == "Ready" && c.Status == metav1.ConditionTrue {
			return true
		}
	}
	return false
}
