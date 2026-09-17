// SPDX-License-Identifier: AGPL-3.0-or-later

package migration

import (
	"context"
	"fmt"

	"sigs.k8s.io/controller-runtime/pkg/client"

	keystonev1alpha1 "github.com/dogukanturhal/keystone/api/v1alpha1"
)

// compositeResolver delegates to the appropriate resolver based on
// the source type. This is the production resolver used by the
// MigrationBundleReconciler.
type compositeResolver struct {
	configMap SourceResolver
	oci       SourceResolver
}

// NewCompositeResolver creates a resolver that handles ConfigMap and
// OCI sources. It is the recommended resolver for production use,
// replacing NewConfigMapResolver when OCI support is needed.
//
// Two reader arguments by design:
//
//   - `cmReader` should be the manager's APIReader (uncached). The
//     manager's per-type ConfigMap cache is scoped by label to only
//     SD-emitted bundle CMs, so user-authored ConfigMap-sourced
//     bundles must read uncached to be resolvable. See cmd/manager/
//     main.go cache.Options.ByObject for the cache scope wiring.
//
//   - `cli` should be the manager's cache-backed Client (the OCI
//     resolver reads pull-secret Secrets through it; that path is
//     unaffected by the ConfigMap cache scope and stays on the
//     cached client to amortise repeated pulls during burst
//     reconciles).
//
// Tests typically pass the same fake `client.Client` for both — the
// fake satisfies `client.Reader` and routes both to the same in-memory
// store.
func NewCompositeResolver(cmReader client.Reader, cli client.Client) SourceResolver {
	return &compositeResolver{
		configMap: NewConfigMapResolver(cmReader),
		oci:       NewOCIResolver(cli),
	}
}

func (r *compositeResolver) Resolve(ctx context.Context, namespace string, src keystonev1alpha1.MigrationSource) (*ResolvedSource, error) {
	switch src.Type {
	case keystonev1alpha1.SourceConfigMap:
		return r.configMap.Resolve(ctx, namespace, src)
	case keystonev1alpha1.SourceOCIArtifact:
		return r.oci.Resolve(ctx, namespace, src)
	default:
		return nil, fmt.Errorf("unsupported source type: %s", src.Type)
	}
}
