// SPDX-License-Identifier: AGPL-3.0-or-later

package migration

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"path/filepath"
	"sort"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"oras.land/oras-go/v2/registry/remote"
	"oras.land/oras-go/v2/registry/remote/auth"

	ocispec "github.com/opencontainers/image-spec/specs-go/v1"

	keystonev1alpha1 "github.com/dogukanturhal/keystone/api/v1alpha1"
)

// ociResolver pulls SQL files from OCI artifacts in container registries.
// Credentials are read from Kubernetes Secrets (dockerconfigjson or
// plain username/password). Integrity verification (keystone.sum) is
// applied the same way as ConfigMap sources.
type ociResolver struct {
	c client.Client
}

// NewOCIResolver creates a resolver that can pull OCI artifacts.
func NewOCIResolver(c client.Client) SourceResolver {
	return &ociResolver{c: c}
}

func (r *ociResolver) Resolve(ctx context.Context, namespace string, src keystonev1alpha1.MigrationSource) (*ResolvedSource, error) {
	if src.Type != keystonev1alpha1.SourceOCIArtifact {
		return nil, fmt.Errorf("ociResolver received %s source", src.Type)
	}
	if src.OCIArtifactRef == nil {
		return nil, fmt.Errorf("source.type=OCIArtifact requires source.ociArtifactRef")
	}
	ref := src.OCIArtifactRef

	repo, err := remote.NewRepository(ref.Repository)
	if err != nil {
		return nil, fmt.Errorf("parse OCI repository %q: %w", ref.Repository, err)
	}
	repo.PlainHTTP = ref.PlainHTTP

	// Resolve credentials if a pull secret is provided.
	if ref.PullSecretRef != "" {
		cred, err := r.resolveCredentials(ctx, namespace, ref.PullSecretRef)
		if err != nil {
			return nil, fmt.Errorf("resolve OCI credentials: %w", err)
		}
		repo.Client = &auth.Client{
			Credential: auth.StaticCredential(repo.Reference.Host(), cred),
		}
	}

	// Build the reference string (digest takes precedence over tag).
	reference := ref.Tag
	if reference == "" {
		reference = "latest"
	}
	if ref.Digest != "" {
		reference = ref.Digest
	}

	// Resolve the manifest.
	desc, err := repo.Resolve(ctx, reference)
	if err != nil {
		return nil, fmt.Errorf("resolve OCI manifest %s:%s: %w", ref.Repository, reference, err)
	}

	// Fetch the manifest to discover layers.
	manifestRC, err := repo.Fetch(ctx, desc)
	if err != nil {
		return nil, fmt.Errorf("fetch OCI manifest: %w", err)
	}
	manifestBytes, err := io.ReadAll(io.LimitReader(manifestRC, 1<<20)) // 1MB limit
	manifestRC.Close()
	if err != nil {
		return nil, fmt.Errorf("read OCI manifest: %w", err)
	}

	var manifest ocispec.Manifest
	if err := json.Unmarshal(manifestBytes, &manifest); err != nil {
		return nil, fmt.Errorf("parse OCI manifest: %w", err)
	}

	pattern := ref.FilePattern
	if pattern == "" {
		pattern = "*.up.sql"
	}

	out := &ResolvedSource{Files: make(map[string]string)}
	var rawSum []byte

	// Each layer is one file. The layer's annotations carry the filename.
	for _, layer := range manifest.Layers {
		filename := layerFilename(layer)
		if filename == "" {
			continue
		}

		// Fetch layer content.
		layerRC, err := repo.Fetch(ctx, layer)
		if err != nil {
			return nil, fmt.Errorf("fetch layer %s: %w", filename, err)
		}
		content, err := io.ReadAll(io.LimitReader(layerRC, 10<<20)) // 10MB per file
		layerRC.Close()
		if err != nil {
			return nil, fmt.Errorf("read layer %s: %w", filename, err)
		}

		if filename == SumFilename {
			rawSum = content
			continue
		}

		matched, err := filepath.Match(pattern, filename)
		if err != nil {
			return nil, fmt.Errorf("invalid file pattern %q: %w", pattern, err)
		}
		if !matched {
			continue
		}
		out.Files[filename] = string(content)
		out.Names = append(out.Names, filename)
	}

	sort.Strings(out.Names)
	out.ContentHash = HashFiles(out.Files, out.Names)
	applyIntegrity(out, rawSum)
	return out, nil
}

// layerFilename extracts the filename from an OCI layer descriptor.
// Convention: the annotation "org.opencontainers.image.title" carries
// the filename (this is what ORAS push uses).
func layerFilename(layer ocispec.Descriptor) string {
	if layer.Annotations == nil {
		return ""
	}
	return layer.Annotations[ocispec.AnnotationTitle]
}

// resolveCredentials reads OCI registry auth from a Kubernetes Secret.
// Supports both dockerconfigjson and plain username/password formats.
func (r *ociResolver) resolveCredentials(ctx context.Context, namespace, secretName string) (auth.Credential, error) {
	var secret corev1.Secret
	if err := r.c.Get(ctx, types.NamespacedName{
		Namespace: namespace, Name: secretName,
	}, &secret); err != nil {
		return auth.Credential{}, fmt.Errorf("get pull secret %s/%s: %w", namespace, secretName, err)
	}

	// Try dockerconfigjson first.
	if data, ok := secret.Data[".dockerconfigjson"]; ok {
		return parseDockerConfig(data)
	}

	// Fall back to plain username/password keys.
	username := string(secret.Data["username"])
	password := string(secret.Data["password"])
	if username == "" || password == "" {
		return auth.Credential{}, fmt.Errorf("pull secret %s/%s has neither "+
			".dockerconfigjson nor username/password keys", namespace, secretName)
	}
	return auth.Credential{
		Username: username,
		Password: password,
	}, nil
}

// dockerConfig is the minimal structure for parsing .dockerconfigjson.
type dockerConfig struct {
	Auths map[string]dockerAuth `json:"auths"`
}

type dockerAuth struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// parseDockerConfig extracts the first credential from a dockerconfigjson.
func parseDockerConfig(data []byte) (auth.Credential, error) {
	var cfg dockerConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return auth.Credential{}, fmt.Errorf("parse dockerconfigjson: %w", err)
	}
	for _, a := range cfg.Auths {
		return auth.Credential{
			Username: a.Username,
			Password: a.Password,
		}, nil
	}
	return auth.Credential{}, fmt.Errorf("dockerconfigjson has no auth entries")
}
