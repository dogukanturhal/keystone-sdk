// SPDX-License-Identifier: AGPL-3.0-or-later

package migration

import (
	"encoding/json"
	"testing"

	ocispec "github.com/opencontainers/image-spec/specs-go/v1"

	"oras.land/oras-go/v2/registry/remote/auth"
)

func TestLayerFilename(t *testing.T) {
	tests := []struct {
		name  string
		layer ocispec.Descriptor
		want  string
	}{
		{
			name: "with title annotation",
			layer: ocispec.Descriptor{
				Annotations: map[string]string{
					ocispec.AnnotationTitle: "001_create_users.up.sql",
				},
			},
			want: "001_create_users.up.sql",
		},
		{
			name:  "no annotations",
			layer: ocispec.Descriptor{},
			want:  "",
		},
		{
			name: "empty annotations",
			layer: ocispec.Descriptor{
				Annotations: map[string]string{},
			},
			want: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := layerFilename(tt.layer)
			if got != tt.want {
				t.Errorf("layerFilename() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestParseDockerConfig(t *testing.T) {
	cfg := dockerConfig{
		Auths: map[string]dockerAuth{
			"ghcr.io/dogukanturhal": {
				Username: "robot$keystone",
				Password: "secret123",
			},
		},
	}
	data, _ := json.Marshal(cfg)

	cred, err := parseDockerConfig(data)
	if err != nil {
		t.Fatalf("parseDockerConfig: %v", err)
	}
	if cred.Username != "robot$keystone" {
		t.Errorf("username = %q, want %q", cred.Username, "robot$keystone")
	}
	if cred.Password != "secret123" {
		t.Errorf("password = %q, want %q", cred.Password, "secret123")
	}
}

func TestParseDockerConfig_Empty(t *testing.T) {
	cfg := dockerConfig{Auths: map[string]dockerAuth{}}
	data, _ := json.Marshal(cfg)

	_, err := parseDockerConfig(data)
	if err == nil {
		t.Error("expected error for empty auths")
	}
}

func TestParseDockerConfig_Invalid(t *testing.T) {
	_, err := parseDockerConfig([]byte("not json"))
	if err == nil {
		t.Error("expected error for invalid JSON")
	}
}

// Verify auth.Credential is used correctly (compile-time check).
var _ auth.Credential = auth.Credential{Username: "u", Password: "p"}
