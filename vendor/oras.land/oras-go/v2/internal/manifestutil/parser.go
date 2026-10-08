/*
Copyright The ORAS Authors.
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package manifestutil

import (
	"context"
	"encoding/json"

	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"oras.land/oras-go/v2/content"
	"oras.land/oras-go/v2/internal/docker"
	"oras.land/oras-go/v2/internal/spec"
)

// Config returns the config of desc, if present.
func Config(ctx context.Context, fetcher content.Fetcher, desc ocispec.Descriptor) (*ocispec.Descriptor, error) {
	switch desc.MediaType {
	case docker.MediaTypeManifest, ocispec.MediaTypeImageManifest:
		content, err := content.FetchAll(ctx, fetcher, desc)
		if err != nil {
			return nil, err
		}
		// OCI manifest schema can be used to marshal docker manifest
		var manifest ocispec.Manifest
		if err := json.Unmarshal(content, &manifest); err != nil {
			return nil, err
		}
		return &manifest.Config, nil
	default:
		return nil, nil
	}
}

// Manifest returns the manifests of desc, if present.
func Manifests(ctx context.Context, fetcher content.Fetcher, desc ocispec.Descriptor) ([]ocispec.Descriptor, error) {
	switch desc.MediaType {
	case docker.MediaTypeManifestList, ocispec.MediaTypeImageIndex:
		content, err := content.FetchAll(ctx, fetcher, desc)
		if err != nil {
			return nil, err
		}
		// OCI manifest index schema can be used to marshal docker manifest list
		var index ocispec.Index
		if err := json.Unmarshal(content, &index); err != nil {
			return nil, err
		}
		return index.Manifests, nil
	default:
		return nil, nil
	}
}

// Subject returns the subject of desc, if present.
func Subject(ctx context.Context, fetcher content.Fetcher, desc ocispec.Descriptor) (*ocispec.Descriptor, error) {
	switch desc.MediaType {
	case ocispec.MediaTypeImageManifest, ocispec.MediaTypeImageIndex, spec.MediaTypeArtifactManifest:
		content, err := content.FetchAll(ctx, fetcher, desc)
		if err != nil {
			return nil, err
		}
		var manifest struct {
			Subject *ocispec.Descriptor `json:"subject,omitempty"`
		}
		if err := json.Unmarshal(content, &manifest); err != nil {
			return nil, err
		}
		return manifest.Subject, nil
	default:
		return nil, nil
	}
}
