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

package platform

import (
	"context"
	"encoding/json"
	"fmt"
	"io"

	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"oras.land/oras-go/v2/content"
	"oras.land/oras-go/v2/errdef"
	"oras.land/oras-go/v2/internal/docker"
	"oras.land/oras-go/v2/internal/manifestutil"
)

// Match checks whether the current platform matches the target platform.
// Match will return true if all of the following conditions are met.
//   - Architecture and OS exactly match.
//   - Variant and OSVersion exactly match if target platform provided.
//   - OSFeatures of the target platform are the subsets of the OSFeatures
//     array of the current platform.
//
// Note: Variant, OSVersion and OSFeatures are optional fields, will skip
// the comparison if the target platform does not provide specific value.
func Match(got *ocispec.Platform, want *ocispec.Platform) bool {
	if got == nil && want == nil {
		return true
	}

	if got == nil || want == nil {
		return false
	}

	if got.Architecture != want.Architecture || got.OS != want.OS {
		return false
	}

	if want.OSVersion != "" && got.OSVersion != want.OSVersion {
		return false
	}

	if want.Variant != "" && got.Variant != want.Variant {
		return false
	}

	if len(want.OSFeatures) != 0 && !isSubset(want.OSFeatures, got.OSFeatures) {
		return false
	}

	return true
}

// isSubset returns true if all items in slice A are present in slice B.
func isSubset(a, b []string) bool {
	set := make(map[string]bool, len(b))
	for _, v := range b {
		set[v] = true
	}
	for _, v := range a {
		if _, ok := set[v]; !ok {
			return false
		}
	}

	return true
}

// SelectManifest implements platform filter and returns the descriptor of the
// first matched manifest if the root is a manifest list. If the root is a
// manifest, then return the root descriptor if platform matches.
func SelectManifest(ctx context.Context, src content.ReadOnlyStorage, root ocispec.Descriptor, p *ocispec.Platform) (ocispec.Descriptor, error) {
	switch root.MediaType {
	case docker.MediaTypeManifestList, ocispec.MediaTypeImageIndex:
		manifests, err := manifestutil.Manifests(ctx, src, root)
		if err != nil {
			return ocispec.Descriptor{}, err
		}

		// platform filter
		for _, m := range manifests {
			if Match(m.Platform, p) {
				return m, nil
			}
		}
		return ocispec.Descriptor{}, fmt.Errorf("%s: %w: no matching manifest was found in the manifest list", root.Digest, errdef.ErrNotFound)
	case docker.MediaTypeManifest, ocispec.MediaTypeImageManifest:
		// config will be non-nil for docker manifest and OCI image manifest
		config, err := manifestutil.Config(ctx, src, root)
		if err != nil {
			return ocispec.Descriptor{}, err
		}

		configMediaType := docker.MediaTypeConfig
		if root.MediaType == ocispec.MediaTypeImageManifest {
			configMediaType = ocispec.MediaTypeImageConfig
		}
		cfgPlatform, err := getPlatformFromConfig(ctx, src, *config, configMediaType)
		if err != nil {
			return ocispec.Descriptor{}, err
		}

		if Match(cfgPlatform, p) {
			return root, nil
		}
		return ocispec.Descriptor{}, fmt.Errorf("%s: %w: platform in manifest does not match target platform", root.Digest, errdef.ErrNotFound)
	default:
		return ocispec.Descriptor{}, fmt.Errorf("%s: %s: %w", root.Digest, root.MediaType, errdef.ErrUnsupported)
	}
}

// getPlatformFromConfig returns a platform object which is made up from the
// fields in config blob.
func getPlatformFromConfig(ctx context.Context, src content.ReadOnlyStorage, desc ocispec.Descriptor, targetConfigMediaType string) (*ocispec.Platform, error) {
	if desc.MediaType != targetConfigMediaType {
		return nil, fmt.Errorf("fail to recognize platform from unknown config %s: expect %s: %w", desc.MediaType, targetConfigMediaType, errdef.ErrUnsupported)
	}

	rc, err := src.Fetch(ctx, desc)
	if err != nil {
		return nil, err
	}
	defer rc.Close()

	var platform ocispec.Platform
	if err = json.NewDecoder(rc).Decode(&platform); err != nil && err != io.EOF {
		return nil, err
	}

	return &platform, nil
}
