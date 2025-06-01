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

package remote

import (
	"strings"

	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"oras.land/oras-go/v2/internal/docker"
	"oras.land/oras-go/v2/internal/spec"
)

// defaultManifestMediaTypes contains the default set of manifests media types.
var defaultManifestMediaTypes = []string{
	docker.MediaTypeManifest,
	docker.MediaTypeManifestList,
	ocispec.MediaTypeImageManifest,
	ocispec.MediaTypeImageIndex,
	spec.MediaTypeArtifactManifest,
}

// defaultManifestAcceptHeader is the default set in the `Accept` header for
// resolving manifests from tags.
var defaultManifestAcceptHeader = strings.Join(defaultManifestMediaTypes, ", ")

// isManifest determines if the given descriptor points to a manifest.
func isManifest(manifestMediaTypes []string, desc ocispec.Descriptor) bool {
	if len(manifestMediaTypes) == 0 {
		manifestMediaTypes = defaultManifestMediaTypes
	}
	for _, mediaType := range manifestMediaTypes {
		if desc.MediaType == mediaType {
			return true
		}
	}
	return false
}

// manifestAcceptHeader generates the set in the `Accept` header for resolving
// manifests from tags.
func manifestAcceptHeader(manifestMediaTypes []string) string {
	if len(manifestMediaTypes) == 0 {
		return defaultManifestAcceptHeader
	}
	return strings.Join(manifestMediaTypes, ", ")
}
