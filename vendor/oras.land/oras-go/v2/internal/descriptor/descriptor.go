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

package descriptor

import (
	"github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"oras.land/oras-go/v2/internal/docker"
	"oras.land/oras-go/v2/internal/spec"
)

// DefaultMediaType is the media type used when no media type is specified.
const DefaultMediaType string = "application/octet-stream"

// Descriptor contains the minimun information to describe the disposition of
// targeted content.
// Since it only has strings and integers, Descriptor is a comparable struct.
type Descriptor struct {
	// MediaType is the media type of the object this schema refers to.
	MediaType string `json:"mediaType,omitempty"`

	// Digest is the digest of the targeted content.
	Digest digest.Digest `json:"digest"`

	// Size specifies the size in bytes of the blob.
	Size int64 `json:"size"`
}

// Empty is an empty descriptor
var Empty Descriptor

// FromOCI shrinks the OCI descriptor to the minimum.
func FromOCI(desc ocispec.Descriptor) Descriptor {
	return Descriptor{
		MediaType: desc.MediaType,
		Digest:    desc.Digest,
		Size:      desc.Size,
	}
}

// IsForeignLayer checks if a descriptor describes a foreign layer.
func IsForeignLayer(desc ocispec.Descriptor) bool {
	switch desc.MediaType {
	case ocispec.MediaTypeImageLayerNonDistributable,
		ocispec.MediaTypeImageLayerNonDistributableGzip,
		ocispec.MediaTypeImageLayerNonDistributableZstd,
		docker.MediaTypeForeignLayer:
		return true
	default:
		return false
	}
}

// IsManifest checks if a descriptor describes a manifest.
func IsManifest(desc ocispec.Descriptor) bool {
	switch desc.MediaType {
	case docker.MediaTypeManifest,
		docker.MediaTypeManifestList,
		ocispec.MediaTypeImageManifest,
		ocispec.MediaTypeImageIndex,
		spec.MediaTypeArtifactManifest:
		return true
	default:
		return false
	}
}

// Plain returns a plain descriptor that contains only MediaType, Digest and
// Size.
func Plain(desc ocispec.Descriptor) ocispec.Descriptor {
	return ocispec.Descriptor{
		MediaType: desc.MediaType,
		Digest:    desc.Digest,
		Size:      desc.Size,
	}
}
