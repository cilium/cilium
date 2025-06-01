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

// Package content provides implementations to access content stores.
package content

import (
	"context"

	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

// Resolver resolves reference tags.
type Resolver interface {
	// Resolve resolves a reference to a descriptor.
	Resolve(ctx context.Context, reference string) (ocispec.Descriptor, error)
}

// Tagger tags reference tags.
type Tagger interface {
	// Tag tags a descriptor with a reference string.
	Tag(ctx context.Context, desc ocispec.Descriptor, reference string) error
}

// TagResolver provides reference tag indexing services.
type TagResolver interface {
	Tagger
	Resolver
}

// Untagger untags reference tags.
type Untagger interface {
	// Untag untags the given reference string.
	Untag(ctx context.Context, reference string) error
}
