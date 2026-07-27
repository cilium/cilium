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

// Package memory provides implementation of a memory backed content store.
package memory

import (
	"context"
	"fmt"
	"io"

	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"oras.land/oras-go/v2/content"
	"oras.land/oras-go/v2/errdef"
	"oras.land/oras-go/v2/internal/cas"
	"oras.land/oras-go/v2/internal/graph"
	"oras.land/oras-go/v2/internal/resolver"
)

// Store represents a memory based store, which implements `oras.Target`.
type Store struct {
	storage  content.Storage
	resolver content.TagResolver
	graph    *graph.Memory
}

// New creates a new memory based store.
func New() *Store {
	return &Store{
		storage:  cas.NewMemory(),
		resolver: resolver.NewMemory(),
		graph:    graph.NewMemory(),
	}
}

// Fetch fetches the content identified by the descriptor.
func (s *Store) Fetch(ctx context.Context, target ocispec.Descriptor) (io.ReadCloser, error) {
	return s.storage.Fetch(ctx, target)
}

// Push pushes the content, matching the expected descriptor.
func (s *Store) Push(ctx context.Context, expected ocispec.Descriptor, reader io.Reader) error {
	if err := s.storage.Push(ctx, expected, reader); err != nil {
		return err
	}

	// index predecessors.
	// there is no data consistency issue as long as deletion is not implemented
	// for the memory store.
	return s.graph.Index(ctx, s.storage, expected)
}

// Exists returns true if the described content exists.
func (s *Store) Exists(ctx context.Context, target ocispec.Descriptor) (bool, error) {
	return s.storage.Exists(ctx, target)
}

// Resolve resolves a reference to a descriptor.
func (s *Store) Resolve(ctx context.Context, reference string) (ocispec.Descriptor, error) {
	return s.resolver.Resolve(ctx, reference)
}

// Tag tags a descriptor with a reference string.
// Returns ErrNotFound if the tagged content does not exist.
func (s *Store) Tag(ctx context.Context, desc ocispec.Descriptor, reference string) error {
	exists, err := s.storage.Exists(ctx, desc)
	if err != nil {
		return err
	}
	if !exists {
		return fmt.Errorf("%s: %s: %w", desc.Digest, desc.MediaType, errdef.ErrNotFound)
	}
	return s.resolver.Tag(ctx, desc, reference)
}

// Predecessors returns the nodes directly pointing to the current node.
// Predecessors returns nil without error if the node does not exists in the
// store.
// Like other operations, calling Predecessors() is go-routine safe. However,
// it does not necessarily correspond to any consistent snapshot of the stored
// contents.
func (s *Store) Predecessors(ctx context.Context, node ocispec.Descriptor) ([]ocispec.Descriptor, error) {
	return s.graph.Predecessors(ctx, node)
}
