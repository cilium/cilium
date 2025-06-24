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

package resolver

import (
	"context"
	"fmt"
	"maps"
	"sync"

	"github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"oras.land/oras-go/v2/errdef"
	"oras.land/oras-go/v2/internal/container/set"
)

// Memory is a memory based resolver.
type Memory struct {
	lock  sync.RWMutex
	index map[string]ocispec.Descriptor
	tags  map[digest.Digest]set.Set[string]
}

// NewMemory creates a new Memory resolver.
func NewMemory() *Memory {
	return &Memory{
		index: make(map[string]ocispec.Descriptor),
		tags:  make(map[digest.Digest]set.Set[string]),
	}
}

// Resolve resolves a reference to a descriptor.
func (m *Memory) Resolve(_ context.Context, reference string) (ocispec.Descriptor, error) {
	m.lock.RLock()
	defer m.lock.RUnlock()

	desc, ok := m.index[reference]
	if !ok {
		return ocispec.Descriptor{}, fmt.Errorf("%s: %w", reference, errdef.ErrNotFound)
	}
	return desc, nil
}

// Tag tags a descriptor with a reference string.
func (m *Memory) Tag(_ context.Context, desc ocispec.Descriptor, reference string) error {
	m.lock.Lock()
	defer m.lock.Unlock()

	m.index[reference] = desc
	tagSet, ok := m.tags[desc.Digest]
	if !ok {
		tagSet = set.New[string]()
		m.tags[desc.Digest] = tagSet
	}
	tagSet.Add(reference)
	return nil
}

// Untag removes a reference from index map.
func (m *Memory) Untag(reference string) {
	m.lock.Lock()
	defer m.lock.Unlock()

	desc, ok := m.index[reference]
	if !ok {
		return
	}
	delete(m.index, reference)
	tagSet := m.tags[desc.Digest]
	tagSet.Delete(reference)
	if len(tagSet) == 0 {
		delete(m.tags, desc.Digest)
	}
}

// Map dumps the memory into a built-in map structure.
// Like other operations, calling Map() is go-routine safe.
func (m *Memory) Map() map[string]ocispec.Descriptor {
	m.lock.RLock()
	defer m.lock.RUnlock()

	return maps.Clone(m.index)
}

// TagSet returns the set of tags of the descriptor.
func (m *Memory) TagSet(desc ocispec.Descriptor) set.Set[string] {
	m.lock.RLock()
	defer m.lock.RUnlock()

	tagSet := m.tags[desc.Digest]
	return maps.Clone(tagSet)
}
