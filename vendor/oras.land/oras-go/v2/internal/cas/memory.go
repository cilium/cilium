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

package cas

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"sync"

	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	contentpkg "oras.land/oras-go/v2/content"
	"oras.land/oras-go/v2/errdef"
	"oras.land/oras-go/v2/internal/descriptor"
)

// Memory is a memory based CAS.
type Memory struct {
	content sync.Map // map[descriptor.Descriptor][]byte
}

// NewMemory creates a new Memory CAS.
func NewMemory() *Memory {
	return &Memory{}
}

// Fetch fetches the content identified by the descriptor.
func (m *Memory) Fetch(_ context.Context, target ocispec.Descriptor) (io.ReadCloser, error) {
	key := descriptor.FromOCI(target)
	content, exists := m.content.Load(key)
	if !exists {
		return nil, fmt.Errorf("%s: %s: %w", key.Digest, key.MediaType, errdef.ErrNotFound)
	}
	return io.NopCloser(bytes.NewReader(content.([]byte))), nil
}

// Push pushes the content, matching the expected descriptor.
func (m *Memory) Push(_ context.Context, expected ocispec.Descriptor, content io.Reader) error {
	key := descriptor.FromOCI(expected)

	// check if the content exists in advance to avoid reading from the content.
	if _, exists := m.content.Load(key); exists {
		return fmt.Errorf("%s: %s: %w", key.Digest, key.MediaType, errdef.ErrAlreadyExists)
	}

	// read and try to store the content.
	value, err := contentpkg.ReadAll(content, expected)
	if err != nil {
		return err
	}
	if _, exists := m.content.LoadOrStore(key, value); exists {
		return fmt.Errorf("%s: %s: %w", key.Digest, key.MediaType, errdef.ErrAlreadyExists)
	}
	return nil
}

// Exists returns true if the described content exists.
func (m *Memory) Exists(_ context.Context, target ocispec.Descriptor) (bool, error) {
	key := descriptor.FromOCI(target)
	_, exists := m.content.Load(key)
	return exists, nil
}

// Map dumps the memory into a built-in map structure.
// Like other operations, calling Map() is go-routine safe. However, it does not
// necessarily correspond to any consistent snapshot of the storage contents.
func (m *Memory) Map() map[descriptor.Descriptor][]byte {
	res := make(map[descriptor.Descriptor][]byte)
	m.content.Range(func(key, value interface{}) bool {
		res[key.(descriptor.Descriptor)] = value.([]byte)
		return true
	})
	return res
}
