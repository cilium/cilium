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

package content

import (
	"context"
	"fmt"
	"io"

	"github.com/containerd/containerd/remotes"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

// MultiReader store to read content from multiple stores. It finds the content by asking each underlying
// store to find the content, which it does based on the hash.
//
// Example:
//        fileStore := NewFileStore(rootPath)
//        memoryStore := NewMemoryStore()
//        // load up content in fileStore and memoryStore
//        multiStore := MultiReader([]content.Provider{fileStore, memoryStore})
//
// You now can use multiStore anywhere that content.Provider is accepted
type MultiReader struct {
	stores []remotes.Fetcher
}

// AddStore add a store to read from
func (m *MultiReader) AddStore(store ...remotes.Fetcher) {
	m.stores = append(m.stores, store...)
}

// ReaderAt get a reader
func (m MultiReader) Fetch(ctx context.Context, desc ocispec.Descriptor) (io.ReadCloser, error) {
	for _, store := range m.stores {
		r, err := store.Fetch(ctx, desc)
		if r != nil && err == nil {
			return r, nil
		}
	}
	// we did not find any
	return nil, fmt.Errorf("not found")
}
