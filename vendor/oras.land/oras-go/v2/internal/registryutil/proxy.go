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

package registryutil

import (
	"context"
	"io"
	"sync"

	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"oras.land/oras-go/v2/content"
	"oras.land/oras-go/v2/internal/cas"
	"oras.land/oras-go/v2/internal/ioutil"
	"oras.land/oras-go/v2/registry"
)

// ReferenceStorage represents a CAS that supports registry.ReferenceFetcher.
type ReferenceStorage interface {
	content.ReadOnlyStorage
	registry.ReferenceFetcher
}

// Proxy is a caching proxy dedicated for registry.ReferenceFetcher.
// The first fetch call of a described content will read from the remote and
// cache the fetched content.
// The subsequent fetch call will read from the local cache.
type Proxy struct {
	registry.ReferenceFetcher
	*cas.Proxy
}

// NewProxy creates a proxy for the `base` ReferenceStorage, using the `cache`
// storage as the cache.
func NewProxy(base ReferenceStorage, cache content.Storage) *Proxy {
	return &Proxy{
		ReferenceFetcher: base,
		Proxy:            cas.NewProxy(base, cache),
	}
}

// FetchReference fetches the content identified by the reference from the
// remote and cache the fetched content.
func (p *Proxy) FetchReference(ctx context.Context, reference string) (ocispec.Descriptor, io.ReadCloser, error) {
	target, rc, err := p.ReferenceFetcher.FetchReference(ctx, reference)
	if err != nil {
		return ocispec.Descriptor{}, nil, err
	}

	// skip caching if the content already exists in cache
	exists, err := p.Cache.Exists(ctx, target)
	if err != nil {
		return ocispec.Descriptor{}, nil, err
	}
	if exists {
		return target, rc, nil
	}

	// cache content while reading
	pr, pw := io.Pipe()
	var wg sync.WaitGroup
	wg.Add(1)
	var pushErr error
	go func() {
		defer wg.Done()
		pushErr = p.Cache.Push(ctx, target, pr)
		if pushErr != nil {
			pr.CloseWithError(pushErr)
		}
	}()
	closer := ioutil.CloserFunc(func() error {
		rcErr := rc.Close()
		if err := pw.Close(); err != nil {
			return err
		}
		wg.Wait()
		if pushErr != nil {
			return pushErr
		}
		return rcErr
	})

	return target, struct {
		io.Reader
		io.Closer
	}{
		Reader: io.TeeReader(rc, pw),
		Closer: closer,
	}, nil
}
