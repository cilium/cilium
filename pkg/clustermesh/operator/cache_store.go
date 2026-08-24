// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package operator

import (
	"fmt"

	"k8s.io/client-go/tools/cache"

	"github.com/cilium/cilium/pkg/kvstore/store"
	cslices "github.com/cilium/cilium/pkg/slices"
)

type CacheStore[T store.NamedKey] struct {
	indexer cache.Indexer
}

// NewCacheStore creates an indexer for clustermesh objects.
// The API was simplified to not return errors since we provide a key function
// that cannot return an error. This means that from the underlying methods
// only ByIndex could return an error when providing an unknown index.
func NewCacheStore[T store.NamedKey](indexers cache.Indexers) *CacheStore[T] {
	return &CacheStore[T]{
		indexer: cache.NewIndexer(func(obj any) (string, error) {
			return obj.(T).GetKeyName(), nil
		}, indexers),
	}
}

func (s *CacheStore[T]) Get(obj T) (item T, exists bool) {
	itemAny, exists, _ := s.indexer.Get(obj)
	if exists {
		item = itemAny.(T)
	}
	return item, exists
}

func (s *CacheStore[T]) GetByKey(key string) (item T, exists bool) {
	itemAny, exists, _ := s.indexer.GetByKey(key)
	if exists {
		item = itemAny.(T)
	}
	return item, exists
}

func (s *CacheStore[T]) MustByIndex(indexName, indexedValue string) []T {
	items, err := s.indexer.ByIndex(indexName, indexedValue)
	if err != nil {
		panic(fmt.Errorf("failed to retrieve objects by index %q with value %q: %w", indexName, indexedValue, err))
	}
	return cslices.Map(items, func(item any) T {
		return item.(T)
	})
}

func (s *CacheStore[T]) Update(obj T) {
	_ = s.indexer.Update(obj)
}

func (s *CacheStore[T]) Delete(obj T) {
	_ = s.indexer.Delete(obj)
}
