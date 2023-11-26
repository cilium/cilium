// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package resource

import (
	corev1 "k8s.io/api/core/v1"
	k8sRuntime "k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/tools/cache"
)

// Store is a read-only typed wrapper for cache.Store.
type Store[T k8sRuntime.Object] interface {
	// List returns all items currently in the store.
	List() []T

	// IterKeys returns a key iterator.
	IterKeys() KeyIter

	// Get returns the latest version by deriving the key from the given object.
	Get(obj T) (item T, exists bool, err error)

	// GetByKey returns the latest version of the object with given key.
	GetByKey(key Key) (item T, exists bool, err error)

	// IndexKeys returns the keys of the stored objects whose set of indexed values
	// for the index includes the given indexed value.
	IndexKeys(indexName, indexedValue string) ([]string, error)

	// ByIndex returns the stored objects whose set of indexed values for the index
	// includes the given indexed value.
	ByIndex(indexName, indexedValue string) ([]T, error)

	// CacheStore returns the underlying cache.Store instance. Use for temporary
	// compatibility purposes only!
	CacheStore() cache.Store

	// Release the store and allows the associated resource to stop its informer if
	// this is the last reference to it.
	// This is a no-op if the resource is not releasable.
	Release()
}

// typedStore implements Store on top of an untyped cache.Indexer.
type typedStore[T k8sRuntime.Object] struct {
	store   cache.Indexer
	release func()
}

var _ Store[*corev1.Node] = &typedStore[*corev1.Node]{}

func (s *typedStore[T]) List() []T {
	items := s.store.List()
	result := make([]T, len(items))
	for i := range items {
		result[i] = items[i].(T)
	}
	return result
}

func (s *typedStore[T]) IterKeys() KeyIter {
	return &keyIterImpl{keys: s.store.ListKeys(), pos: -1}
}

func (s *typedStore[T]) Get(obj T) (item T, exists bool, err error) {
	return s.GetByKey(NewKey(obj))
}

func (s *typedStore[T]) GetByKey(key Key) (item T, exists bool, err error) {
	var itemAny any
	itemAny, exists, err = s.store.GetByKey(key.String())
	if exists {
		item = itemAny.(T)
	}
	return
}

func (s *typedStore[T]) IndexKeys(indexName, indexedValue string) ([]string, error) {
	return s.store.IndexKeys(indexName, indexedValue)
}

func (s *typedStore[T]) ByIndex(indexName, indexedValue string) ([]T, error) {
	itemsAny, err := s.store.ByIndex(indexName, indexedValue)
	if err != nil {
		return nil, err
	}
	items := make([]T, 0, len(itemsAny))
	for _, item := range itemsAny {
		items = append(items, item.(T))
	}
	return items, nil
}

func (s *typedStore[T]) CacheStore() cache.Store {
	return s.store
}

func (s *typedStore[T]) Release() {
	s.release()
}

type KeyIter interface {
	// Next returns true if there is a key, false if iteration has finished.
	Next() bool
	Key() Key
}

type keyIterImpl struct {
	keys []string
	pos  int
}

func (it *keyIterImpl) Next() bool {
	it.pos++
	return it.pos < len(it.keys)
}

func (it *keyIterImpl) Key() Key {
	ns, name, _ := cache.SplitMetaNamespaceKey(it.keys[it.pos])
	// ignoring error from SplitMetaNamespaceKey as the string is from
	// the cache.
	return Key{Namespace: ns, Name: name}
}
