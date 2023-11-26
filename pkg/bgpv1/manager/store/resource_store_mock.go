// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package store

import (
	"golang.org/x/exp/maps"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/tools/cache"

	"github.com/cilium/cilium/pkg/k8s/resource"
	"github.com/cilium/cilium/pkg/lock"
)

var _ BGPCPResourceStore[*runtime.Unknown] = (*mockBGPCPResourceStore[*runtime.Unknown])(nil)

type mockBGPCPResourceStore[T runtime.Object] struct {
	objMu   lock.Mutex
	objects map[resource.Key]T
}

func NewMockBGPCPResourceStore[T runtime.Object]() *mockBGPCPResourceStore[T] {
	return &mockBGPCPResourceStore[T]{
		objects: make(map[resource.Key]T),
	}
}

func (mds *mockBGPCPResourceStore[T]) List() []T {
	mds.objMu.Lock()
	defer mds.objMu.Unlock()
	return maps.Values(mds.objects)
}

func (mds *mockBGPCPResourceStore[T]) IterKeys() resource.KeyIter {
	mds.objMu.Lock()
	defer mds.objMu.Unlock()
	return newMockKeyIter(maps.Keys(mds.objects))
}

func (mds *mockBGPCPResourceStore[T]) Upsert(obj T) {
	mds.objMu.Lock()
	defer mds.objMu.Unlock()

	key := resource.NewKey(obj)
	mds.objects[key] = obj
}

func (mds *mockBGPCPResourceStore[T]) Delete(key resource.Key) {
	mds.objMu.Lock()
	defer mds.objMu.Unlock()

	delete(mds.objects, key)
}

func (mds *mockBGPCPResourceStore[T]) IndexKeys(indexName, indexedValue string) ([]string, error) {
	return nil, nil
}

func (mds *mockBGPCPResourceStore[T]) ByIndex(indexName, indexedValue string) ([]T, error) {
	return nil, nil
}

func (mds *mockBGPCPResourceStore[T]) CacheStore() cache.Store {
	return nil
}

func (mds *mockBGPCPResourceStore[T]) Get(obj T) (item T, exists bool, err error) {
	return mds.GetByKey(resource.NewKey(obj))
}

func (mds *mockBGPCPResourceStore[T]) GetByKey(key resource.Key) (item T, exists bool, err error) {
	mds.objMu.Lock()
	defer mds.objMu.Unlock()

	item, exists = mds.objects[key]

	return item, exists, nil
}

func (mds *mockBGPCPResourceStore[T]) Release() {
}
