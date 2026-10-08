// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package store

import (
	"maps"
	"slices"

	"k8s.io/apimachinery/pkg/runtime"

	"github.com/cilium/cilium/pkg/k8s/resource"
	"github.com/cilium/cilium/pkg/lock"
)

var _ BGPCPResourceStore[*runtime.Unknown] = (*MockBGPCPResourceStore[*runtime.Unknown])(nil)

type MockBGPCPResourceStore[T runtime.Object] struct {
	objMu   lock.Mutex
	objects map[resource.Key]T
}

func NewMockBGPCPResourceStore[T runtime.Object]() *MockBGPCPResourceStore[T] {
	return &MockBGPCPResourceStore[T]{
		objects: make(map[resource.Key]T),
	}
}

func (mds *MockBGPCPResourceStore[T]) List() ([]T, error) {
	mds.objMu.Lock()
	defer mds.objMu.Unlock()
	return slices.Collect(maps.Values(mds.objects)), nil
}

func (mds *MockBGPCPResourceStore[T]) GetByKey(key resource.Key) (item T, exists bool, err error) {
	mds.objMu.Lock()
	defer mds.objMu.Unlock()

	item, exists = mds.objects[key]

	return item, exists, nil
}

func (mds *MockBGPCPResourceStore[T]) Upsert(obj T) {
	mds.objMu.Lock()
	defer mds.objMu.Unlock()

	key := resource.NewKey(obj)
	mds.objects[key] = obj
}

func (mds *MockBGPCPResourceStore[T]) Delete(key resource.Key) {
	mds.objMu.Lock()
	defer mds.objMu.Unlock()

	delete(mds.objects, key)
}

func InitMockStore[T runtime.Object](objects []T) BGPCPResourceStore[T] {
	store := NewMockBGPCPResourceStore[T]()
	for _, obj := range objects {
		store.Upsert(obj)
	}
	return store
}
