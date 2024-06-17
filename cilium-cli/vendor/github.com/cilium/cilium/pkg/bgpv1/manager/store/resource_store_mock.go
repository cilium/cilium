// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package store

import (
	"golang.org/x/exp/maps"
	"k8s.io/apimachinery/pkg/runtime"

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

func (mds *mockBGPCPResourceStore[T]) List() ([]T, error) {
	mds.objMu.Lock()
	defer mds.objMu.Unlock()
	return maps.Values(mds.objects), nil
}

func (mds *mockBGPCPResourceStore[T]) GetByKey(key resource.Key) (item T, exists bool, err error) {
	mds.objMu.Lock()
	defer mds.objMu.Unlock()

	item, exists = mds.objects[key]

	return item, exists, nil
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

func InitMockStore[T runtime.Object](objects []T) BGPCPResourceStore[T] {
	store := NewMockBGPCPResourceStore[T]()
	for _, obj := range objects {
		store.Upsert(obj)
	}
	return store
}
