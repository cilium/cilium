// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package manager

import (
	"golang.org/x/exp/maps"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/tools/cache"

	"github.com/cilium/cilium/pkg/k8s/resource"
	"github.com/cilium/cilium/pkg/lock"
)

var _ DiffStore[*runtime.Unknown] = (*fakeDiffStore[*runtime.Unknown])(nil)

type fakeDiffStore[T runtime.Object] struct {
	objMu   lock.Mutex
	objects map[resource.Key]T

	changedMu lock.Mutex
	changed   map[resource.Key]bool
}

func newFakeDiffStore[T runtime.Object]() *fakeDiffStore[T] {
	return &fakeDiffStore[T]{
		objects: make(map[resource.Key]T),
		changed: make(map[resource.Key]bool),
	}
}

func (mds *fakeDiffStore[T]) Diff() (upserted []T, deleted []resource.Key, err error) {
	mds.changedMu.Lock()
	defer mds.changedMu.Unlock()

	for key := range mds.changed {
		obj, exists, err := mds.GetByKey(key)
		if err != nil {
			return nil, nil, err
		}
		if exists {
			upserted = append(upserted, obj)
		} else {
			deleted = append(deleted, key)
		}
	}

	// Reset the changed map
	mds.changed = make(map[resource.Key]bool)

	return upserted, deleted, nil
}

// List returns all items currently in the store.
func (mds *fakeDiffStore[T]) List() []T {
	mds.objMu.Lock()
	defer mds.objMu.Unlock()
	return maps.Values(mds.objects)
}

// IterKeys returns a key iterator.
func (mds *fakeDiffStore[T]) IterKeys() resource.KeyIter {
	mds.objMu.Lock()
	defer mds.objMu.Unlock()
	return newMockKeyIter(maps.Keys(mds.objects))
}

func (mds *fakeDiffStore[T]) Upsert(obj T) {
	mds.objMu.Lock()
	mds.changedMu.Lock()
	defer mds.objMu.Unlock()
	defer mds.changedMu.Unlock()

	key := resource.NewKey(obj)
	mds.objects[key] = obj
	mds.changed[key] = true
}

func (mds *fakeDiffStore[T]) Delete(key resource.Key) {
	mds.objMu.Lock()
	mds.changedMu.Lock()
	defer mds.objMu.Unlock()
	defer mds.changedMu.Unlock()

	delete(mds.objects, key)
	mds.changed[key] = true
}

func (mds *fakeDiffStore[T]) CacheStore() cache.Store {
	return nil
}

// Get returns the latest version by deriving the key from the given object.
func (mds *fakeDiffStore[T]) Get(obj T) (item T, exists bool, err error) {
	return mds.GetByKey(resource.NewKey(obj))
}

// GetByKey returns the latest version of the object with given key.
func (mds *fakeDiffStore[T]) GetByKey(key resource.Key) (item T, exists bool, err error) {
	mds.objMu.Lock()
	defer mds.objMu.Unlock()

	item, exists = mds.objects[key]

	return item, exists, nil
}

type fakeKeyIter struct {
	i    int
	keys []resource.Key
}

func newMockKeyIter(keys []resource.Key) *fakeKeyIter {
	return &fakeKeyIter{
		i:    -1,
		keys: keys,
	}
}

// Next returns true if there is a key, false if iteration has finished.
func (mki *fakeKeyIter) Next() bool {
	mki.i++
	return mki.i < len(mki.keys)
}

func (mki *fakeKeyIter) Key() resource.Key {
	key := mki.keys[mki.i]
	return key
}
