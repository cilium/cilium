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

var _ DiffStore[*runtime.Unknown] = (*fakeDiffStore[*runtime.Unknown])(nil)

type fakeDiffStore[T runtime.Object] struct {
	objMu   lock.Mutex
	objects map[resource.Key]T

	changedMu lock.Mutex
	changed   map[string]updatedKeysMap     // updated keys per caller ID
	deleted   map[string]map[resource.Key]T // deleted objects per caller ID
}

func NewFakeDiffStore[T runtime.Object]() *fakeDiffStore[T] {
	return &fakeDiffStore[T]{
		objects: make(map[resource.Key]T),
		changed: make(map[string]updatedKeysMap),
		deleted: make(map[string]map[resource.Key]T),
	}
}

func InitFakeDiffStore[T runtime.Object](objs []T) *fakeDiffStore[T] {
	mds := NewFakeDiffStore[T]()
	for _, obj := range objs {
		mds.Upsert(obj)
	}
	return mds
}
func (mds *fakeDiffStore[T]) InitDiff(callerID string) {
	mds.changedMu.Lock()
	defer mds.changedMu.Unlock()

	mds.changed[callerID] = make(map[resource.Key]bool)
	mds.deleted[callerID] = make(map[resource.Key]T)
}

func (mds *fakeDiffStore[T]) Diff(callerID string) (upserted []T, deleted []T, err error) {
	mds.changedMu.Lock()
	defer mds.changedMu.Unlock()

	changed, ok := mds.changed[callerID]
	if !ok {
		return nil, nil, ErrDiffUninitialized
	}

	for key := range changed {
		obj, exists, err := mds.GetByKey(key)
		if err != nil {
			return nil, nil, err
		}
		if exists {
			upserted = append(upserted, obj)
		}
	}

	for _, obj := range mds.deleted[callerID] {
		deleted = append(deleted, obj)
	}

	// Reset the maps
	mds.changed[callerID] = make(map[resource.Key]bool)
	mds.deleted[callerID] = make(map[resource.Key]T)

	return upserted, deleted, nil
}

func (mds *fakeDiffStore[T]) CleanupDiff(callerID string) {
	mds.changedMu.Lock()
	defer mds.changedMu.Unlock()

	delete(mds.changed, callerID)
	delete(mds.deleted, callerID)
}

// List returns all items currently in the store.
func (mds *fakeDiffStore[T]) List() ([]T, error) {
	mds.objMu.Lock()
	defer mds.objMu.Unlock()
	return slices.Collect(maps.Values(mds.objects)), nil
}

// GetByKey returns the latest version of the object with given key.
func (mds *fakeDiffStore[T]) GetByKey(key resource.Key) (item T, exists bool, err error) {
	mds.objMu.Lock()
	defer mds.objMu.Unlock()

	item, exists = mds.objects[key]

	return item, exists, nil
}

func (mds *fakeDiffStore[T]) Upsert(obj T) {
	mds.objMu.Lock()
	mds.changedMu.Lock()
	defer mds.objMu.Unlock()
	defer mds.changedMu.Unlock()

	key := resource.NewKey(obj)
	mds.objects[key] = obj
	for _, changed := range mds.changed {
		changed[key] = true
	}
}

func (mds *fakeDiffStore[T]) Delete(obj T) {
	mds.objMu.Lock()
	mds.changedMu.Lock()
	defer mds.objMu.Unlock()
	defer mds.changedMu.Unlock()

	key := resource.NewKey(obj)
	for _, deleted := range mds.deleted {
		deleted[key] = obj
	}
	delete(mds.objects, key)
}
