// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package store

import (
	"context"
	"errors"
	"fmt"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	k8sRuntime "k8s.io/apimachinery/pkg/runtime"

	"github.com/cilium/cilium/pkg/bgpv1/agent/signaler"
	"github.com/cilium/cilium/pkg/k8s/resource"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/time"
)

var (
	ErrStoreUninitialized = errors.New("the store has not initialized yet")
	ErrDiffUninitialized  = errors.New("diff not initialized for caller")
)

// DiffStore is a wrapper around the resource.Store. The diffStore tracks all changes made to it since the
// last time the user synced up. This allows a user to get a list of just the changed objects while still being able
// to query the full store for a full sync.
type DiffStore[T k8sRuntime.Object] interface {
	// InitDiff initializes tracking io items to Diff for the given callerID.
	InitDiff(callerID string)

	// Diff returns a list of items that have been upserted (updated or inserted) and deleted
	// since InitDiff or the last call to Diff with the same callerID.
	// Init(callerID) has to be called before Diff(callerID).
	Diff(callerID string) (upserted []T, deleted []T, err error)

	// CleanupDiff cleans up all caller-specific diff state.
	CleanupDiff(callerID string)

	// GetByKey returns the latest version of the object with given key.
	GetByKey(key resource.Key) (item T, exists bool, err error)

	// List returns all items currently in the store.
	List() (items []T, err error)
}

var _ DiffStore[*k8sRuntime.Unknown] = (*diffStore[*k8sRuntime.Unknown])(nil)

type diffStoreParams[T k8sRuntime.Object] struct {
	cell.In

	Lifecycle cell.Lifecycle
	Health    cell.Health
	JobGroup  job.Group
	Resource  resource.Resource[T]
	Signaler  *signaler.BGPCPSignaler
}

// updatedKeysMap is a map of updated resource keys since the last diff against the map.
type updatedKeysMap map[resource.Key]bool

// diffStore takes a resource.Resource[T] and watches for events, it stores all of the keys that have been changed.
// diffStore can still be used as a normal store, but adds the Diff function to get a Diff of all changes.
// The diffStore also takes in Signaler which it will signal after the initial sync and every update thereafter.
type diffStore[T k8sRuntime.Object] struct {
	store resource.Store[T]

	resource resource.Resource[T]
	signaler *signaler.BGPCPSignaler

	initialSync bool

	mu                lock.Mutex
	callerUpdatedKeys map[string]updatedKeysMap     // updated keys per caller ID
	callerDeletedObjs map[string]map[resource.Key]T // deleted objects per caller ID
}

func NewDiffStore[T k8sRuntime.Object](params diffStoreParams[T]) DiffStore[T] {
	if params.Resource == nil {
		return nil
	}

	ds := &diffStore[T]{
		resource: params.Resource,
		signaler: params.Signaler,

		callerUpdatedKeys: make(map[string]updatedKeysMap),
		callerDeletedObjs: make(map[string]map[resource.Key]T),
	}

	params.JobGroup.Add(
		job.OneShot("diffstore-events",
			func(ctx context.Context, health cell.Health) (err error) {
				ds.mu.Lock()
				ds.store, err = ds.resource.Store(ctx)
				ds.mu.Unlock()
				if err != nil {
					return fmt.Errorf("error creating resource store: %w", err)
				}
				for event := range ds.resource.Events(ctx) {
					ds.handleEvent(event)
				}
				return nil
			},
			job.WithRetry(3, &job.ExponentialBackoff{Min: 100 * time.Millisecond, Max: time.Second}),
			job.WithShutdown()),
	)

	return ds
}

func (ds *diffStore[T]) handleEvent(event resource.Event[T]) {
	update := func(k resource.Key) {
		ds.mu.Lock()
		for _, updatedKeys := range ds.callerUpdatedKeys {
			updatedKeys[k] = true
		}
		ds.mu.Unlock()

		if ds.initialSync {
			ds.signaler.Event(struct{}{})
		}
	}
	delete := func(k resource.Key, o T) {
		ds.mu.Lock()
		for _, deletedObjs := range ds.callerDeletedObjs {
			deletedObjs[k] = o
		}
		ds.mu.Unlock()

		if ds.initialSync {
			ds.signaler.Event(struct{}{})
		}
	}

	switch event.Kind {
	case resource.Sync:
		ds.initialSync = true
		ds.signaler.Event(struct{}{})
	case resource.Upsert:
		update(event.Key)
	case resource.Delete:
		delete(event.Key, event.Object)
	}

	event.Done(nil)
}

// InitDiff initializes tracking io items to Diff for the given callerID.
func (ds *diffStore[T]) InitDiff(callerID string) {
	ds.mu.Lock()
	defer ds.mu.Unlock()

	ds.callerUpdatedKeys[callerID] = make(updatedKeysMap)
	ds.callerDeletedObjs[callerID] = make(map[resource.Key]T)
}

// Diff returns a list of items that have been upserted (updated or inserted) and deleted
// since InitDiff or the last call to Diff with the same callerID.
// Init(callerID) has to be called before Diff(callerID).
func (ds *diffStore[T]) Diff(callerID string) (upserted []T, deleted []T, err error) {
	// Deleting keys doesn't shrink the memory size. So if the size of updateKeys ever reaches above this threshold
	// we should re-create it to reduce memory usage. Below the threshold, don't bother to avoid unnecessary allocation.
	// Note: this value is arbitrary, can be changed to tune CPU/Memory tradeoff
	const shrinkThreshold = 64

	ds.mu.Lock()
	defer ds.mu.Unlock()

	if ds.store == nil {
		return nil, nil, ErrStoreUninitialized
	}

	updatedKeys, ok := ds.callerUpdatedKeys[callerID]
	if !ok {
		return nil, nil, ErrDiffUninitialized
	}
	shrink := len(updatedKeys) > shrinkThreshold
	for k := range updatedKeys {
		item, found, err := ds.store.GetByKey(k)
		if err != nil {
			return nil, nil, err
		}

		if found {
			upserted = append(upserted, item)
		}
		if !shrink {
			delete(updatedKeys, k)
		}
	}
	if shrink {
		ds.callerUpdatedKeys[callerID] = make(updatedKeysMap, shrinkThreshold)
	}

	deletedObjs, ok := ds.callerDeletedObjs[callerID]
	if !ok {
		return nil, nil, ErrDiffUninitialized
	}
	shrink = len(deletedObjs) > shrinkThreshold
	for k, o := range deletedObjs {
		deleted = append(deleted, o)
		if !shrink {
			delete(deletedObjs, k)
		}
	}
	if shrink {
		ds.callerDeletedObjs[callerID] = make(map[resource.Key]T, shrinkThreshold)
	}

	return upserted, deleted, err
}

// CleanupDiff cleans up all caller-specific diff state.
func (ds *diffStore[T]) CleanupDiff(callerID string) {
	ds.mu.Lock()
	defer ds.mu.Unlock()

	delete(ds.callerUpdatedKeys, callerID)
	delete(ds.callerDeletedObjs, callerID)
}

// GetByKey returns the latest version of the object with given key.
func (ds *diffStore[T]) GetByKey(key resource.Key) (item T, exists bool, err error) {
	ds.mu.Lock()
	defer ds.mu.Unlock()

	if ds.store == nil {
		var empty T
		return empty, false, ErrStoreUninitialized
	}

	return ds.store.GetByKey(key)
}

// List returns all items currently in the store.
func (ds *diffStore[T]) List() (items []T, err error) {
	ds.mu.Lock()
	defer ds.mu.Unlock()

	if ds.store == nil {
		return nil, ErrStoreUninitialized
	}

	return ds.store.List(), nil
}
