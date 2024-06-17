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

var ErrStoreUninitialized = errors.New("the store has not initialized yet")

// DiffStore is a wrapper around the resource.Store. The diffStore tracks all changes made to it since the
// last time the user synced up. This allows a user to get a list of just the changed objects while still being able
// to query the full store for a full sync.
type DiffStore[T k8sRuntime.Object] interface {
	// Diff returns a list of items that have been upserted(updated or inserted) and deleted since the last call to Diff.
	Diff() (upserted []T, deleted []resource.Key, err error)

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

// diffStore takes a resource.Resource[T] and watches for events, it stores all of the keys that have been changed.
// diffStore can still be used as a normal store, but adds the Diff function to get a Diff of all changes.
// The diffStore also takes in Signaler which it will signal after the initial sync and every update thereafter.
type diffStore[T k8sRuntime.Object] struct {
	store resource.Store[T]

	resource resource.Resource[T]
	signaler *signaler.BGPCPSignaler

	initialSync bool

	mu          lock.Mutex
	updatedKeys map[resource.Key]bool
}

func NewDiffStore[T k8sRuntime.Object](params diffStoreParams[T]) DiffStore[T] {
	if params.Resource == nil {
		return nil
	}

	ds := &diffStore[T]{
		resource: params.Resource,
		signaler: params.Signaler,

		updatedKeys: make(map[resource.Key]bool),
	}

	params.JobGroup.Add(
		job.OneShot("diffstore-events",
			func(ctx context.Context, health cell.Health) (err error) {
				ds.store, err = ds.resource.Store(ctx)
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
		ds.updatedKeys[k] = true
		ds.mu.Unlock()

		// Start triggering the signaler after initialization to reduce reconciliation load.
		if ds.initialSync {
			ds.signaler.Event(struct{}{})
		}
	}

	switch event.Kind {
	case resource.Sync:
		ds.initialSync = true
		ds.signaler.Event(struct{}{})
	case resource.Upsert, resource.Delete:
		update(event.Key)
	}

	event.Done(nil)
}

// Diff returns a list of items that have been upserted(updated or inserted) and deleted since the last call to Diff.
func (ds *diffStore[T]) Diff() (upserted []T, deleted []resource.Key, err error) {
	ds.mu.Lock()
	defer ds.mu.Unlock()

	if ds.store == nil {
		return nil, nil, ErrStoreUninitialized
	}

	// Deleting keys doesn't shrink the memory size. So if the size of updateKeys ever reaches above this threshold
	// we should re-create it to reduce memory usage. Below the threshold, don't bother to avoid unnecessary allocation.
	// Note: this value is arbitrary, can be changed to tune CPU/Memory tradeoff
	const shrinkThreshold = 64
	shrink := len(ds.updatedKeys) > shrinkThreshold

	for k := range ds.updatedKeys {
		item, found, err := ds.store.GetByKey(k)
		if err != nil {
			return nil, nil, err
		}

		if found {
			upserted = append(upserted, item)
		} else {
			deleted = append(deleted, k)
		}

		if !shrink {
			delete(ds.updatedKeys, k)
		}
	}

	if shrink {
		ds.updatedKeys = make(map[resource.Key]bool, shrinkThreshold)
	}

	return upserted, deleted, err
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
