// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package manager

import (
	"context"
	"fmt"

	"github.com/cilium/cilium/pkg/bgpv1/agent"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/cilium/cilium/pkg/k8s/resource"
	"github.com/cilium/cilium/pkg/lock"

	k8sRuntime "k8s.io/apimachinery/pkg/runtime"
)

// DiffStore is a super set of the resource.Store. The diffStore tracks all changes made to it since the
// last time the user synced up. This allows a user to get a list of just the changed objects while still being able
// to query the full store for a full sync.
type DiffStore[T k8sRuntime.Object] interface {
	resource.Store[T]

	// Diff returns a list of items that have been upserted(updated or inserted) and deleted since the last call to Diff.
	Diff() (upserted []T, deleted []resource.Key, err error)
}

var _ DiffStore[*k8sRuntime.Unknown] = (*diffStore[*k8sRuntime.Unknown])(nil)

type diffStoreParams[T k8sRuntime.Object] struct {
	cell.In

	Lifecycle hive.Lifecycle
	Resource  resource.Resource[T]
	Signaler  agent.Signaler
}

// diffStore takes a resource.Resource[T] and watches for events, it stores all of the keys that have been changed.
// diffStore can still be used as a normal store, but adds the Diff function to get a Diff of all changes.
// The diffStore also takes in Signaler which it will signal after the initial sync and every update thereafter.
type diffStore[T k8sRuntime.Object] struct {
	resource.Store[T]

	resource resource.Resource[T]
	signaler agent.Signaler

	ctx      context.Context
	cancel   context.CancelFunc
	doneChan chan struct{}

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
		doneChan:    make(chan struct{}),
	}
	ds.ctx, ds.cancel = context.WithCancel(context.Background())

	params.Lifecycle.Append(ds)

	return ds
}

// Start implements hive.HookInterface
func (ds *diffStore[T]) Start(ctx hive.HookContext) error {
	var err error
	ds.Store, err = ds.resource.Store(ctx)
	if err != nil {
		return fmt.Errorf("resource.Store(): %w", err)
	}

	go ds.run()
	return nil
}

// Stop implements hive.HookInterface
func (ds *diffStore[T]) Stop(stopCtx hive.HookContext) error {
	ds.cancel()

	select {
	case <-ds.doneChan:
	case <-stopCtx.Done():
		return stopCtx.Err()
	}

	return nil
}

func (ds *diffStore[T]) run() {
	defer close(ds.doneChan)

	for event := range ds.resource.Events(ds.ctx) {
		ds.handleEvent(event)
	}
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
func (sd *diffStore[T]) Diff() (upserted []T, deleted []resource.Key, err error) {
	sd.mu.Lock()
	defer sd.mu.Unlock()

	// Deleting keys doesn't shrink the memory size. So if the size of updateKeys ever reaches above this threshold
	// we should re-create it to reduce memory usage. Below the threshold, don't bother to avoid unnecessary allocation.
	// Note: this value is arbitrary, can be changed to tune CPU/Memory tradeoff
	const shrinkThreshold = 64
	shrink := len(sd.updatedKeys) > shrinkThreshold

	for k := range sd.updatedKeys {
		item, found, err := sd.GetByKey(k)
		if err != nil {
			return nil, nil, err
		}

		if found {
			upserted = append(upserted, item)
		} else {
			deleted = append(deleted, k)
		}

		if !shrink {
			delete(sd.updatedKeys, k)
		}
	}

	if shrink {
		sd.updatedKeys = make(map[resource.Key]bool, shrinkThreshold)
	}

	return upserted, deleted, err
}
