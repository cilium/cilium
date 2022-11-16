// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package resource

import (
	"context"

	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/stream"

	k8sRuntime "k8s.io/apimachinery/pkg/runtime"
)

// DiffStoreFactory creates diffStores. All stores from the same factory share the same underlying store, but each
// diff store tracks the diff since the last time it was checked.
type DiffStoreFactory[T k8sRuntime.Object] interface {
	// NewStore creates a new store from this factory, all DiffStores share the same underlying store but each
	// records its own diff list.
	NewStore() DiffStore[T]

	// Observe returns a channel which will be signalled every time there is at least one pending change.
	// Multiple changes are coalesced. Calling `done` will drain and close the channel, it should be called when no
	// longer using `onDiff` to free resources.
	Observe() (onDiff <-chan struct{}, done func())
}

var _ DiffStoreFactory[*k8sRuntime.Unknown] = (*diffStoreFactory[*k8sRuntime.Unknown])(nil)

type diffStoreParams[T k8sRuntime.Object] struct {
	cell.In

	LS         hive.Lifecycle
	Shutdowner hive.Shutdowner
	Resource   Resource[T]
}

type diffStoreFactory[T k8sRuntime.Object] struct {
	params diffStoreParams[T]

	store Store[T]

	ctx      context.Context
	cancel   context.CancelFunc
	doneChan chan struct{}

	inSync bool

	mu         lock.Mutex
	onDiff     []chan struct{}
	diffStores []*diffStore[T]
}

// NewDiffStoreFactory
func NewDiffStoreFactory[T k8sRuntime.Object](params diffStoreParams[T]) DiffStoreFactory[T] {
	dsf := &diffStoreFactory[T]{
		params:   params,
		doneChan: make(chan struct{}),
	}

	dsf.ctx, dsf.cancel = context.WithCancel(context.Background())

	params.LS.Append(dsf)

	return dsf
}

// NewStore creates a new store from this factory, all DiffStores share the same underlying store but each
// records its own diff list.
func (dsf *diffStoreFactory[T]) NewStore() DiffStore[T] {
	dsf.mu.Lock()
	defer dsf.mu.Unlock()

	store := &diffStore[T]{
		factory:     dsf,
		store:       dsf.store,
		changedKeys: make(map[Key]bool),
	}
	dsf.diffStores = append(dsf.diffStores, store)
	return store
}

// Observe returns a channel which will be signalled every time there is at least one pending change.
// Multiple changes are coalesced. Calling `done` will drain and close the channel, it should be called when no
// longer using `onDiff` to free resources.
func (dsf *diffStoreFactory[T]) Observe() (onDiff <-chan struct{}, done func()) {
	newOnDiff := make(chan struct{}, 1)
	dsf.onDiff = append(dsf.onDiff, newOnDiff)
	done = func() {
		// Close
		close(newOnDiff)
		// And drain
		select {
		case <-newOnDiff:
		default:
		}
	}
	return newOnDiff, done
}

// Start implements hive.Hook
func (dsf *diffStoreFactory[T]) Start(_ hive.HookContext) error {
	go dsf.run()
	return nil
}

// Stop implements hive.Hook
func (dsf *diffStoreFactory[T]) Stop(stopCtx hive.HookContext) error {
	dsf.cancel()

	select {
	case <-dsf.doneChan:
	case <-stopCtx.Done():
	}

	return nil
}

func (dsf *diffStoreFactory[T]) run() {
	defer close(dsf.doneChan)

	var err error
	dsf.store, err = dsf.params.Resource.Store(dsf.ctx)
	if err != nil {
		dsf.params.Shutdowner.Shutdown(hive.ShutdownWithError(err))
		return
	}

	dsf.mu.Lock()
	for _, store := range dsf.diffStores {
		store.store = dsf.store
	}
	dsf.mu.Unlock()

	errChan := make(chan error, 2)
	updateChan := stream.ToChannel[Event[T]](dsf.ctx, errChan, dsf.params.Resource)

	for {
		select {
		case event, ok := <-updateChan:
			if !ok {
				break
			}

			event.Handle(
				func() error {
					dsf.inSync = true
					dsf.signalObservers()
					return nil
				},
				dsf.handleChange,
				dsf.handleChange,
			)
		case err := <-errChan:
			dsf.params.Shutdowner.Shutdown(hive.ShutdownWithError(err))
			return
		}
	}
}

func (dsf *diffStoreFactory[T]) handleChange(k Key, _ T) error {
	dsf.mu.Lock()
	defer dsf.mu.Unlock()

	for _, store := range dsf.diffStores {
		store.markChanged(k)
	}

	if dsf.inSync {
		dsf.signalObservers()
	}

	return nil
}

func (dsf *diffStoreFactory[T]) signalObservers() {
	for _, onDiff := range dsf.onDiff {
		select {
		case onDiff <- struct{}{}:
		default:
		}
	}
}

// DiffStore is a super set of the Store. The diffStore tracks all changes made to the diff store since the
// last time the user synced up. This allows a user to get a list of just the changed objects while still being able
// to query the full store for a full sync.
type DiffStore[T k8sRuntime.Object] interface {
	Store[T]

	// Diff returns a list of items that have been upserted(updated or inserted) and deleted since the last call to Diff.
	Diff() (upserted []T, deleted []Key, err error)
	// MarkChanged marks a key as having been changed so it will appear in the Diff again. This can be used in case
	// of a failure to process so a next call to Diff gets the chance to process the key again.
	MarkChanged(Key)
}

var _ DiffStore[*k8sRuntime.Unknown] = (*diffStore[*k8sRuntime.Unknown])(nil)

// diffStore takes a Resource[T] and watches for events, it stores all of the keys that have been changed.
// diffStore can still be used as a normal store, but adds the Diff function to get a Diff of all changes.
// The diffStore also takes in Signaler which it will signal after the initial sync and every update thereafter.
type diffStore[T k8sRuntime.Object] struct {
	store Store[T]

	factory *diffStoreFactory[T]

	mu          lock.Mutex
	changedKeys map[Key]bool
}

// Diff returns a list of items that have been upserted(updated or inserted) and deleted since the last call to Diff.
func (sd *diffStore[T]) Diff() (upserted []T, deleted []Key, err error) {
	sd.mu.Lock()
	defer sd.mu.Unlock()

	for k := range sd.changedKeys {
		item, found, err := sd.store.GetByKey(k)
		if err != nil {
			return nil, nil, err
		}

		if found {
			upserted = append(upserted, item)
		} else {
			deleted = append(deleted, k)
		}
	}

	sd.changedKeys = make(map[Key]bool, 0)

	return upserted, deleted, err
}

// MarkChanged marks a key as having been changed so it will appear in the Diff again. This can be used in case
// of a failure to process so a next call to Diff gets the chance to process the key again.
func (sd *diffStore[T]) MarkChanged(key Key) {
	sd.markChanged(key)

	// Signal all observers to re-trigger an observer activated Diff.
	sd.factory.signalObservers()
}

func (sd *diffStore[T]) markChanged(key Key) {
	sd.mu.Lock()
	defer sd.mu.Unlock()
	sd.changedKeys[key] = true
}

// List returns all items currently in the store.
func (sd *diffStore[T]) List() []T {
	return sd.store.List()
}

// IterKeys returns a key iterator.
func (sd *diffStore[T]) IterKeys() KeyIter {
	return sd.store.IterKeys()
}

// Get returns the latest version by deriving the key from the given object.
func (sd *diffStore[T]) Get(obj T) (item T, exists bool, err error) {
	return sd.store.Get(obj)
}

// GetByKey returns the latest version of the object with given key.
func (sd *diffStore[T]) GetByKey(key Key) (item T, exists bool, err error) {
	return sd.store.GetByKey(key)
}
