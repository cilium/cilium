// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package store

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/option"
)

// Configure a generous timeout to prevent flakes when running in a noisy CI environment.
var (
	tick    = 10 * time.Millisecond
	timeout = 5 * time.Second
)

type fakeBackend struct {
	t           *testing.T
	expectLease bool

	updated chan *KVPair
	deleted chan *KVPair

	errorsOnUpdate map[string]uint
	errorsOnDelete map[string]uint
}

func NewFakeBackend(t *testing.T, expectLease bool) *fakeBackend {
	return &fakeBackend{
		t:           t,
		expectLease: expectLease,

		updated: make(chan *KVPair),
		deleted: make(chan *KVPair),

		errorsOnUpdate: make(map[string]uint),
		errorsOnDelete: make(map[string]uint),
	}
}

func (fb *fakeBackend) Update(ctx context.Context, key string, value []byte, lease bool) error {
	if lease != fb.expectLease {
		key = "error"
		value = []byte(fmt.Sprintf("incorrect lease setting, expected(%v) - found(%v)", fb.expectLease, lease))
	}

	select {
	case fb.updated <- NewKVPair(key, string(value)):
	case <-ctx.Done():
		require.Failf(fb.t, "Context closed before writing to updated channel", "key: %s, value: %s", key, value)
	}

	if cnt := fb.errorsOnUpdate[key]; cnt > 0 {
		fb.errorsOnUpdate[key]--
		return errors.New("failing on purpose")
	}

	return nil
}

func (fb *fakeBackend) Delete(ctx context.Context, key string) error {
	select {
	case fb.deleted <- NewKVPair(key, ""):
	case <-ctx.Done():
		require.Failf(fb.t, "Context closed before writing to deleted channel", "key: %s", key)
	}

	if cnt := fb.errorsOnDelete[key]; cnt > 0 {
		fb.errorsOnDelete[key]--
		return errors.New("failing on purpose")
	}

	return nil
}

type fakeRateLimiter struct{ whenCalled, forgetCalled chan *KVPair }

func NewFakeRateLimiter() *fakeRateLimiter {
	return &fakeRateLimiter{whenCalled: make(chan *KVPair), forgetCalled: make(chan *KVPair)}
}

func (frl *fakeRateLimiter) When(item interface{}) time.Duration {
	frl.whenCalled <- NewKVPair(item.(string), "")
	return time.Duration(0)
}
func (frl *fakeRateLimiter) Forget(item interface{}) {
	frl.forgetCalled <- NewKVPair(item.(string), "")
}
func (frl *fakeRateLimiter) NumRequeues(item interface{}) int { return 0 }

func eventually(in <-chan *KVPair) *KVPair {
	select {
	case kv := <-in:
		return kv
	case <-time.After(timeout):
		return NewKVPair("error", "timed out waiting for KV")
	}
}

func TestWorkqueueSyncStore(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	backend := NewFakeBackend(t, true)
	store := NewWorkqueueSyncStore(backend, "/foo/bar")

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		store.Run(ctx)
	}()

	defer func() {
		cancel()
		wg.Wait()
	}()

	// Upserts should trigger the corresponding backend operation.
	store.UpsertKey(ctx, NewKVPair("key1", "value1"))
	store.UpsertKey(ctx, NewKVPair("key2", "value2"))
	require.Equal(t, NewKVPair("/foo/bar/key1", "value1"), eventually(backend.updated))
	require.Equal(t, NewKVPair("/foo/bar/key2", "value2"), eventually(backend.updated))

	// Unless the pair is already part of the known state.
	store.UpsertKey(ctx, NewKVPair("key1", "value1"))
	store.UpsertKey(ctx, NewKVPair("key3", "value3"))
	require.Equal(t, NewKVPair("/foo/bar/key3", "value3"), eventually(backend.updated))

	// Upserts for the same key should be coalescenced. In this case, it is guaranteed
	// to happen since the first upsert blocks until we read from the channel.
	store.UpsertKey(ctx, NewKVPair("key4", "value4"))
	store.UpsertKey(ctx, NewKVPair("key1", "valueA"))
	store.UpsertKey(ctx, NewKVPair("key1", "valueB"))
	require.Equal(t, NewKVPair("/foo/bar/key4", "value4"), eventually(backend.updated))
	require.Equal(t, NewKVPair("/foo/bar/key1", "valueB"), eventually(backend.updated))

	// Deletions should trigger the corresponding backend operation, only if known to exist.
	store.DeleteKey(ctx, NewKVPair("key5", ""))
	store.DeleteKey(ctx, NewKVPair("key4", ""))
	require.Equal(t, NewKVPair("/foo/bar/key4", ""), eventually(backend.deleted))

	// Both upserts and deletes should be retried in case an error is returned by the client
	backend.errorsOnUpdate["/foo/bar/key1"] = 1
	store.UpsertKey(ctx, NewKVPair("key1", "valueC"))
	require.Equal(t, NewKVPair("/foo/bar/key1", "valueC"), eventually(backend.updated))
	require.Equal(t, NewKVPair("/foo/bar/key1", "valueC"), eventually(backend.updated))

	backend.errorsOnDelete["/foo/bar/key2"] = 1
	store.DeleteKey(ctx, NewKVPair("key2", ""))
	require.Equal(t, NewKVPair("/foo/bar/key2", ""), eventually(backend.deleted))
	require.Equal(t, NewKVPair("/foo/bar/key2", ""), eventually(backend.deleted))
}

func TestWorkqueueSyncStoreWithoutLease(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	backend := NewFakeBackend(t, false)
	store := NewWorkqueueSyncStore(backend, "/foo/bar", WSSWithoutLease())

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		store.Run(ctx)
	}()

	defer func() {
		cancel()
		wg.Wait()
	}()

	// The fake backend checks whether the lease setting corresponds to the expected
	// value, and emits a KVPair with the error message in case it does not match
	store.UpsertKey(ctx, NewKVPair("key1", "value1"))
	require.Equal(t, NewKVPair("/foo/bar/key1", "value1"), eventually(backend.updated))
}

func TestWorkqueueSyncStoreWithRateLimiter(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	backend := NewFakeBackend(t, true)
	limiter := NewFakeRateLimiter()
	store := NewWorkqueueSyncStore(backend, "/foo/bar", WSSWithRateLimiter(limiter))

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		store.Run(ctx)
	}()

	defer func() {
		cancel()
		wg.Wait()
	}()

	backend.errorsOnUpdate["/foo/bar/key1"] = 1

	// Assert that the custom rate limiter has been correctly called
	store.UpsertKey(ctx, NewKVPair("key1", "value1"))
	require.Equal(t, NewKVPair("/foo/bar/key1", "value1"), eventually(backend.updated))
	require.Equal(t, NewKVPair("key1", ""), eventually(limiter.whenCalled))
	require.Equal(t, NewKVPair("/foo/bar/key1", "value1"), eventually(backend.updated))
	require.Equal(t, NewKVPair("key1", ""), eventually(limiter.forgetCalled))
}

func TestWorkqueueSyncStoreWithWorkers(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	backend := NewFakeBackend(t, true)
	store := NewWorkqueueSyncStore(backend, "/foo/bar", WSSWithWorkers(2))

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		store.Run(ctx)
	}()

	defer func() {
		cancel()
		wg.Wait()
	}()

	store.UpsertKey(ctx, NewKVPair("key1", "value1"))
	require.Equal(t, NewKVPair("/foo/bar/key1", "value1"), eventually(backend.updated))

	// Since the Update() and Delete() functions implemented by the fake backend
	// block until we read from the correposponding channel, reading in reversed
	// order the elements from the two channels requires at least two workers
	store.DeleteKey(ctx, NewKVPair("key1", "value1"))
	store.UpsertKey(ctx, NewKVPair("key2", "value2"))
	require.Equal(t, NewKVPair("/foo/bar/key2", "value2"), eventually(backend.updated))
	require.Equal(t, NewKVPair("/foo/bar/key1", ""), eventually(backend.deleted))
}

func TestWorkqueueSyncStoreSynced(t *testing.T) {
	runnable := func(body func(*testing.T, context.Context, *fakeBackend, SyncStore), opts ...WSSOpt) func(t *testing.T) {
		return func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			backend := NewFakeBackend(t, true)
			store := NewWorkqueueSyncStore(backend, "foo/bar", opts...)

			var wg sync.WaitGroup
			wg.Add(1)
			go func() {
				defer wg.Done()
				store.Run(ctx)
			}()

			defer func() {
				cancel()
				wg.Wait()
			}()

			body(t, ctx, backend, store)
		}
	}

	t.Run("standard", runnable(func(t *testing.T, ctx context.Context, backend *fakeBackend, store SyncStore) {
		callback := func(ctx context.Context) {
			backend.Update(ctx, "callback/executed", []byte{}, true)
		}

		store.UpsertKey(ctx, NewKVPair("key1", "value1"))
		store.UpsertKey(ctx, NewKVPair("key2", "value2"))
		store.Synced(ctx, callback, callback)
		store.UpsertKey(ctx, NewKVPair("key3", "value3"))

		require.Equal(t, NewKVPair("foo/bar/key1", "value1"), eventually(backend.updated))
		require.Equal(t, NewKVPair("foo/bar/key2", "value2"), eventually(backend.updated))
		require.Equal(t, "cilium/synced/qux/foo/bar", eventually(backend.updated).Key)
		require.Equal(t, NewKVPair("callback/executed", ""), eventually(backend.updated))
		require.Equal(t, NewKVPair("callback/executed", ""), eventually(backend.updated))
		require.Equal(t, NewKVPair("foo/bar/key3", "value3"), eventually(backend.updated))
	}, WSSWithSourceClusterName("qux")))

	t.Run("key-override", runnable(func(t *testing.T, ctx context.Context, backend *fakeBackend, store SyncStore) {
		store.UpsertKey(ctx, NewKVPair("key1", "value1"))
		store.UpsertKey(ctx, NewKVPair("key2", "value2"))
		store.Synced(ctx)
		store.UpsertKey(ctx, NewKVPair("key3", "value3"))

		require.Equal(t, NewKVPair("foo/bar/key1", "value1"), eventually(backend.updated))
		require.Equal(t, NewKVPair("foo/bar/key2", "value2"), eventually(backend.updated))
		require.Equal(t, "cilium/synced/qux/override", eventually(backend.updated).Key)
		require.Equal(t, NewKVPair("foo/bar/key3", "value3"), eventually(backend.updated))
	}, WSSWithSourceClusterName("qux"), WSSWithSyncedKeyOverride("override")))

	t.Run("key-upsertion-failure", runnable(func(t *testing.T, ctx context.Context, backend *fakeBackend, store SyncStore) {
		backend.errorsOnUpdate["foo/bar/key1"] = 1

		store.UpsertKey(ctx, NewKVPair("key1", "value1"))
		store.UpsertKey(ctx, NewKVPair("key2", "value2"))
		store.Synced(ctx)
		store.UpsertKey(ctx, NewKVPair("key3", "value3"))

		require.Equal(t, NewKVPair("foo/bar/key1", "value1"), eventually(backend.updated))
		require.Equal(t, NewKVPair("foo/bar/key2", "value2"), eventually(backend.updated))
		require.Equal(t, NewKVPair("foo/bar/key3", "value3"), eventually(backend.updated))
		require.Equal(t, NewKVPair("foo/bar/key1", "value1"), eventually(backend.updated))
		// The synced key shall be created only once key1 has been successfully upserted.
		require.Equal(t, "cilium/synced/qux/foo/bar", eventually(backend.updated).Key)
	}, WSSWithSourceClusterName("qux")))

	t.Run("synced-upsertion-failure", runnable(func(t *testing.T, ctx context.Context, backend *fakeBackend, store SyncStore) {
		backend.errorsOnUpdate["cilium/synced/qux/foo/bar"] = 1

		store.UpsertKey(ctx, NewKVPair("key1", "value1"))
		store.UpsertKey(ctx, NewKVPair("key2", "value2"))
		store.Synced(ctx)

		require.Equal(t, NewKVPair("foo/bar/key1", "value1"), eventually(backend.updated))
		require.Equal(t, NewKVPair("foo/bar/key2", "value2"), eventually(backend.updated))
		require.Equal(t, "cilium/synced/qux/foo/bar", eventually(backend.updated).Key)
		require.Equal(t, "cilium/synced/qux/foo/bar", eventually(backend.updated).Key)
	}, WSSWithSourceClusterName("qux")))

	// Assert that the synced key is created only after key1 has been successfully upserted also in case there are multiple workers
	t.Run("multiple-workers", runnable(func(t *testing.T, ctx context.Context, backend *fakeBackend, store SyncStore) {
		backend.errorsOnUpdate["foo/bar/key1"] = 2
		store.UpsertKey(ctx, NewKVPair("key1", "value1"))
		store.Synced(ctx)

		require.Equal(t, NewKVPair("foo/bar/key1", "value1"), eventually(backend.updated))
		require.Equal(t, NewKVPair("foo/bar/key1", "value1"), eventually(backend.updated))
		require.Equal(t, NewKVPair("foo/bar/key1", "value1"), eventually(backend.updated))
		require.Equal(t, "cilium/synced/qux/foo/bar", eventually(backend.updated).Key)
	}, WSSWithSourceClusterName("qux"), WSSWithWorkers(10)))
}

func TestWorkqueueSyncStoreMetrics(t *testing.T) {
	defer func(name string, queue, sync metrics.GaugeVec) {
		option.Config.ClusterName = name
		metrics.KVStoreSyncQueueSize = queue
		metrics.KVStoreInitialSyncCompleted = sync
	}(option.Config.ClusterName, metrics.KVStoreSyncQueueSize, metrics.KVStoreInitialSyncCompleted)

	option.Config.ClusterName = "foo"
	cfg, collectors := metrics.CreateConfiguration([]string{"cilium_kvstore_sync_queue_size", "cilium_kvstore_initial_sync_completed"})
	require.True(t, cfg.KVStoreSyncQueueSizeEnabled)
	require.True(t, cfg.KVStoreInitialSyncCompletedEnabled)
	require.Len(t, collectors, 2)

	ctx, cancel := context.WithCancel(context.Background())
	backend := NewFakeBackend(t, true)
	store := NewWorkqueueSyncStore(backend, "cilium/state/nodes/v1")

	// The queue size should be initially zero.
	require.Equal(t, float64(0), testutil.ToFloat64(metrics.KVStoreSyncQueueSize.WithLabelValues("nodes/v1", "foo")))

	// We are not reading from the store, hence the queue size should reflect the number of upsertions
	store.UpsertKey(ctx, NewKVPair("key1", "value1"))
	store.UpsertKey(ctx, NewKVPair("key2", "value2"))
	require.Equal(t, float64(2), testutil.ToFloat64(metrics.KVStoreSyncQueueSize.WithLabelValues("nodes/v1", "foo")))

	// Upserting a different key shall increse the metric
	store.UpsertKey(ctx, NewKVPair("key3", "value3"))
	require.Equal(t, float64(3), testutil.ToFloat64(metrics.KVStoreSyncQueueSize.WithLabelValues("nodes/v1", "foo")))

	// Upserting an already upserted key (although with a different value) shall not increase the metric
	store.UpsertKey(ctx, NewKVPair("key1", "valueA"))
	require.Equal(t, float64(3), testutil.ToFloat64(metrics.KVStoreSyncQueueSize.WithLabelValues("nodes/v1", "foo")))

	// Start the store
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		store.Run(ctx)
	}()

	defer func() {
		cancel()
		wg.Wait()

		// The store should no longer be synced, since it is stopped.
		require.Equal(t, metrics.BoolToFloat64(false),
			testutil.ToFloat64(metrics.KVStoreInitialSyncCompleted.WithLabelValues("nodes/v1", "foo", "write")))
	}()

	// The metric should reflect the updated queue size (one in this case, since one element has been processed, and
	// another is being processed --- stuck performing Update()). We need to assert this "eventually", because we have
	// no guarantee that the processing of the second element has already started.
	require.Equal(t, NewKVPair("cilium/state/nodes/v1/key1", "valueA"), eventually(backend.updated))
	require.Eventually(t, func() bool {
		return testutil.ToFloat64(metrics.KVStoreSyncQueueSize.WithLabelValues("nodes/v1", "foo")) == 1
	}, timeout, tick, "Incorrect metric value (expected: 1)")

	// Deleting one element, the queue size should grow by one (the worker is still stuck in the Update() call).
	store.DeleteKey(ctx, NewKVPair("key1", ""))
	require.Equal(t, float64(2), testutil.ToFloat64(metrics.KVStoreSyncQueueSize.WithLabelValues("nodes/v1", "foo")))

	backend.errorsOnUpdate["cilium/state/nodes/v1/key3"] = 1
	require.Equal(t, NewKVPair("cilium/state/nodes/v1/key2", "value2"), eventually(backend.updated))
	require.Equal(t, NewKVPair("cilium/state/nodes/v1/key3", "value3"), eventually(backend.updated))
	require.Equal(t, NewKVPair("cilium/state/nodes/v1/key1", ""), eventually(backend.deleted))
	require.Equal(t, NewKVPair("cilium/state/nodes/v1/key3", "value3"), eventually(backend.updated))

	store.Synced(ctx, func(ctx context.Context) {
		// When the callback is executed, the store should be synced
		require.Equal(t, metrics.BoolToFloat64(true),
			testutil.ToFloat64(metrics.KVStoreInitialSyncCompleted.WithLabelValues("nodes/v1", "foo", "write")))
	})

	// The store should not yet be synced, as the synced entry has not yet been written to the kvstore.
	require.Equal(t, metrics.BoolToFloat64(false),
		testutil.ToFloat64(metrics.KVStoreInitialSyncCompleted.WithLabelValues("nodes/v1", "foo", "write")))
	require.Equal(t, "cilium/synced/foo/cilium/state/nodes/v1", eventually(backend.updated).Key)

	// Once all elements have been processed, the metric should be zero.
	require.Equal(t, float64(0), testutil.ToFloat64(metrics.KVStoreSyncQueueSize.WithLabelValues("nodes/v1", "foo")))

	// The metric should reflect the specified cluster name if overwritten.
	storeWithClusterName := NewWorkqueueSyncStore(backend, "cilium/state/nodes/v1", WSSWithSourceClusterName("bar"))
	storeWithClusterName.UpsertKey(ctx, NewKVPair("key2", "value2"))
	require.Equal(t, float64(1), testutil.ToFloat64(metrics.KVStoreSyncQueueSize.WithLabelValues("nodes/v1", "bar")))
}
