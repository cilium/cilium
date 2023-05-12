// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package store

import (
	"context"
	"path"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/kvstore"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/option"
)

type fakeLWBackend struct {
	t      *testing.T
	prefix string
	events []kvstore.KeyValueEvent
}

func NewFakeLWBackend(t *testing.T, prefix string, events []kvstore.KeyValueEvent) *fakeLWBackend {
	return &fakeLWBackend{
		t:      t,
		prefix: prefix,
		events: events,
	}
}

func (fb *fakeLWBackend) ListAndWatch(ctx context.Context, _, prefix string, _ int) *kvstore.Watcher {
	ch := make(kvstore.EventChan)

	go func() {
		defer close(ch)
		require.Equal(fb.t, fb.prefix, prefix)

		for _, event := range fb.events {
			event.Key = path.Join(fb.prefix, event.Key)
			select {
			case ch <- event:
			case <-ctx.Done():
				require.Fail(fb.t, "Context closed before propagating all events", "pending: %#v", event)
			}
		}

		<-ctx.Done()
	}()

	return &kvstore.Watcher{Events: ch}
}

type fakeObserver struct {
	t       *testing.T
	updated chan *KVPair
	deleted chan *KVPair
}

func NewFakeObserver(t *testing.T) *fakeObserver {
	return &fakeObserver{
		t:       t,
		updated: make(chan *KVPair),
		deleted: make(chan *KVPair),
	}
}

func (fo *fakeObserver) OnUpdate(k Key) {
	select {
	case fo.updated <- k.(*KVPair):
	case <-time.After(timeout):
		require.Failf(fo.t, "Failed observing update event", "key: %s", k.GetKeyName())
	}
}
func (fo *fakeObserver) OnDelete(k NamedKey) {
	select {
	case fo.deleted <- k.(*KVPair):
	case <-time.After(timeout):
		require.Failf(fo.t, "Failed observing delete event", "key: %s", k.GetKeyName())
	}
}

func rwsRun(store WatchStore, prefix string, body func(), backend WatchStoreBackend) {
	ctx, cancel := context.WithCancel(context.Background())

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		store.Watch(ctx, backend, prefix)
	}()

	defer func() {
		cancel()
		wg.Wait()
	}()

	body()
}

func rwsDrain(t *testing.T, store WatchStore, observer *fakeObserver, expected []*KVPair) {
	drainDone := make(chan struct{})
	go func() {
		store.Drain()
		close(drainDone)
	}()

	var actual []*KVPair
	for range expected {
		actual = append(actual, eventually(observer.deleted))
	}

	// Since the drained elements are spilled out of a map, there's no ordering guarantee.
	require.ElementsMatch(t, expected, actual)

	select {
	case <-drainDone:
	case <-time.After(timeout):
		require.Fail(t, "The drain operation did not complete when expected")
	}
}

func TestRestartableWatchStore(t *testing.T) {
	observer := NewFakeObserver(t)
	store := NewRestartableWatchStore("qux", KVPairCreator, observer)
	require.Equal(t, uint64(0), store.NumEntries())

	// Watch the kvstore once, and assert that the expected events are propagated
	rwsRun(store, "foo/bar", func() {
		require.Equal(t, NewKVPair("key1", "value1A"), eventually(observer.updated))
		require.Equal(t, NewKVPair("key2", "value2A"), eventually(observer.updated))
		require.Equal(t, NewKVPair("key2", "value2B"), eventually(observer.updated))
		require.Equal(t, NewKVPair("key3", "value3A"), eventually(observer.updated))
		require.Equal(t, NewKVPair("key3", "value3A"), eventually(observer.deleted))
		require.Equal(t, uint64(2), store.NumEntries())
	}, NewFakeLWBackend(t, "foo/bar/", []kvstore.KeyValueEvent{
		{Typ: kvstore.EventTypeCreate, Key: "key1", Value: []byte("value1A")},
		{Typ: kvstore.EventTypeCreate, Key: "key2", Value: []byte("value2A")},
		{Typ: kvstore.EventTypeListDone},
		{Typ: kvstore.EventTypeModify, Key: "key2", Value: []byte("value2B")},
		{Typ: kvstore.EventTypeCreate, Key: "key3", Value: []byte("value3A")},
		{Typ: kvstore.EventTypeDelete, Key: "key4"}, // The key is not known locally -> no event
		{Typ: kvstore.EventTypeDelete, Key: "key3"},
	}))

	// Watch the kvstore a second time, and assert that the expected events (including
	// stale keys deletions) are propagated, even though the watcher prefix changed.
	rwsRun(store, "foo/baz", func() {
		require.Equal(t, NewKVPair("key1", "value1C"), eventually(observer.updated))
		require.Equal(t, NewKVPair("key4", "value4A"), eventually(observer.updated))
		require.Equal(t, NewKVPair("key2", "value2B"), eventually(observer.deleted))
		require.Equal(t, NewKVPair("key2", "value2C"), eventually(observer.updated))
		require.Equal(t, uint64(3), store.NumEntries())
	}, NewFakeLWBackend(t, "foo/baz/", []kvstore.KeyValueEvent{
		{Typ: kvstore.EventTypeCreate, Key: "key1", Value: []byte("value1C")},
		{Typ: kvstore.EventTypeCreate, Key: "key4", Value: []byte("value4A")},
		{Typ: kvstore.EventTypeListDone},
		{Typ: kvstore.EventTypeCreate, Key: "key2", Value: []byte("value2C")},
	}))
}

func TestRestartableWatchStoreDrain(t *testing.T) {
	observer := NewFakeObserver(t)
	store := NewRestartableWatchStore("qux", KVPairCreator, observer)

	// Watch a few keys through the watch store
	rwsRun(store, "foo/bar", func() {
		require.Equal(t, NewKVPair("key1", "value1A"), eventually(observer.updated))
		require.Equal(t, NewKVPair("key2", "value2A"), eventually(observer.updated))
		require.Equal(t, NewKVPair("key3", "value3A"), eventually(observer.updated))
		require.Equal(t, NewKVPair("key2", "value2A"), eventually(observer.deleted))
	}, NewFakeLWBackend(t, "foo/bar/", []kvstore.KeyValueEvent{
		{Typ: kvstore.EventTypeCreate, Key: "key1", Value: []byte("value1A")},
		{Typ: kvstore.EventTypeCreate, Key: "key2", Value: []byte("value2A")},
		{Typ: kvstore.EventTypeListDone},
		{Typ: kvstore.EventTypeModify, Key: "key3", Value: []byte("value3A")},
		{Typ: kvstore.EventTypeDelete, Key: "key2"},
	}))

	// Drain the store, and assert that a deletion event is emitted for all keys
	rwsDrain(t, store, observer, []*KVPair{
		NewKVPair("key1", "value1A"),
		NewKVPair("key3", "value3A"),
	})

	// Make sure that it is possible to restart the watch store
	rwsRun(store, "foo/bar", func() {
		require.Equal(t, NewKVPair("key1", "value1A"), eventually(observer.updated))
	}, NewFakeLWBackend(t, "foo/bar/", []kvstore.KeyValueEvent{
		{Typ: kvstore.EventTypeCreate, Key: "key1", Value: []byte("value1A")},
	}))

	// And to drain it again
	rwsDrain(t, store, observer, []*KVPair{
		NewKVPair("key1", "value1A"),
	})
}

func TestRestartableWatchStoreSyncCallback(t *testing.T) {
	observer := NewFakeObserver(t)
	callback := func(value string) func(context.Context) {
		return func(context.Context) {
			observer.OnUpdate(NewKVPair("callback/executed", value))
		}
	}

	store := NewRestartableWatchStore("qux", KVPairCreator, observer,
		RWSWithOnSyncCallback(callback("1")), RWSWithOnSyncCallback(callback("2")))

	// The watcher is closed before receiving the list done event, the sync callbacks should not be executed
	rwsRun(store, "foo/bar", func() {
		require.Equal(t, NewKVPair("key1", "value1A"), eventually(observer.updated))
	}, NewFakeLWBackend(t, "foo/bar/", []kvstore.KeyValueEvent{
		{Typ: kvstore.EventTypeCreate, Key: "key1", Value: []byte("value1A")},
	}))

	// Assert that the callback are executed when the list done event is received
	rwsRun(store, "foo/bar", func() {
		require.Equal(t, NewKVPair("key1", "value1A"), eventually(observer.updated))
		require.Equal(t, NewKVPair("callback/executed", "1"), eventually(observer.updated))
		require.Equal(t, NewKVPair("callback/executed", "2"), eventually(observer.updated))
		require.Equal(t, NewKVPair("key2", "value2A"), eventually(observer.updated))
	}, NewFakeLWBackend(t, "foo/bar/", []kvstore.KeyValueEvent{
		{Typ: kvstore.EventTypeCreate, Key: "key1", Value: []byte("value1A")},
		{Typ: kvstore.EventTypeListDone},
		{Typ: kvstore.EventTypeCreate, Key: "key2", Value: []byte("value2A")},
	}))

	// Assert that the callbacks are not executed a second time
	rwsRun(store, "foo/bar", func() {
		require.Equal(t, NewKVPair("key1", "value1A"), eventually(observer.updated))
		require.Equal(t, NewKVPair("key2", "value2A"), eventually(observer.deleted))
		require.Equal(t, NewKVPair("key3", "value3A"), eventually(observer.updated))
	}, NewFakeLWBackend(t, "foo/bar/", []kvstore.KeyValueEvent{
		{Typ: kvstore.EventTypeCreate, Key: "key1", Value: []byte("value1A")},
		{Typ: kvstore.EventTypeListDone},
		{Typ: kvstore.EventTypeCreate, Key: "key3", Value: []byte("value3A")},
	}))
}

func TestRestartableWatchStoreConcurrent(t *testing.T) {
	var wg sync.WaitGroup
	ctx, cancel := context.WithCancel(context.Background())

	defer func() {
		cancel()
		wg.Wait()
	}()

	backend := NewFakeLWBackend(t, "foo/bar/", []kvstore.KeyValueEvent{
		{Typ: kvstore.EventTypeCreate, Key: "key1", Value: []byte("value1")},
	})
	observer := NewFakeObserver(t)
	store := NewRestartableWatchStore("qux", KVPairCreator, observer)

	wg.Add(1)
	go func() {
		store.Watch(ctx, backend, "foo/bar/")
		wg.Done()
	}()

	// Ensure that the Watch operation running in the goroutine has started
	require.Equal(t, NewKVPair("key1", "value1"), eventually(observer.updated))

	require.Panics(t, func() { store.Watch(ctx, backend, "foo/bar/") }, "store.Watch should panic when already running")
	require.Panics(t, store.Drain, "store.Drain should panic when store.Watch is running")
}

func TestRestartableWatchStoreMetrics(t *testing.T) {
	defer func(name string, metric metrics.GaugeVec) {
		metrics.KVStoreInitialSyncCompleted = metric
	}(option.Config.ClusterName, metrics.KVStoreInitialSyncCompleted)

	cfg, collectors := metrics.CreateConfiguration([]string{"cilium_kvstore_initial_sync_completed"})
	require.True(t, cfg.KVStoreInitialSyncCompletedEnabled)
	require.Len(t, collectors, 1)

	entries := prometheus.NewGauge(prometheus.GaugeOpts{Name: "test_elements_metric"})
	synced := metrics.KVStoreInitialSyncCompleted.WithLabelValues("nodes/v1", "qux", "read")

	observer := NewFakeObserver(t)
	store := NewRestartableWatchStore("qux", KVPairCreator, observer, RWSWithEntriesMetric(entries))

	require.Equal(t, float64(0), testutil.ToFloat64(entries))
	require.Equal(t, metrics.BoolToFloat64(false), testutil.ToFloat64(synced))

	rwsRun(store, "cilium/state/nodes/v1", func() {
		require.Equal(t, NewKVPair("key1", "value1A"), eventually(observer.updated))
		require.Equal(t, metrics.BoolToFloat64(false), testutil.ToFloat64(synced))
		require.Equal(t, NewKVPair("key2", "value2A"), eventually(observer.updated))

		require.Eventually(t, func() bool {
			return metrics.BoolToFloat64(true) == testutil.ToFloat64(synced)
		}, timeout, tick)

		require.Equal(t, NewKVPair("key1", "value1A"), eventually(observer.deleted))
		require.Equal(t, NewKVPair("key2", "value2B"), eventually(observer.updated))
		require.Equal(t, NewKVPair("key3", "value3A"), eventually(observer.updated))
	}, NewFakeLWBackend(t, "cilium/state/nodes/v1/", []kvstore.KeyValueEvent{
		{Typ: kvstore.EventTypeCreate, Key: "key1", Value: []byte("value1A")},
		{Typ: kvstore.EventTypeCreate, Key: "key2", Value: []byte("value2A")},
		{Typ: kvstore.EventTypeListDone},
		{Typ: kvstore.EventTypeDelete, Key: "key1"},
		{Typ: kvstore.EventTypeCreate, Key: "key2", Value: []byte("value2B")},
		{Typ: kvstore.EventTypeCreate, Key: "key3", Value: []byte("value3A")},
	}))

	// The metric should reflect the number of elements.
	require.Equal(t, float64(2), testutil.ToFloat64(entries))
	require.Equal(t, metrics.BoolToFloat64(false), testutil.ToFloat64(synced))

	rwsRun(store, "cilium/state/nodes/v1", func() {
		require.Equal(t, NewKVPair("key3", "value3A"), eventually(observer.updated))
		require.Equal(t, metrics.BoolToFloat64(false), testutil.ToFloat64(synced))
		require.Equal(t, NewKVPair("key2", "value2B"), eventually(observer.deleted))

		require.Eventually(t, func() bool {
			return metrics.BoolToFloat64(true) == testutil.ToFloat64(synced)
		}, timeout, tick)

		require.Equal(t, NewKVPair("key1", "value1A"), eventually(observer.updated))
	}, NewFakeLWBackend(t, "cilium/state/nodes/v1/", []kvstore.KeyValueEvent{
		{Typ: kvstore.EventTypeCreate, Key: "key3", Value: []byte("value3A")},
		{Typ: kvstore.EventTypeListDone},
		{Typ: kvstore.EventTypeCreate, Key: "key1", Value: []byte("value1A")},
	}))
}
