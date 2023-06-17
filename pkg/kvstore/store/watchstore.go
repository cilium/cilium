// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package store

import (
	"context"
	"strings"
	"sync/atomic"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/sirupsen/logrus"

	"github.com/cilium/cilium/pkg/kvstore"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/metrics"
)

// WatchStore abstracts the operations allowing to synchronize key/value pairs
// from a kvstore, emitting the corresponding events.
type WatchStore interface {
	// Watch starts watching the specified kvstore prefix, blocking until the context is closed.
	// Depending on the implementation, it might be executed multiple times.
	Watch(ctx context.Context, backend WatchStoreBackend, prefix string)

	// NumEntries returns the number of entries synchronized from the store.
	NumEntries() uint64

	// Drain emits a deletion event for each known key. It shall be called only
	// when no watch operation is in progress.
	Drain()
}

// WatchStoreBackend represents the subset of kvstore.BackendOperations leveraged
// by WatchStore implementations.
type WatchStoreBackend interface {
	// ListAndWatch creates a new watcher for the given prefix after listing the existing keys.
	ListAndWatch(ctx context.Context, name, prefix string, chanSize int) *kvstore.Watcher
}

type RWSOpt func(*restartableWatchStore)

// WSWithOnSyncCallback registers a function to be executed after
// listing all keys from the kvstore for the first time. Multiple
// callback functions can be registered.
func RWSWithOnSyncCallback(callback func(ctx context.Context)) RWSOpt {
	return func(rws *restartableWatchStore) {
		rws.onSyncCallbacks = append(rws.onSyncCallbacks, callback)
	}
}

// WSWithEntriesGauge registers a Prometheus gauge metric that is kept
// in sync with the number of entries synchronized from the kvstore.
func RWSWithEntriesMetric(gauge prometheus.Gauge) RWSOpt {
	return func(rws *restartableWatchStore) {
		rws.entriesMetric = gauge
	}
}

type rwsEntry struct {
	key   Key
	stale bool
}

// restartableWatchStore implements the WatchStore interface, supporting
// multiple executions of the Watch() operation (granted that the previous one
// already terminated). This allows to transparently handle the case in which
// we had to create a new etcd connection (for instance following a failure)
// which refers to the same remote cluster.
type restartableWatchStore struct {
	source     string
	keyCreator KeyCreator
	observer   Observer

	watching        atomic.Bool
	synced          bool
	onSyncCallbacks []func(ctx context.Context)

	// Using a separate entries counter avoids the need for synchronizing the
	// access to the state map, since the only concurrent reader is represented
	// by the NumEntries() function.
	state      map[string]*rwsEntry
	numEntries atomic.Uint64

	log           *logrus.Entry
	entriesMetric prometheus.Gauge
}

// NewRestartableWatchStore returns a WatchStore instance which supports
// restarting the watch operation multiple times, automatically handling
// the emission of deletion events for all stale entries (if enabled). It
// shall be restarted only once the previous Watch execution terminated.
func NewRestartableWatchStore(clusterName string, keyCreator KeyCreator, observer Observer, opts ...RWSOpt) WatchStore {
	rws := &restartableWatchStore{
		source:     clusterName,
		keyCreator: keyCreator,
		observer:   observer,

		state: make(map[string]*rwsEntry),

		log:           log,
		entriesMetric: metrics.NoOpGauge,
	}

	for _, opt := range opts {
		opt(rws)
	}

	rws.log = rws.log.WithField(logfields.ClusterName, rws.source)
	return rws
}

// Watch starts watching the specified kvstore prefix, blocking until the context is closed.
// It might be executed multiple times, granted that the previous execution already terminated.
func (rws *restartableWatchStore) Watch(ctx context.Context, backend WatchStoreBackend, prefix string) {
	// Append a trailing "/" to the prefix, to make sure that we watch only
	// sub-elements belonging to that prefix, and not to sibling prefixes
	// (for instance in case the last part of the prefix is the cluster name,
	// and one is the substring of another).
	if !strings.HasSuffix(prefix, "/") {
		prefix = prefix + "/"
	}

	rws.log = rws.log.WithField(logfields.Prefix, prefix)
	syncedMetric := metrics.KVStoreInitialSyncCompleted.WithLabelValues(
		kvstore.GetScopeFromKey(prefix), rws.source, "read")

	rws.log.Info("Starting restartable watch store")
	syncedMetric.Set(metrics.BoolToFloat64(false))

	if rws.watching.Swap(true) {
		rws.log.Panic("Cannot start the watch store while still running")
	}

	defer func() {
		rws.log.Info("Stopped restartable watch store")
		syncedMetric.Set(metrics.BoolToFloat64(false))
		rws.watching.Store(false)
	}()

	// Mark all known keys as stale.
	for _, entry := range rws.state {
		entry.stale = true
	}

	// The events channel is closed when the context is closed.
	watcher := backend.ListAndWatch(ctx, prefix, prefix, 0)
	for event := range watcher.Events {
		if event.Typ == kvstore.EventTypeListDone {
			rws.log.Debug("Initial synchronization completed")
			rws.drainKeys(true)
			syncedMetric.Set(metrics.BoolToFloat64(true))

			if !rws.synced {
				rws.synced = true
				for _, callback := range rws.onSyncCallbacks {
					callback(ctx)
				}
			}

			continue
		}

		key := strings.TrimPrefix(event.Key, prefix)
		rws.log.WithFields(logrus.Fields{
			logfields.Key:   key,
			logfields.Event: event.Typ,
		}).Debug("Received event from kvstore")

		switch event.Typ {
		case kvstore.EventTypeCreate, kvstore.EventTypeModify:
			rws.handleUpsert(key, event.Value)
		case kvstore.EventTypeDelete:
			rws.handleDelete(key)
		}
	}
}

// NumEntries returns the number of entries synchronized from the store.
func (rws *restartableWatchStore) NumEntries() uint64 {
	return rws.numEntries.Load()
}

// Drain emits a deletion event for each known key. It shall be called only
// when no watch operation is in progress.
func (rws *restartableWatchStore) Drain() {
	if rws.watching.Swap(true) {
		rws.log.Panic("Cannot drain the watch store while still running")
	}
	defer rws.watching.Store(false)

	rws.log.Info("Draining restartable watch store")
	rws.drainKeys(false)
	rws.log.Info("Drained restartable watch store")
}

// drainKeys emits synthetic deletion events:
// * staleOnly == true: for all keys marked as stale;
// * staleOnly == false: for all known keys;
func (rws *restartableWatchStore) drainKeys(staleOnly bool) {
	for key, entry := range rws.state {
		if !staleOnly || entry.stale {
			rws.log.WithField(logfields.Key, key).Debug("Emitting deletion event for stale key")
			rws.handleDelete(key)
		}
	}
}

func (rws *restartableWatchStore) handleUpsert(key string, value []byte) {
	entry := &rwsEntry{key: rws.keyCreator()}
	if err := entry.key.Unmarshal(key, value); err != nil {
		rws.log.WithFields(logrus.Fields{
			logfields.Key:   key,
			logfields.Value: string(value),
		}).WithError(err).Warning("Unable to unmarshal value")
		return
	}

	rws.state[key] = entry
	rws.numEntries.Store(uint64(len(rws.state)))
	rws.entriesMetric.Set(float64(len(rws.state)))
	rws.observer.OnUpdate(entry.key)
}

func (rws *restartableWatchStore) handleDelete(key string) {
	entry, ok := rws.state[key]
	if !ok {
		rws.log.WithField(logfields.Key, key).Warning("Received deletion event for unknown key")
		return
	}

	delete(rws.state, key)
	rws.numEntries.Store(uint64(len(rws.state)))
	rws.entriesMetric.Set(float64(len(rws.state)))
	rws.observer.OnDelete(entry.key)
}
