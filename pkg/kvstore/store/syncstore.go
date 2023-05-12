// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package store

import (
	"bytes"
	"context"
	"fmt"
	"path"
	"sync"
	"sync/atomic"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/sirupsen/logrus"
	"k8s.io/client-go/util/workqueue"

	"github.com/cilium/cilium/pkg/kvstore"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/option"
)

// SyncStore abstracts the operations allowing to synchronize key/value pairs
// into a kvstore.
type SyncStore interface {
	// Run starts the SyncStore logic, blocking until the context is closed.
	Run(ctx context.Context)

	// UpsertKey upserts a key/value pair into the kvstore.
	UpsertKey(ctx context.Context, key Key) error

	// DeleteKey removes a key from the kvstore.
	DeleteKey(ctx context.Context, key NamedKey) error

	// Synced triggers the insertion of the "synced" key associated with this
	// store into the kvstore once all upsertions already issued have completed
	// successfully, eventually executing all specified callbacks (if any).
	// Only the first invocation takes effect.
	Synced(ctx context.Context, callbacks ...func(ctx context.Context)) error
}

// SyncStoreBackend represents the subset kvstore.BackendOperations leveraged
// by SyncStore implementations.
type SyncStoreBackend interface {
	// Update creates or updates a key.
	Update(ctx context.Context, key string, value []byte, lease bool) error
	// Delete deletes a key.
	Delete(ctx context.Context, key string) error
}

// wqSyncStore implements the SyncStore interface leveraging a workqueue to
// coalescence update/delete requests and handle retries in case of errors.
type wqSyncStore struct {
	backend SyncStoreBackend
	prefix  string
	source  string

	workers   uint
	withLease bool

	limiter   workqueue.RateLimiter
	workqueue workqueue.RateLimitingInterface
	state     sync.Map /* map[string][]byte --- map[NamedKey.GetKeyName()]Key.Marshal() */

	synced          atomic.Bool // Synced() has been triggered
	pendingSync     sync.Map    // map[string]struct{}: the set of keys still to sync
	syncedKey       string
	syncedCallbacks []func(context.Context)

	log          *logrus.Entry
	queuedMetric prometheus.Gauge
	syncedMetric prometheus.Gauge
}

type syncCanary struct{}

type WSSOpt func(*wqSyncStore)

// WSSWithSourceClusterName configures the name of the source cluster the information
// is synchronized from, which is used to scope the "synced" prefix and enrich the metrics.
func WSSWithSourceClusterName(cluster string) WSSOpt {
	return func(wss *wqSyncStore) {
		wss.source = cluster
	}
}

// WSSWithRateLimiter sets the rate limiting algorithm to be used when requeueing failed events.
func WSSWithRateLimiter(limiter workqueue.RateLimiter) WSSOpt {
	return func(wss *wqSyncStore) {
		wss.limiter = limiter
	}
}

// WSSWithWorkers configures the number of workers spawned by Run() to handle update/delete operations.
func WSSWithWorkers(workers uint) WSSOpt {
	return func(wss *wqSyncStore) {
		wss.workers = workers
	}
}

// WSSWithoutLease disables attaching the lease to upserted keys.
func WSSWithoutLease() WSSOpt {
	return func(wss *wqSyncStore) {
		wss.withLease = false
	}
}

// WSSWithSyncedKeyOverride overrides the "synced" key inserted into the kvstore
// when initial synchronization completed (by default it corresponds to the prefix).
func WSSWithSyncedKeyOverride(key string) WSSOpt {
	return func(wss *wqSyncStore) {
		wss.syncedKey = key
	}
}

// NewWorkqueueSyncStore returns a SyncStore instance which leverages a workqueue
// to coalescence update/delete requests and handle retries in case of errors.
func NewWorkqueueSyncStore(backend SyncStoreBackend, prefix string, opts ...WSSOpt) SyncStore {
	wss := &wqSyncStore{
		backend: backend,
		prefix:  prefix,
		source:  option.Config.ClusterName,

		workers:   1,
		withLease: true,
		limiter:   workqueue.DefaultControllerRateLimiter(),
		syncedKey: prefix,

		log: log.WithField(logfields.Prefix, prefix),
	}

	for _, opt := range opts {
		opt(wss)
	}

	wss.log = wss.log.WithField(logfields.ClusterName, wss.source)
	wss.workqueue = workqueue.NewRateLimitingQueue(wss.limiter)
	wss.queuedMetric = metrics.KVStoreSyncQueueSize.WithLabelValues(kvstore.GetScopeFromKey(prefix), wss.source)
	wss.syncedMetric = metrics.KVStoreInitialSyncCompleted.WithLabelValues(kvstore.GetScopeFromKey(prefix), wss.source, "write")
	return wss
}

// Run starts the SyncStore logic, blocking until the context is closed.
func (wss *wqSyncStore) Run(ctx context.Context) {
	var wg sync.WaitGroup

	wss.syncedMetric.Set(metrics.BoolToFloat64(false))
	defer wss.syncedMetric.Set(metrics.BoolToFloat64(false))

	wss.log.WithField(logfields.Workers, wss.workers).Info("Starting workqueue-based sync store")
	wg.Add(int(wss.workers))
	for i := uint(0); i < wss.workers; i++ {
		go func() {
			defer wg.Done()
			for wss.processNextItem(ctx) {
			}
		}()
	}

	<-ctx.Done()

	wss.log.Info("Shutting down workqueue-based sync store")
	wss.workqueue.ShutDown()
	wg.Wait()
}

// UpsertKey registers the key for asynchronous upsertion in the kvstore, if the
// corresponding value has changed. It returns an error in case it is impossible
// to marshal the value, while kvstore failures are automatically handled through
// a retry mechanism.
func (wss *wqSyncStore) UpsertKey(_ context.Context, k Key) error {
	key := k.GetKeyName()
	value, err := k.Marshal()
	if err != nil {
		return fmt.Errorf("failed marshaling key %q: %w", k, err)
	}

	prevValue, loaded := wss.state.Swap(key, value)
	if loaded && bytes.Equal(prevValue.([]byte), value) {
		wss.log.WithField(logfields.Key, k).Debug("ignoring upsert request for already up-to-date key")
	} else {
		if !wss.synced.Load() {
			wss.pendingSync.Store(key, struct{}{})
		}

		wss.workqueue.Add(key)
		wss.queuedMetric.Set(float64(wss.workqueue.Len()))
	}

	return nil
}

// DeleteKey registers the key for asynchronous deletion from the kvstore, if it
// was known to be present. It never returns an error, because kvstore failures
// are automatically handled through a retry mechanism.
func (wss *wqSyncStore) DeleteKey(_ context.Context, k NamedKey) error {
	key := k.GetKeyName()
	if _, loaded := wss.state.LoadAndDelete(key); loaded {
		wss.workqueue.Add(key)
		wss.queuedMetric.Set(float64(wss.workqueue.Len()))
	} else {
		wss.log.WithField(logfields.Key, key).Debug("ignoring delete request for non-existing key")
	}

	return nil
}

func (wss *wqSyncStore) Synced(_ context.Context, callbacks ...func(ctx context.Context)) error {
	if synced := wss.synced.Swap(true); !synced {
		wss.syncedCallbacks = callbacks
		wss.workqueue.Add(syncCanary{})
	}
	return nil
}

func (wss *wqSyncStore) processNextItem(ctx context.Context) bool {
	// Retrieve the next key to process from the workqueue.
	key, shutdown := wss.workqueue.Get()
	wss.queuedMetric.Set(float64(wss.workqueue.Len()))
	if shutdown {
		return false
	}

	// We call Done here so the workqueue knows we have finished
	// processing this item.
	defer func() {
		wss.workqueue.Done(key)
		// This ensures that the metric is correctly updated in case of requeues.
		wss.queuedMetric.Set(float64(wss.workqueue.Len()))
	}()

	// Run the handler, passing it the key to be processed as parameter.
	if err := wss.handle(ctx, key); err != nil {
		// Put the item back on the workqueue to handle any transient errors.
		wss.workqueue.AddRateLimited(key)
		return true
	}

	// Since no error occurred, forget this item so it does not get queued again
	// until another change happens.
	wss.workqueue.Forget(key)
	wss.pendingSync.Delete(key)
	return true
}

func (wss *wqSyncStore) handle(ctx context.Context, key interface{}) error {
	if _, ok := key.(syncCanary); ok {
		return wss.handleSync(ctx)
	}

	if value, ok := wss.state.Load(key); ok {
		return wss.handleUpsert(ctx, key.(string), value.([]byte))
	}

	return wss.handleDelete(ctx, key.(string))
}

func (wss *wqSyncStore) handleUpsert(ctx context.Context, key string, value []byte) error {
	scopedLog := wss.log.WithField(logfields.Key, key)

	err := wss.backend.Update(ctx, wss.keyPath(key), value, wss.withLease)
	if err != nil {
		scopedLog.WithError(err).Warning("Failed upserting key in kvstore. Retrying...")
		return err
	}

	scopedLog.Debug("Upserted key in kvstore")
	return nil
}

func (wss *wqSyncStore) handleDelete(ctx context.Context, key string) error {
	scopedLog := wss.log.WithField(logfields.Key, key)

	if err := wss.backend.Delete(ctx, wss.keyPath(key)); err != nil {
		scopedLog.WithError(err).Warning("Failed deleting key from kvstore. Retrying...")
		return err
	}

	scopedLog.Debug("Deleted key from kvstore")
	return nil
}

func (wss *wqSyncStore) handleSync(ctx context.Context) error {
	// This could be replaced by wss.toSync.Len() == 0 if it only existed...
	syncCompleted := true
	wss.pendingSync.Range(func(any, any) bool {
		syncCompleted = false
		return false
	})

	if !syncCompleted {
		return fmt.Errorf("there are still keys to be synchronized")
	}

	key := path.Join(kvstore.SyncedPrefix, wss.source, wss.syncedKey)
	scopedLog := wss.log.WithField(logfields.Key, key)

	err := wss.backend.Update(ctx, key, []byte(time.Now().Format(time.RFC3339)), wss.withLease)
	if err != nil {
		scopedLog.WithError(err).Warning("Failed upserting synced key in kvstore. Retrying...")
		return err
	}

	wss.log.Info("Initial synchronization from the external source completed")
	wss.syncedMetric.Set(metrics.BoolToFloat64(true))

	// Execute any callback that might have been registered.
	for _, callback := range wss.syncedCallbacks {
		callback(ctx)
	}

	return nil
}

// keyPath returns the absolute kvstore path of a key
func (wss *wqSyncStore) keyPath(key string) string {
	// WARNING - STABLE API: The composition of the absolute key path
	// cannot be changed without breaking up and downgrades.
	return path.Join(wss.prefix, key)
}
