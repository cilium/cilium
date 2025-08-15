// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package store

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"path"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/prometheus/client_golang/prometheus"
	"k8s.io/client-go/util/workqueue"

	"github.com/cilium/cilium/pkg/kvstore"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/time"
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

	// RegisterLeaseExpiredObserver registers a function which is executed when
	// the lease associated with a key having the given prefix is detected as expired.
	RegisterLeaseExpiredObserver(prefix string, fn func(key string))
}

// wqSyncStore implements the SyncStore interface leveraging a workqueue to
// coalescence update/delete requests and handle retries in case of errors.
type wqSyncStore struct {
	backend SyncStoreBackend
	prefix  string
	source  string

	workers   uint
	withLease bool

	limiter   workqueue.TypedRateLimiter[workqueueKey]
	workqueue workqueue.TypedRateLimitingInterface[workqueueKey]
	state     lock.Map[string, []byte] // map[NamedKey.GetKeyName()]Key.Marshal()

	synced          atomic.Bool                // Synced() has been triggered
	pendingSync     lock.Map[string, struct{}] // the set of keys still to sync
	syncedKey       string
	syncedCallbacks []func(context.Context)

	log          *slog.Logger
	queuedMetric prometheus.Gauge
	errorsMetric prometheus.Counter
	syncedMetric prometheus.Gauge
}

type workqueueKey struct {
	value      string
	syncCanary *struct{ skipCallbacks bool }
}

type WSSOpt func(*wqSyncStore)

// WSSWithRateLimiter sets the rate limiting algorithm to be used when requeueing failed events.
func WSSWithRateLimiter(limiter workqueue.TypedRateLimiter[workqueueKey]) WSSOpt {
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
func newWorkqueueSyncStore(logger *slog.Logger, clusterName string, backend SyncStoreBackend, prefix string, m *Metrics, opts ...WSSOpt) SyncStore {
	wss := &wqSyncStore{
		backend: backend,
		prefix:  prefix,
		source:  clusterName,

		workers:   1,
		withLease: true,
		limiter:   workqueue.DefaultTypedControllerRateLimiter[workqueueKey](),
		syncedKey: prefix,

		log: logger.With(logfields.Prefix, prefix),
	}

	for _, opt := range opts {
		opt(wss)
	}

	wss.log = wss.log.With(logfields.ClusterName, wss.source)
	wss.workqueue = workqueue.NewTypedRateLimitingQueue(wss.limiter)
	wss.queuedMetric = m.KVStoreSyncQueueSize.WithLabelValues(kvstore.GetScopeFromKey(prefix), wss.source)
	wss.errorsMetric = m.KVStoreSyncErrors.WithLabelValues(kvstore.GetScopeFromKey(prefix), wss.source)
	wss.syncedMetric = m.KVStoreInitialSyncCompleted.WithLabelValues(kvstore.GetScopeFromKey(prefix), wss.source, "write")
	return wss
}

// Run starts the SyncStore logic, blocking until the context is closed.
func (wss *wqSyncStore) Run(ctx context.Context) {
	var wg sync.WaitGroup

	wss.syncedMetric.Set(metrics.BoolToFloat64(false))
	defer wss.syncedMetric.Set(metrics.BoolToFloat64(false))

	wss.backend.RegisterLeaseExpiredObserver(wss.prefix, wss.handleExpiredLease)
	wss.backend.RegisterLeaseExpiredObserver(wss.getSyncedKey(), wss.handleExpiredLease)

	wss.log.Info("Starting workqueue-based sync store", logfields.Workers, wss.workers)
	wg.Add(int(wss.workers))
	for i := uint(0); i < wss.workers; i++ {
		go func() {
			defer wg.Done()
			for wss.processNextItem(ctx) {
			}
		}()
	}

	<-ctx.Done()

	wss.backend.RegisterLeaseExpiredObserver(wss.prefix, nil)
	wss.backend.RegisterLeaseExpiredObserver(wss.getSyncedKey(), nil)

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
		return fmt.Errorf("failed marshaling key %q: %w", key, err)
	}

	prevValue, loaded := wss.state.Swap(key, value)
	if loaded && bytes.Equal(prevValue, value) {
		wss.log.Debug("ignoring upsert request for already up-to-date key", logfields.Key, key)
	} else {
		if !wss.synced.Load() {
			wss.pendingSync.Store(key, struct{}{})
		}

		wss.workqueue.Add(workqueueKey{value: key})
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
		wss.workqueue.Add(workqueueKey{value: key})
		wss.queuedMetric.Set(float64(wss.workqueue.Len()))
	} else {
		wss.log.Debug("ignoring delete request for non-existing key", logfields.Key, key)
	}

	return nil
}

func (wss *wqSyncStore) Synced(_ context.Context, callbacks ...func(ctx context.Context)) error {
	if synced := wss.synced.Swap(true); !synced {
		wss.syncedCallbacks = callbacks
		wss.workqueue.Add(workqueueKey{syncCanary: &struct{ skipCallbacks bool }{}})
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
		wss.errorsMetric.Inc()
		wss.workqueue.AddRateLimited(key)
		return true
	}

	// Since no error occurred, forget this item so it does not get queued again
	// until another change happens.
	wss.workqueue.Forget(key)
	wss.pendingSync.Delete(key.value)
	return true
}

func (wss *wqSyncStore) handle(ctx context.Context, item workqueueKey) error {
	if item.syncCanary != nil {
		return wss.handleSync(ctx, item.syncCanary.skipCallbacks)
	}
	key := item.value

	if value, ok := wss.state.Load(key); ok {
		return wss.handleUpsert(ctx, key, value)
	}

	return wss.handleDelete(ctx, key)
}

func (wss *wqSyncStore) handleUpsert(ctx context.Context, key string, value []byte) error {
	err := wss.backend.Update(ctx, wss.keyPath(key), value, wss.withLease)
	if err != nil {
		wss.log.Warn("Failed upserting key in kvstore. Retrying...",
			logfields.Error, err,
			logfields.Key, key,
		)
		return err
	}

	wss.log.Debug("Upserted key in kvstore",
		logfields.Key, key,
	)
	return nil
}

func (wss *wqSyncStore) handleDelete(ctx context.Context, key string) error {
	if err := wss.backend.Delete(ctx, wss.keyPath(key)); err != nil {
		wss.log.Warn("Failed deleting key from kvstore. Retrying...",
			logfields.Error, err,
			logfields.Key, key,
		)
		return err
	}

	wss.log.Debug("Deleted key from kvstore",
		logfields.Key, key,
	)
	return nil
}

func (wss *wqSyncStore) handleSync(ctx context.Context, skipCallbacks bool) error {
	// This could be replaced by wss.toSync.Len() == 0 if it only existed...
	syncCompleted := true
	wss.pendingSync.Range(func(string, struct{}) bool {
		syncCompleted = false
		return false
	})

	if !syncCompleted {
		return fmt.Errorf("there are still keys to be synchronized")
	}

	key := wss.getSyncedKey()

	err := wss.backend.Update(ctx, key, []byte(time.Now().Format(time.RFC3339)), wss.withLease)
	if err != nil {
		wss.log.Warn("Failed upserting synced key in kvstore. Retrying...",
			logfields.Error, err,
			logfields.Key, key,
		)
		return err
	}

	wss.log.Info("Initial synchronization from the external source completed",
		logfields.Key, key,
	)
	wss.syncedMetric.Set(metrics.BoolToFloat64(true))

	// Execute any callback that might have been registered.
	if !skipCallbacks {
		for _, callback := range wss.syncedCallbacks {
			callback(ctx)
		}
	}

	return nil
}

// handleExpiredLease gets executed when the lease attached to a given key expired,
// and is responsible for enqueuing the given key to recreate it.
func (wss *wqSyncStore) handleExpiredLease(key string) {
	defer wss.queuedMetric.Set(float64(wss.workqueue.Len()))

	if key == wss.getSyncedKey() {
		// Re-enqueue the creation of the sync canary, but make sure that
		// the registered callbacks are not executed a second time.
		wss.workqueue.Add(workqueueKey{syncCanary: &struct{ skipCallbacks bool }{true}})
		return
	}

	key = strings.TrimPrefix(strings.TrimPrefix(key, wss.prefix), "/")
	_, ok := wss.state.Load(key)
	if ok {
		wss.log.Debug("enqueuing upsert request for key as the attached lease expired", logfields.Key, key)
		if !wss.synced.Load() {
			wss.pendingSync.Store(key, struct{}{})
		}

		wss.workqueue.Add(workqueueKey{value: key})
	}
}

// keyPath returns the absolute kvstore path of a key
func (wss *wqSyncStore) keyPath(key string) string {
	// WARNING - STABLE API: The composition of the absolute key path
	// cannot be changed without breaking up and downgrades.
	return path.Join(wss.prefix, key)
}

func (wss *wqSyncStore) getSyncedKey() string {
	return path.Join(kvstore.SyncedPrefix, wss.source, wss.syncedKey)
}
