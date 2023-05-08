// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package store

import (
	"bytes"
	"context"
	"fmt"
	"path"
	"sync"

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

	log          *logrus.Entry
	queuedMetric prometheus.Gauge
}

type WSSOpt func(*wqSyncStore)

// WSSWithSourceClusterName configures the name of the source cluster the information
// is synchronized from, which is used to enrich the metrics.
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

		log: log.WithField("prefix", prefix),
	}

	for _, opt := range opts {
		opt(wss)
	}

	wss.workqueue = workqueue.NewRateLimitingQueue(wss.limiter)
	wss.queuedMetric = metrics.KVStoreSyncQueueSize.WithLabelValues(kvstore.GetScopeFromKey(prefix), wss.source)
	return wss
}

// Run starts the SyncStore logic, blocking until the context is closed.
func (wss *wqSyncStore) Run(ctx context.Context) {
	var wg sync.WaitGroup

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
	if err := wss.handle(ctx, key.(string)); err != nil {
		// Put the item back on the workqueue to handle any transient errors.
		wss.workqueue.AddRateLimited(key)
		return true
	}

	// Since no error occurred, forget this item so it does not get queued again
	// until another change happens.
	wss.workqueue.Forget(key)
	return true
}

func (wss *wqSyncStore) handle(ctx context.Context, key string) error {
	if value, ok := wss.state.Load(key); ok {
		return wss.handleUpsert(ctx, key, value.([]byte))
	}

	return wss.handleDelete(ctx, key)
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

// keyPath returns the absolute kvstore path of a key
func (wss *wqSyncStore) keyPath(key string) string {
	// WARNING - STABLE API: The composition of the absolute key path
	// cannot be changed without breaking up and downgrades.
	return path.Join(wss.prefix, key)
}
