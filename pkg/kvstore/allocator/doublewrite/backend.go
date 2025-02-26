// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium
package doublewrite

import (
	"context"
	"log/slog"
	"strings"

	"github.com/cilium/cilium/pkg/allocator"
	"github.com/cilium/cilium/pkg/idpool"
	"github.com/cilium/cilium/pkg/k8s/identitybackend"
	"github.com/cilium/cilium/pkg/kvstore"
	kvstoreallocator "github.com/cilium/cilium/pkg/kvstore/allocator"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/rate"
)

var (
	log = logging.DefaultLogger.With(slog.String(logfields.LogSubsys, "double-write-allocator"))
)

// NewDoubleWriteBackend creates a backend which writes identities to both the CRD and KVStore backends.
// It should be used for migration purposes only.
func NewDoubleWriteBackend(c DoubleWriteBackendConfiguration) (allocator.Backend, error) {
	crdBackend, err := identitybackend.NewCRDBackend(c.CRDBackendConfiguration)
	if err != nil {
		return nil, err
	}
	kvstoreBackend, err := kvstoreallocator.NewKVStoreBackend(c.KVStoreBackendConfiguration)
	if err != nil {
		return nil, err
	}

	log.Debug(
		"Creating the Double-Write backend",
		slog.String("KVStoreBackendConfiguration.Suffix", c.KVStoreBackendConfiguration.Suffix),
		slog.Any("KVStoreBackendConfiguration.Typ", c.KVStoreBackendConfiguration.Typ),
		slog.String("KVStoreBackendConfiguration.BasePath", c.KVStoreBackendConfiguration.BasePath),
		slog.Bool("readFromKVStore", c.ReadFromKVStore),
	)

	return &doubleWriteBackend{crdBackend: crdBackend, kvstoreBackend: kvstoreBackend, readFromKVStore: c.ReadFromKVStore}, nil
}

type DoubleWriteBackendConfiguration struct {
	CRDBackendConfiguration     identitybackend.CRDBackendConfiguration
	KVStoreBackendConfiguration kvstoreallocator.KVStoreBackendConfiguration
	ReadFromKVStore             bool
}

type doubleWriteBackend struct {
	crdBackend      allocator.Backend
	kvstoreBackend  allocator.Backend
	readFromKVStore bool
}

func (d *doubleWriteBackend) DeleteAllKeys(ctx context.Context) {
	d.crdBackend.DeleteAllKeys(ctx)
	d.kvstoreBackend.DeleteAllKeys(ctx)
}

func (d *doubleWriteBackend) DeleteID(ctx context.Context, id idpool.ID) error {
	crdErr := d.crdBackend.DeleteID(ctx, id)
	if crdErr != nil {
		log.Error("CRD backend failed to delete identity", slog.Any(logfields.Error, crdErr), slog.Any(logfields.Identity, id))
	}
	kvStoreErr := d.kvstoreBackend.DeleteID(ctx, id)
	if kvStoreErr != nil {
		log.Error("KVStore backend failed to delete identity", slog.Any(logfields.Error, kvStoreErr), slog.Any(logfields.Identity, id))
	}

	if d.readFromKVStore {
		return kvStoreErr
	}
	return crdErr
}

func (d *doubleWriteBackend) AllocateID(ctx context.Context, id idpool.ID, key allocator.AllocatorKey) (allocator.AllocatorKey, error) {
	crdKey, crdErr := d.crdBackend.AllocateID(ctx, id, key)
	if crdErr != nil {
		log.Error("CRD backend failed to allocate identity", slog.Any(logfields.Error, crdErr), slog.Any(logfields.Identity, id), slog.Any(logfields.Key, key))
		return crdKey, crdErr
	}
	kvStoreKey, kvStoreErr := d.kvstoreBackend.AllocateID(ctx, id, key)
	if kvStoreErr != nil {
		log.Error("KVStore backend failed to allocate identity), deleting the corresponding CRD identity", slog.Any(logfields.Error, kvStoreErr), slog.Any(logfields.Identity, id), slog.Any(logfields.Key, key))
		// revert the allocation in the CRD backend
		releaseErr := d.crdBackend.DeleteID(ctx, id)
		if releaseErr != nil {
			log.Error("CRD backend failed to release identity", slog.Any(logfields.Error, releaseErr), slog.Any(logfields.Identity, id), slog.Any(logfields.Key, crdKey))
		}
		return kvStoreKey, kvStoreErr
	}
	if d.readFromKVStore {
		return kvStoreKey, nil
	}
	return crdKey, nil
}

func (d *doubleWriteBackend) AllocateIDIfLocked(ctx context.Context, id idpool.ID, key allocator.AllocatorKey, lock kvstore.KVLocker) (allocator.AllocatorKey, error) {
	crdKey, crdErr := d.crdBackend.AllocateIDIfLocked(ctx, id, key, lock)
	if crdErr != nil {
		log.Error("CRD backend failed to allocate identity with lock", slog.Any(logfields.Error, crdErr), slog.Any(logfields.Identity, id), slog.Any(logfields.Key, key))
		return crdKey, crdErr
	}
	kvStoreKey, kvStoreErr := d.kvstoreBackend.AllocateIDIfLocked(ctx, id, key, lock)
	if kvStoreErr != nil {
		log.Error("KVStore backend failed to allocate identity with lock), deleting the corresponding CRD identity", slog.Any(logfields.Error, kvStoreErr), slog.Any(logfields.Identity, id), slog.Any(logfields.Key, key))
		// revert the allocation in the CRD backend
		releaseErr := d.crdBackend.DeleteID(ctx, id)
		if releaseErr != nil {
			log.Error("CRD backend failed to release identity", slog.Any(logfields.Error, releaseErr), slog.Any(logfields.Identity, id), slog.Any(logfields.Key, crdKey))
		}
		return kvStoreKey, kvStoreErr
	}
	if d.readFromKVStore {
		return kvStoreKey, nil
	}
	return crdKey, nil
}

func (d *doubleWriteBackend) AcquireReference(ctx context.Context, id idpool.ID, key allocator.AllocatorKey, lock kvstore.KVLocker) error {
	crdErr := d.crdBackend.AcquireReference(ctx, id, key, lock)
	if crdErr != nil {
		logMessage := "CRD backend failed to acquire reference with lock"
		if d.readFromKVStore && strings.Contains(crdErr.Error(), "does not exist") {
			// This is a common error when CRD identities don't exist during the very first migration so we log it as debug
			log.Debug(logMessage, slog.Any(logfields.Error, crdErr), slog.Any(logfields.Identity, id), slog.Any(logfields.Key, key))
		} else {
			log.Error(logMessage, slog.Any(logfields.Error, crdErr), slog.Any(logfields.Identity, id), slog.Any(logfields.Key, key))
		}
	}
	kvStoreErr := d.kvstoreBackend.AcquireReference(ctx, id, key, lock)
	if kvStoreErr != nil {
		log.Error("KVStore backend failed to acquire reference with lock", slog.Any(logfields.Error, kvStoreErr), slog.Any(logfields.Identity, id), slog.Any(logfields.Key, key))
	}
	if d.readFromKVStore {
		return kvStoreErr
	}
	return crdErr
}

func (d *doubleWriteBackend) RunLocksGC(ctx context.Context, staleKeysPrevRound map[string]kvstore.Value) (map[string]kvstore.Value, error) {
	// This is a no-op for the CRD backend
	return d.kvstoreBackend.RunLocksGC(ctx, staleKeysPrevRound)
}

func (d *doubleWriteBackend) RunGC(
	ctx context.Context,
	rateLimit *rate.Limiter,
	staleKeysPrevRound map[string]uint64,
	minID, maxID idpool.ID,
) (map[string]uint64, *allocator.GCStats, error) {
	// This is a no-op for the CRD backend
	return d.kvstoreBackend.RunGC(ctx, rateLimit, staleKeysPrevRound, minID, maxID)
}

func (d *doubleWriteBackend) UpdateKey(ctx context.Context, id idpool.ID, key allocator.AllocatorKey, reliablyMissing bool) error {
	// Note: reliablyMissing is forced to "true" in order to ensure that when using the doublewrite backend for the first time,
	// identities are properly created in the "secondary" identity store
	crdErr := d.crdBackend.UpdateKey(ctx, id, key, true)
	if crdErr != nil {
		log.Error("CRD backend failed to update key", slog.Any(logfields.Error, crdErr), slog.Any(logfields.Identity, id), slog.Any(logfields.Key, key), slog.Bool("reliablyMissing", reliablyMissing))
	}
	kvStoreErr := d.kvstoreBackend.UpdateKey(ctx, id, key, reliablyMissing)
	if kvStoreErr != nil {
		log.Error("KVStore backend failed to update key", slog.Any(logfields.Error, kvStoreErr), slog.Any(logfields.Identity, id), slog.Any(logfields.Key, key), slog.Bool("reliablyMissing", reliablyMissing))
	}
	if d.readFromKVStore {
		return kvStoreErr
	}
	return crdErr
}

func (d *doubleWriteBackend) UpdateKeyIfLocked(ctx context.Context, id idpool.ID, key allocator.AllocatorKey, reliablyMissing bool, lock kvstore.KVLocker) error {
	// Note: reliablyMissing is forced to "true" in order to ensure that when using the doublewrite backend for the first time,
	// identities are properly created in the "secondary" identity store
	crdErr := d.crdBackend.UpdateKeyIfLocked(ctx, id, key, true, lock)
	if crdErr != nil {
		log.Error("CRD backend failed to update key with lock", slog.Any(logfields.Error, crdErr), slog.Any(logfields.Identity, id), slog.Any(logfields.Key, key), slog.Bool("reliablyMissing", reliablyMissing))
	}
	kvStoreErr := d.kvstoreBackend.UpdateKeyIfLocked(ctx, id, key, reliablyMissing, lock)
	if kvStoreErr != nil {
		log.Error("KVStore backend failed to update key with lock", slog.Any(logfields.Error, kvStoreErr), slog.Any(logfields.Identity, id), slog.Any(logfields.Key, key), slog.Bool("reliablyMissing", reliablyMissing))
	}
	if d.readFromKVStore {
		return kvStoreErr
	}
	return crdErr
}

func (d *doubleWriteBackend) Lock(ctx context.Context, key allocator.AllocatorKey) (kvstore.KVLocker, error) {
	// CRD backend doesn't require locking but since we are still doing KVStore operations, let's use the KVStore lock
	return d.kvstoreBackend.Lock(ctx, key)
}

func (d *doubleWriteBackend) Get(ctx context.Context, key allocator.AllocatorKey) (idpool.ID, error) {
	if d.readFromKVStore {
		return d.kvstoreBackend.Get(ctx, key)
	}
	return d.crdBackend.Get(ctx, key)
}

func (d *doubleWriteBackend) GetIfLocked(ctx context.Context, key allocator.AllocatorKey, lock kvstore.KVLocker) (idpool.ID, error) {
	if d.readFromKVStore {
		return d.kvstoreBackend.GetIfLocked(ctx, key, lock)
	}
	return d.crdBackend.GetIfLocked(ctx, key, lock)
}

func (d *doubleWriteBackend) GetByID(ctx context.Context, id idpool.ID) (allocator.AllocatorKey, error) {
	if d.readFromKVStore {
		return d.kvstoreBackend.GetByID(ctx, id)
	}
	return d.crdBackend.GetByID(ctx, id)
}

func (d *doubleWriteBackend) Release(ctx context.Context, id idpool.ID, key allocator.AllocatorKey) (err error) {
	kvStoreErr := d.kvstoreBackend.Release(ctx, id, key)
	if kvStoreErr != nil {
		log.Error("KVStore backend failed to release identity", slog.Any(logfields.Error, kvStoreErr), slog.Any(logfields.Identity, id), slog.Any(logfields.Key, key))
	}
	// This is a no-op for the CRD backend
	if d.readFromKVStore {
		return kvStoreErr
	}
	return nil
}

func (d *doubleWriteBackend) ListIDs(ctx context.Context) (identityIDs []idpool.ID, err error) {
	if d.readFromKVStore {
		return d.kvstoreBackend.ListIDs(ctx)
	}
	return d.crdBackend.ListIDs(ctx)
}

type NoOpHandler struct{}

func (h NoOpHandler) OnListDone()                                {}
func (h NoOpHandler) OnUpsert(idpool.ID, allocator.AllocatorKey) {}
func (h NoOpHandler) OnDelete(idpool.ID, allocator.AllocatorKey) {}

func (d *doubleWriteBackend) ListAndWatch(ctx context.Context, handler allocator.CacheMutations) {
	if d.readFromKVStore {
		// We still need to run ListAndWatch for the CRD backend to initialize the underlying store.
		// Since we don't need to use the results of the list operation, we can use a no-op handler
		go d.crdBackend.ListAndWatch(ctx, NoOpHandler{})
		d.kvstoreBackend.ListAndWatch(ctx, handler)
	}
	d.crdBackend.ListAndWatch(ctx, handler)
}
