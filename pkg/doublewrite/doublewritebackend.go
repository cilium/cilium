package doublewrite

import (
	"context"
	"github.com/cilium/cilium/pkg/allocator"
	"github.com/cilium/cilium/pkg/idpool"
	"github.com/cilium/cilium/pkg/k8s/identitybackend"
	"github.com/cilium/cilium/pkg/kvstore"
	kvstoreallocator "github.com/cilium/cilium/pkg/kvstore/allocator"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/rate"
	"github.com/sirupsen/logrus"
)

var (
	log = logging.DefaultLogger.WithField(logfields.LogSubsys, "double-write-allocator")
)

func NewDoubleWriteBackend(c DoubleWriteBackendConfiguration) (allocator.Backend, error) {
	crdBackend, _ := identitybackend.NewCRDBackend(c.CRDBackendConfiguration)
	kvstoreBackend, _ := kvstoreallocator.NewKVStoreBackend(c.KVStoreBackendConfiguration)

	log.WithFields(logrus.Fields{
		"KVStoreBackendConfiguration.Suffix":   c.KVStoreBackendConfiguration.Suffix,
		"KVStoreBackendConfiguration.Typ":      c.KVStoreBackendConfiguration.Typ.String(),
		"KVStoreBackendConfiguration.BasePath": c.KVStoreBackendConfiguration.BasePath,
		"readFromKVStore":                      c.ReadFromKVStore,
	}).Debug("Creating the Double-Write backend")

	return &doubleWriteBackend{crdBackend: crdBackend.(*identitybackend.CRDBackend), kvstoreBackend: kvstoreBackend, readFromKVStore: c.ReadFromKVStore}, nil
}

type DoubleWriteBackendConfiguration struct {
	CRDBackendConfiguration     identitybackend.CRDBackendConfiguration
	KVStoreBackendConfiguration kvstoreallocator.KVStoreBackendConfiguration
	ReadFromKVStore             bool
}

type doubleWriteBackend struct {
	crdBackend      *identitybackend.CRDBackend
	kvstoreBackend  *kvstoreallocator.KVStoreBackend
	readFromKVStore bool
}

func (d *doubleWriteBackend) DeleteAllKeys(ctx context.Context) {
	d.crdBackend.DeleteAllKeys(ctx)
	d.kvstoreBackend.DeleteAllKeys(ctx)
}

func (d *doubleWriteBackend) AllocateID(ctx context.Context, id idpool.ID, key allocator.AllocatorKey) (allocator.AllocatorKey, error) {
	crdKey, crdErr := d.crdBackend.AllocateID(ctx, id, key)
	if crdErr != nil {
		log.WithFields(logrus.Fields{logfields.Identity: id.String(), logfields.Key: key.String()}).WithError(crdErr).Error("CRD backend failed to allocate identity")
	}
	kvStoreKey, kvStoreErr := d.kvstoreBackend.AllocateID(ctx, id, key)
	if kvStoreErr != nil {
		log.WithFields(logrus.Fields{logfields.Identity: id.String(), logfields.Key: key.String()}).WithError(kvStoreErr).Error("KVStore backend failed to allocate identity")
	}
	if d.readFromKVStore {
		return kvStoreKey, kvStoreErr
	}
	return crdKey, crdErr
}

func (d *doubleWriteBackend) AllocateIDIfLocked(ctx context.Context, id idpool.ID, key allocator.AllocatorKey, lock kvstore.KVLocker) (allocator.AllocatorKey, error) {
	crdKey, crdErr := d.crdBackend.AllocateIDIfLocked(ctx, id, key, lock)
	if crdErr != nil {
		log.WithFields(logrus.Fields{logfields.Identity: id.String(), logfields.Key: key.String()}).WithError(crdErr).Error("CRD backend failed to allocate identity with lock")
	}
	kvStoreKey, kvStoreErr := d.kvstoreBackend.AllocateIDIfLocked(ctx, id, key, lock)
	if kvStoreErr != nil {
		log.WithFields(logrus.Fields{logfields.Identity: id.String(), logfields.Key: key.String()}).WithError(kvStoreErr).Error("KVStore backend failed to allocate identity with lock")
	}
	if d.readFromKVStore {
		return kvStoreKey, kvStoreErr
	}
	return crdKey, crdErr
}

func (d *doubleWriteBackend) AcquireReference(ctx context.Context, id idpool.ID, key allocator.AllocatorKey, lock kvstore.KVLocker) error {
	crdErr := d.crdBackend.AcquireReference(ctx, id, key, lock)
	if crdErr != nil {
		log.WithFields(logrus.Fields{logfields.Identity: id.String(), logfields.Key: key.String()}).WithError(crdErr).Error("CRD backend failed to acquire reference with lock")
	}
	kvStoreErr := d.kvstoreBackend.AcquireReference(ctx, id, key, lock)
	if kvStoreErr != nil {
		log.WithFields(logrus.Fields{logfields.Identity: id.String(), logfields.Key: key.String()}).WithError(kvStoreErr).Error("KVStore backend failed to acquire reference with lock")
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
	crdErr := d.crdBackend.UpdateKey(ctx, id, key, true)
	if crdErr != nil {
		log.WithFields(logrus.Fields{logfields.Identity: id.String(), logfields.Key: key.String(), "reliablyMissing": reliablyMissing}).WithError(crdErr).Error("CRD backend failed to update key")
	}
	kvStoreErr := d.kvstoreBackend.UpdateKey(ctx, id, key, true)
	if kvStoreErr != nil {
		log.WithFields(logrus.Fields{logfields.Identity: id.String(), logfields.Key: key.String(), "reliablyMissing": reliablyMissing}).WithError(kvStoreErr).Error("KVStore backend failed to update key")
	}
	if d.readFromKVStore {
		return kvStoreErr
	}
	return crdErr
}

func (d *doubleWriteBackend) UpdateKeyIfLocked(ctx context.Context, id idpool.ID, key allocator.AllocatorKey, reliablyMissing bool, lock kvstore.KVLocker) error {
	crdErr := d.crdBackend.UpdateKeyIfLocked(ctx, id, key, true, lock)
	if crdErr != nil {
		log.WithFields(logrus.Fields{logfields.Identity: id.String(), logfields.Key: key.String(), "reliablyMissing": reliablyMissing}).WithError(crdErr).Error("CRD backend failed to update key with lock")
	}
	kvStoreErr := d.kvstoreBackend.UpdateKeyIfLocked(ctx, id, key, true, lock)
	if kvStoreErr != nil {
		log.WithFields(logrus.Fields{logfields.Identity: id.String(), logfields.Key: key.String(), "reliablyMissing": reliablyMissing}).WithError(kvStoreErr).Error("KVStore backend failed to update key with lock")
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
		log.WithFields(logrus.Fields{logfields.Identity: id.String(), logfields.Key: key.String()}).WithError(kvStoreErr).Error("KVStore backend failed to release identity")
	}
	// This is a no-op for the CRD backend
	if d.readFromKVStore {
		return kvStoreErr
	}
	return nil
}

func (d *doubleWriteBackend) ListAndWatch(ctx context.Context, handler allocator.CacheMutations, stopChan chan struct{}) {
	d.crdBackend.ListAndWatch(ctx, handler, stopChan)
	d.kvstoreBackend.ListAndWatch(ctx, handler, stopChan)
}

func (d *doubleWriteBackend) Status() (string, error) {
	if d.readFromKVStore {
		return d.kvstoreBackend.Status()
	}
	return d.crdBackend.Status()
}

func (d *doubleWriteBackend) Encode(v string) string {
	// Works for both CRD and etcd KVStore
	return v
}
