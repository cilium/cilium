// Copyright 2016-2019 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package allocator

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/cilium/cilium/pkg/backoff"
	"github.com/cilium/cilium/pkg/idpool"
	"github.com/cilium/cilium/pkg/kvstore"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/uuid"

	"github.com/sirupsen/logrus"
)

var (
	log = logging.DefaultLogger.WithField(logfields.LogSubsys, "allocator")
)

const (
	// maxAllocAttempts is the number of attempted allocation requests
	// performed before failing.
	maxAllocAttempts = 16

	// listTimeout is the time to wait for the initial list operation to
	// succeed when creating a new allocator
	listTimeout = 3 * time.Minute
)

// Allocator is a distributed ID allocator backed by a KVstore. It maps
// arbitrary keys to identifiers. Multiple users on different cluster nodes can
// in parallel request the ID for keys and are guaranteed to retrieve the same
// ID for an identical key.
//
// While the details of how keys are stored is delegated to Backend
// implementations, some expectations exist. See pkg/kvstore/allocator for
// details about the kvstore implementation.
//
// A node takes a reference to an identity when it is in-use on that node, and
// the identity remains in-use if there is any node refernce to it. When an
// identity no longer has any node references, it may be garbage collected. No
// guarantees are made at that point and the numeric identity may be reused.
// Note that the numeric IDs are selected locally and verified with the Backend.
//
// Lookup ID by key:
// 1. Return ID from local cache updated by watcher (no Backend interactions)
// 2. Do ListPrefix() on slave key excluding node suffix, return the first
//    result that matches the exact prefix.
//
// Lookup key by ID:
// 1. Return key from local cache updated by watcher (no Backend interactions)
// 2. Do Get() on master key, return result
//
// Allocate:
// 1. Check local key cache, increment, and return if key is already in use
//    locally (no Backend interactions)
// 2. Check local cache updated by watcher, if...
//
// ... match found:
// 2.1 Create a new slave key. This operation is potentially racy as the master
//     key can be removed in the meantime.
//       etcd: Create is made conditional on existence of master key
//       consul: locking
//
// ... match not found:
// 2.1 Select new unused id from local cache
// 2.2 Create a new master key with the condition that it may not exist
// 2.3 Create a new slave key
//
// 1.1. If found, increment and return (no Backend interactions)
// 2. Lookup ID by key in local cache or via first slave key found in Backend
//
// Release:
//  1. Reduce local reference count until last use (no Backend interactions)
//  2. Delete slave key (basePath/value/key1/node1)
//     This automatically guarantees that when the last node has released the
//     key, the key is no longer found by Get()
//  3. If the node goes down, all slave keys of that node are removed after
//     the TTL expires (auto release).
type Allocator struct {
	// events is a channel which will receive AllocatorEvent as IDs are
	// added, modified or removed from the allocator
	events AllocatorEventChan

	// keyType is an instance of the type to be used as allocator key.
	keyType AllocatorKey

	// min is the lower limit when allocating IDs. The allocator will never
	// allocate an ID lesser than this value.
	min idpool.ID

	// max is the upper limit when allocating IDs. The allocator will never
	// allocate an ID greater than this value.
	max idpool.ID

	// prefixMask if set, will be ORed to all selected IDs prior to
	// allocation
	prefixMask idpool.ID

	// localKeys contains all keys including their reference count for keys
	// which have been allocated and are in local use
	localKeys *localKeys

	// suffix is the suffix attached to keys which must be node specific,
	// this is typical set to the node's IP address
	suffix string

	// backoffTemplate is the backoff configuration while allocating
	backoffTemplate backoff.Exponential

	// slaveKeysMutex protects the concurrent access of the slave key by this
	// agent.
	slaveKeysMutex lock.Mutex

	// mainCache is the main cache, representing the allocator contents of
	// the primary kvstore connection
	mainCache cache

	// remoteCachesMutex protects accesse to remoteCaches
	remoteCachesMutex lock.RWMutex

	// remoteCaches is the list of additional remote caches being watched
	// in addition to the main cache
	remoteCaches map[*RemoteCache]struct{}

	// stopGC is the channel used to stop the garbage collector
	stopGC chan struct{}

	// initialListDone is a channel that is closed when the initial
	// synchronization has completed
	initialListDone waitChan

	// idPool maintains a pool of available ids for allocation.
	idPool *idpool.IDPool

	// enableMasterKeyProtection if true, causes master keys that are still in
	// local use to be automatically re-created
	enableMasterKeyProtection bool

	// disableGC disables the garbage collector
	disableGC bool

	// backend is the upstream, shared, backend to which we syncronize local
	// information
	backend Backend
}

// AllocatorOption is the base type for allocator options
type AllocatorOption func(*Allocator)

// NewAllocatorForGC returns an allocator that can be used to run RunGC()
func NewAllocatorForGC(backend Backend) *Allocator {
	return &Allocator{backend: backend}
}

// Backend represents clients to remote ID allocation systems, such as KV
// Stores. These are used to coordinate key->ID allocation between cilium
// nodes.
type Backend interface {
	// DeleteAllKeys will delete all keys. It is used in tests.
	DeleteAllKeys(ctx context.Context)

	// Encode encodes a key string as required to conform to the key
	// restrictions of the backend
	Encode(string) string

	// AllocateID creates a new key->ID association. This is expected to be a
	// create-only operation, and the ID may be allocated by another node. An
	// error in that case is not expected to be fatal. The actual ID is obtained
	// by Allocator from the local idPool, which is updated with used-IDs as the
	// Backend makes calls to the handler in ListAndWatch.
	AllocateID(ctx context.Context, id idpool.ID, key AllocatorKey) error

	// AllocateIDIfLocked behaves like AllocateID but when lock is non-nil the
	// operation proceeds only if it is still valid.
	AllocateIDIfLocked(ctx context.Context, id idpool.ID, key AllocatorKey, lock kvstore.KVLocker) error

	// AcquireReference records that this node is using this key->ID mapping.
	// This is distinct from any reference counting within this agent; only one
	// reference exists for this node for any number of managed endpoints using
	// it.
	// The semantics of cleaning up stale references is delegated to the Backend
	// implementation. RunGC may need to be invoked.
	// This can race, and so lock can be provided (via a Lock call, below).
	AcquireReference(ctx context.Context, id idpool.ID, key AllocatorKey, lock kvstore.KVLocker) error

	// Release releases the use of an ID associated with the provided key. It
	// does not guard against concurrent calls to
	// releases.Release(ctx context.Context, key AllocatorKey) (err error)
	Release(ctx context.Context, key AllocatorKey) (err error)

	// UpdateKey refreshes the record that this node is using this key -> id
	// mapping. When reliablyMissing is set it will also recreate missing master or
	// slave keys.
	UpdateKey(ctx context.Context, id idpool.ID, key AllocatorKey, reliablyMissing bool) error

	// UpdateKeyIfLocked behaves like UpdateKey but when lock is non-nil the operation proceeds only if it is still valid.
	UpdateKeyIfLocked(ctx context.Context, id idpool.ID, key AllocatorKey, reliablyMissing bool, lock kvstore.KVLocker) error

	// Get returns the allocated ID for this key as seen by the Backend. This may
	// have been created by other agents.
	Get(ctx context.Context, key AllocatorKey) (idpool.ID, error)

	// GetIfLocked behaves like Get, but but when lock is non-nil the
	// operation proceeds only if it is still valid.
	GetIfLocked(ctx context.Context, key AllocatorKey, lock kvstore.KVLocker) (idpool.ID, error)

	// GetByID returns the key associated with this ID, as seen by the Backend.
	// This may have been created by other agents.
	GetByID(ctx context.Context, id idpool.ID) (AllocatorKey, error)

	// Lock provides an opaque lock object that can be used, later, to ensure
	// that the key has not changed since the lock was created. This can be done
	// with GetIfLocked.
	Lock(ctx context.Context, key AllocatorKey) (kvstore.KVLocker, error)

	// ListAndWatch begins synchronizing the local Backend instance with its
	// remote.
	ListAndWatch(ctx context.Context, handler CacheMutations, stopChan chan struct{})

	// RunGC reaps stale or unused identities within the Backend and makes them
	// available for reuse. It is used by the cilium-operator and is not invoked
	// by cilium-agent.
	// Note: not all Backend implemenations rely on this, such as the kvstore
	// backends, and may use leases to expire keys.
	RunGC(ctx context.Context, staleKeysPrevRound map[string]uint64) (map[string]uint64, error)

	// Status returns a human-readable status of the Backend.
	Status() (string, error)
}

// NewAllocator creates a new Allocator. Any type can be used as key as long as
// the type implements the AllocatorKey interface. A variable of the type has
// to be passed into NewAllocator() to make the type known.  The specified base
// path is used to prefix all keys in the kvstore. The provided path must be
// unique.
//
// The allocator can be configured by passing in additional options:
//  - WithEvents() - enable Events channel
//  - WithMin(id) - minimum ID to allocate (default: 1)
//  - WithMax(id) - maximum ID to allocate (default max(uint64))
//
// After creation, IDs can be allocated with Allocate() and released with
// Release()
func NewAllocator(typ AllocatorKey, backend Backend, opts ...AllocatorOption) (*Allocator, error) {
	a := &Allocator{
		keyType:      typ,
		backend:      backend,
		min:          idpool.ID(1),
		max:          idpool.ID(^uint64(0)),
		localKeys:    newLocalKeys(),
		stopGC:       make(chan struct{}),
		suffix:       uuid.NewUUID().String()[:10],
		remoteCaches: map[*RemoteCache]struct{}{},
		backoffTemplate: backoff.Exponential{
			Min:    time.Duration(20) * time.Millisecond,
			Factor: 2.0,
		},
	}

	for _, fn := range opts {
		fn(a)
	}

	a.mainCache = newCache(a)

	if a.suffix == "<nil>" {
		return nil, errors.New("allocator suffix is <nil> and unlikely unique")
	}

	if a.min < 1 {
		return nil, errors.New("minimum ID must be >= 1")
	}

	if a.max <= a.min {
		return nil, errors.New("maximum ID must be greater than minimum ID")
	}

	a.idPool = idpool.NewIDPool(a.min, a.max)

	a.initialListDone = a.mainCache.start(a)
	if !a.disableGC {
		go func() {
			select {
			case <-a.initialListDone:
			case <-time.After(listTimeout):
				log.Fatalf("Timeout while waiting for initial allocator state")
			}
			a.startLocalKeySync()
		}()
	}

	return a, nil
}

// WithBackend sets this allocator to use backend. It is expected to be used at
// initialization.
func WithBackend(backend Backend) AllocatorOption {
	return func(a *Allocator) {
		a.backend = backend
	}
}

// WithEvents enables receiving of events.
//
// CAUTION: When using this function. The provided channel must be continuously
// read while NewAllocator() is being called to ensure that the channel does
// not block indefinitely while NewAllocator() emits events on it while
// populating the initial cache.
func WithEvents(events AllocatorEventChan) AllocatorOption {
	return func(a *Allocator) { a.events = events }
}

// WithMin sets the minimum identifier to be allocated
func WithMin(id idpool.ID) AllocatorOption {
	return func(a *Allocator) { a.min = id }
}

// WithMax sets the maximum identifier to be allocated
func WithMax(id idpool.ID) AllocatorOption {
	return func(a *Allocator) { a.max = id }
}

// WithPrefixMask sets the prefix used for all ID allocations. If set, the mask
// will be ORed to all selected IDs prior to allocation. It is the
// responsibility of the caller to ensure that the mask is not conflicting with
// min..max.
func WithPrefixMask(mask idpool.ID) AllocatorOption {
	return func(a *Allocator) { a.prefixMask = mask }
}

// WithMasterKeyProtection will watch for delete events on master keys and
// re-created them if local usage suggests that the key is still in use
func WithMasterKeyProtection() AllocatorOption {
	return func(a *Allocator) { a.enableMasterKeyProtection = true }
}

// WithoutGC disables the use of the garbage collector
func WithoutGC() AllocatorOption {
	return func(a *Allocator) { a.disableGC = true }
}

// Delete deletes an allocator and stops the garbage collector
func (a *Allocator) Delete() {
	close(a.stopGC)
	a.mainCache.stop()

	if a.events != nil {
		close(a.events)
	}
}

// WaitForInitialSync waits until the initial sync is complete
func (a *Allocator) WaitForInitialSync(ctx context.Context) error {
	select {
	case <-a.initialListDone:
	case <-ctx.Done():
		return fmt.Errorf("identity sync was cancelled: %s", ctx.Err())
	}

	return nil
}

// RangeFunc is the function called by RangeCache
type RangeFunc func(idpool.ID, AllocatorKey)

// ForeachCache iterates over the allocator cache and calls RangeFunc on each
// cached entry
func (a *Allocator) ForeachCache(cb RangeFunc) {
	a.mainCache.foreach(cb)

	a.remoteCachesMutex.RLock()
	for rc := range a.remoteCaches {
		rc.cache.foreach(cb)
	}
	a.remoteCachesMutex.RUnlock()
}

// selectAvailableID selects an available ID.
// Returns a triple of the selected ID ORed with prefixMask, the ID string and
// the originally selected ID.
func (a *Allocator) selectAvailableID() (idpool.ID, string, idpool.ID) {
	if id := a.idPool.LeaseAvailableID(); id != idpool.NoID {
		unmaskedID := id
		id |= a.prefixMask
		return id, id.String(), unmaskedID
	}

	return 0, "", 0
}

// AllocatorKey is the interface to implement in order for a type to be used as
// key for the allocator. The key's data is assumed to be a collection of
// pkg/label.Label, and the functions reflect this somewhat.
type AllocatorKey interface {
	fmt.Stringer

	// GetKey returns the canonical string representation of the key
	GetKey() string

	// PutKey stores the information in v into the key. This is is the inverse
	// operation to GetKey
	PutKey(v string) AllocatorKey

	// GetAsMap returns the key as a collection of "labels" with a key and value.
	// This is the inverse operation to PutKeyFromMap.
	GetAsMap() map[string]string

	// PutKeyFromMap stores the labels in v into the key to be used later. This
	// is the inverse operation to GetAsMap.
	PutKeyFromMap(v map[string]string) AllocatorKey
}

func (a *Allocator) encodeKey(key AllocatorKey) string {
	return a.backend.Encode(key.GetKey())
}

func (a *Allocator) lockedAllocate(ctx context.Context, key AllocatorKey) (idpool.ID, bool, error) {
	kvstore.Trace("Allocating key in kvstore", nil, logrus.Fields{fieldKey: key})

	k := a.encodeKey(key)
	lock, err := a.backend.Lock(ctx, key)
	if err != nil {
		return 0, false, err
	}

	defer lock.Unlock(ctx)

	// fetch first key that matches /value/<key> while ignoring the
	// node suffix
	value, err := a.GetIfLocked(ctx, key, lock)
	if err != nil {
		return 0, false, err
	}

	kvstore.Trace("kvstore state is: ", nil, logrus.Fields{fieldID: value})

	a.slaveKeysMutex.Lock()
	defer a.slaveKeysMutex.Unlock()

	// We shouldn't assume the fact the master key does not exist in the kvstore
	// that localKeys does not have it. The KVStore might have lost all of its
	// data but the local agent still holds a reference for the given master key.
	if value == 0 {
		value = a.localKeys.lookupKey(k)
		if value != 0 {
			// re-create master key
			if err := a.backend.UpdateKeyIfLocked(ctx, value, key, true, lock); err != nil {
				return 0, false, fmt.Errorf("unable to re-create missing master key '%s': %s while allocating ID: %s", key, value, err)
			}
		}
	} else {
		_, err := a.localKeys.allocate(k, key, value)
		if err != nil {
			return 0, false, fmt.Errorf("unable to reserve local key '%s': %s", k, err)
		}
	}

	if value != 0 {
		log.WithField(fieldKey, k).Info("Reusing existing global key")

		if err = a.backend.AcquireReference(ctx, value, key, lock); err != nil {
			a.localKeys.release(k)
			return 0, false, fmt.Errorf("unable to create slave key '%s': %s", k, err)
		}

		// mark the key as verified in the local cache
		if err := a.localKeys.verify(k); err != nil {
			log.WithError(err).Error("BUG: Unable to verify local key")
		}

		return value, false, nil
	}

	log.WithField(fieldKey, k).Debug("Allocating new master ID")
	id, strID, unmaskedID := a.selectAvailableID()
	if id == 0 {
		return 0, false, fmt.Errorf("no more available IDs in configured space")
	}

	kvstore.Trace("Selected available key ID", nil, logrus.Fields{fieldID: id})

	releaseKeyAndID := func() {
		a.localKeys.release(k)
		a.idPool.Release(unmaskedID) // This returns this ID to be re-used for other keys
	}

	oldID, err := a.localKeys.allocate(k, key, id)
	if err != nil {
		a.idPool.Release(unmaskedID)
		return 0, false, fmt.Errorf("unable to reserve local key '%s': %s", k, err)
	}

	// Another local writer beat us to allocating an ID for the same key,
	// start over
	if id != oldID {
		releaseKeyAndID()
		return 0, false, fmt.Errorf("another writer has allocated key %s", k)
	}

	// Check that this key has not been allocated in the cluster during our
	// operation here
	value, err = a.GetNoCache(ctx, key)
	if err != nil {
		releaseKeyAndID()
		return 0, false, err
	}
	if value != 0 {
		releaseKeyAndID()
		return 0, false, fmt.Errorf("Found master key after proceeding with new allocation for %s", k)
	}

	err = a.backend.AllocateIDIfLocked(ctx, id, key, lock)
	if err != nil {
		// Creation failed. Another agent most likely beat us to allocting this
		// ID, retry.
		releaseKeyAndID()
		return 0, false, fmt.Errorf("unable to allocate ID %s for key %s: %s", strID, key, err)
	}

	// Notify pool that leased ID is now in-use.
	a.idPool.Use(unmaskedID)

	if err = a.backend.AcquireReference(ctx, id, key, lock); err != nil {
		// We will leak the master key here as the key has already been
		// exposed and may be in use by other nodes. The garbage
		// collector will release it again.
		releaseKeyAndID()
		return 0, false, fmt.Errorf("slave key creation failed '%s': %s", k, err)
	}

	// mark the key as verified in the local cache
	if err := a.localKeys.verify(k); err != nil {
		log.WithError(err).Error("BUG: Unable to verify local key")
	}

	log.WithField(fieldKey, k).Info("Allocated new global key")

	return id, true, nil
}

// Allocate will retrieve the ID for the provided key. If no ID has been
// allocated for this key yet, a key will be allocated. If allocation fails,
// most likely due to a parallel allocation of the same ID by another user,
// allocation is re-attempted for maxAllocAttempts times.
//
// Returns the ID allocated to the key, if the ID had to be allocated, then
// true is returned. An error is returned in case of failure.
func (a *Allocator) Allocate(ctx context.Context, key AllocatorKey) (idpool.ID, bool, error) {
	var (
		err   error
		value idpool.ID
		isNew bool
		k     = a.encodeKey(key)
	)

	log.WithField(fieldKey, key).Debug("Allocating key")

	select {
	case <-a.initialListDone:
	case <-ctx.Done():
		return 0, false, fmt.Errorf("allocation was cancelled while waiting for initial key list to be received: %s", ctx.Err())
	}

	// Check our list of local keys already in use and increment the
	// refcnt. The returned key must be released afterwards. No kvstore
	// operation was performed for this allocation
	if val := a.localKeys.use(k); val != idpool.NoID {
		kvstore.Trace("Reusing local id", nil, logrus.Fields{fieldID: val, fieldKey: key})
		a.mainCache.insert(key, val)
		return val, false, nil
	}

	kvstore.Trace("Allocating from kvstore", nil, logrus.Fields{fieldKey: key})

	// make a copy of the template and customize it
	boff := a.backoffTemplate
	boff.Name = key.String()

	for attempt := 0; attempt < maxAllocAttempts; attempt++ {
		// FIXME: Add non-locking variant
		value, isNew, err = a.lockedAllocate(ctx, key)
		if err == nil {
			a.mainCache.insert(key, value)
			log.WithField(fieldKey, key).WithField(fieldID, value).Debug("Allocated key")
			return value, isNew, nil
		}

		scopedLog := log.WithFields(logrus.Fields{
			fieldKey:          key,
			logfields.Attempt: attempt,
		})

		select {
		case <-ctx.Done():
			scopedLog.WithError(ctx.Err()).Warning("Ongoing key allocation has been cancelled")
			return 0, false, fmt.Errorf("key allocation cancelled: %s", ctx.Err())
		default:
			scopedLog.WithError(err).Warning("Key allocation attempt failed")
		}

		kvstore.Trace("Allocation attempt failed", err, logrus.Fields{fieldKey: key, logfields.Attempt: attempt})

		if waitErr := boff.Wait(ctx); waitErr != nil {
			return 0, false, waitErr
		}
	}

	return 0, false, err
}

// GetIfLocked returns the ID which is allocated to a key. Returns an ID of NoID if no ID
// has been allocated to this key yet if the client is still holding the given
// lock.
func (a *Allocator) GetIfLocked(ctx context.Context, key AllocatorKey, lock kvstore.KVLocker) (idpool.ID, error) {
	if id := a.mainCache.get(a.encodeKey(key)); id != idpool.NoID {
		return id, nil
	}

	return a.backend.GetIfLocked(ctx, key, lock)
}

// Get returns the ID which is allocated to a key. Returns an ID of NoID if no ID
// has been allocated to this key yet.
func (a *Allocator) Get(ctx context.Context, key AllocatorKey) (idpool.ID, error) {
	if id := a.mainCache.get(a.encodeKey(key)); id != idpool.NoID {
		return id, nil
	}

	return a.GetNoCache(ctx, key)
}

// GetNoCache returns the ID which is allocated to a key in the kvstore,
// bypassing the local copy of allocated keys.
func (a *Allocator) GetNoCache(ctx context.Context, key AllocatorKey) (idpool.ID, error) {
	return a.backend.Get(ctx, key)
}

// GetByID returns the key associated with an ID. Returns nil if no key is
// associated with the ID.
func (a *Allocator) GetByID(ctx context.Context, id idpool.ID) (AllocatorKey, error) {
	if key := a.mainCache.getByID(id); key != nil {
		return key, nil
	}

	return a.backend.GetByID(ctx, id)
}

// Release releases the use of an ID associated with the provided key. After
// the last user has released the ID, the key is removed in the KVstore and
// the returned lastUse value is true.
func (a *Allocator) Release(ctx context.Context, key AllocatorKey) (lastUse bool, err error) {
	log.WithField(fieldKey, key).Info("Releasing key")

	select {
	case <-a.initialListDone:
	case <-ctx.Done():
		return false, fmt.Errorf("release was cancelled while waiting for initial key list to be received: %s", ctx.Err())
	}

	k := a.encodeKey(key)

	a.slaveKeysMutex.Lock()
	defer a.slaveKeysMutex.Unlock()

	// release the key locally, if it was the last use, remove the node
	// specific value key to remove the global reference mark
	lastUse, err = a.localKeys.releaseWithFunc(k, func() error {
		return a.backend.Release(ctx, key)
	})

	return lastUse, err
}

// RunGC scans the kvstore for unused master keys and removes them
func (a *Allocator) RunGC(staleKeysPrevRound map[string]uint64) (map[string]uint64, error) {
	return a.backend.RunGC(context.TODO(), staleKeysPrevRound)
}

// DeleteAllKeys will delete all keys. It is expected to be used in tests.
func (a *Allocator) DeleteAllKeys() {
	a.backend.DeleteAllKeys(context.TODO())
}

// syncLocalKeys checks the kvstore and verifies that a master key exists for
// all locally used allocations. This will restore master keys if deleted for
// some reason.
func (a *Allocator) syncLocalKeys() error {
	// Create a local copy of all local allocations to not require to hold
	// any locks while performing kvstore operations. Local use can
	// disappear while we perform the sync but that is fine as worst case,
	// a master key is created for a slave key that no longer exists. The
	// garbage collector will remove it again.
	ids := a.localKeys.getVerifiedIDs()

	for id, value := range ids {
		if err := a.backend.UpdateKey(context.TODO(), id, value, false); err != nil {
			log.WithError(err).WithFields(logrus.Fields{
				fieldKey: value,
				fieldID:  id,
			}).Warning("Unable to sync key")
		}
	}

	return nil
}

func (a *Allocator) startLocalKeySync() {
	go func(a *Allocator) {
		for {
			if err := a.syncLocalKeys(); err != nil {
				log.WithError(err).Warning("Unable to run local key sync routine")
			}

			select {
			case <-a.stopGC:
				log.Debug("Stopped master key sync routine")
				return
			case <-time.After(option.Config.KVstorePeriodicSync):
			}
		}
	}(a)
}

// AllocatorEventChan is a channel to receive allocator events on
type AllocatorEventChan chan AllocatorEvent

// AllocatorEvent is an event sent over AllocatorEventChan
type AllocatorEvent struct {
	// Typ is the type of event (create / modify / delete)
	Typ kvstore.EventType

	// ID is the allocated ID
	ID idpool.ID

	// Key is the key associated with the ID
	Key AllocatorKey
}

// RemoteCache represents the cache content of an additional kvstore managing
// identities. The contents are not directly accessible but will be merged into
// the ForeachCache() function.
type RemoteCache struct {
	cache     cache
	allocator *Allocator
}

// WatchRemoteKVStore starts watching an allocator base prefix the kvstore
// represents by the provided backend. A local cache of all identities of that
// kvstore will be maintained in the RemoteCache structure returned and will
// start being reported in the identities returned by the ForeachCache()
// function.
func (a *Allocator) WatchRemoteKVStore(backend kvstore.BackendOperations, prefix string) *RemoteCache {
	rc := &RemoteCache{
		cache:     newCache(a),
		allocator: a,
	}

	a.remoteCachesMutex.Lock()
	a.remoteCaches[rc] = struct{}{}
	a.remoteCachesMutex.Unlock()

	rc.cache.start(a)

	return rc
}

// Close stops watching for identities in the kvstore associated with the
// remote cache and will clear the local cache.
func (rc *RemoteCache) Close() {
	rc.allocator.remoteCachesMutex.Lock()
	delete(rc.allocator.remoteCaches, rc)
	rc.allocator.remoteCachesMutex.Unlock()

	rc.cache.stop()
}
