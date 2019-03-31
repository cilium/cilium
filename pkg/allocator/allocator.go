// Copyright 2016-2018 Authors of Cilium
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
// Slave keys:
//   Slave keys are owned by individual nodes:
//     - basePath/value/key1/node1 => 1001
//     - basePath/value/key1/node2 => 1001
//     - basePath/value/key2/node1 => 1002
//     - basePath/value/key2/node2 => 1002
//
//   If at least one key exists with the prefix basePath/value/keyN then that
//   key must be considered to be in use in the allocation space.
//
//   Slave keys are protected by a lease and will automatically get removed
//   after ~ kstore.LeaseTTL if the node does not renew in time.
//
// Master key:
//    - basePath/id/1001 => key1
//    - basePath/id/1002 => key2
//
//   Master keys provide the mapping from ID to key. As long as a master key
//   for an ID exists, the ID is still in use. However, if a master key is no
//   longer backed by at least one slave key, the garbage collector will
//   eventually release the master key and return it back to the pool.
//
// Lookup ID by key:
// 1. Return ID from local cache updated by watcher (no kvstore interactions)
// 2. Do GetPrefix() on slave key excluding node suffix, return first result
//
// Lookup key by ID:
// 1. Return key from local cache updated by watcher (no kvstore interactions)
// 2. Do Get() on master key, return result
//
// Allocate:
// 1. Check local key cache, increment, and return if key is already in use
//    locally (no kvstore interactions)
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
// 1.1. If found, increment and return (no kvstore interactions)
// 2. Lookup ID by key in local cache or via first slave key found in kvstore
// 2.1
// 3.
//
// Release:
//  1. Reduce local reference count until last use (no kvstore interactions)
//  2. Delete slave key (basePath/value/key1/node1)
//     This automatically guarantees that when the last node has relesed the
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

	backend Backend
}

// AllocatorOption is the base type for allocator options
type AllocatorOption func(*Allocator)

// NewAllocatorForGC returns an allocator  that can be used to run RunGC()
func NewAllocatorForGC(backend Backend) *Allocator {
	return &Allocator{backend: backend}
}

type Lock interface {
	Unlock() error
}

type Backend interface {
	// DeleteAllKeys will delete all keys
	DeleteAllKeys()

	AllocateID(ctx context.Context, id idpool.ID, key AllocatorKey) error
	AcquireReference(ctx context.Context, id idpool.ID, key AllocatorKey) error

	Lock(ctx context.Context, key AllocatorKey) (Lock, error)

	UpdateKey(id idpool.ID, key AllocatorKey, reliablyMissing bool)

	Get(ctx context.Context, key AllocatorKey) (idpool.ID, error)
	GetByID(id idpool.ID) (AllocatorKey, error)

	Release(ctx context.Context, key AllocatorKey) error

	ListAndWatch(handler CacheMutations, stopChan chan struct{})

	RunGC(staleKeysPrevRound map[string]uint64) (map[string]uint64, error)

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
//  - WithSuffix(string) - customize the node specifix suffix to attach to keys
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

	// invalid prefixes are only deleted from the main cache
	//a.mainCache.backend.deleteInvalidPrefixes = true

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

// selectAvailableID selects an available ID.  Returns a triple of the selected
// ID ORed with prefixMask, the ID string and the originally selected ID.
func (a *Allocator) selectAvailableID() (idpool.ID, string, idpool.ID) {
	if id := a.idPool.LeaseAvailableID(); id != idpool.NoID {
		unmaskedID := id
		id |= a.prefixMask
		return id, id.String(), unmaskedID
	}

	return 0, "", 0
}

// AllocatorKey is the interface to implement in order for a type to be used as
// key for the allocator
type AllocatorKey interface {
	// GetKey must return the key in string representation
	GetKey() string

	GetAsMap() map[string]string

	// PutKey must transform the key in string representation back into its
	// original type
	PutKey(v string) (AllocatorKey, error)

	PutKeyFromMap(v map[string]string) AllocatorKey

	// String must return the key in human readable string representation
	String() string
}

func (a *Allocator) lockedAllocate(ctx context.Context, key AllocatorKey) (idpool.ID, bool, error) {
	kvstore.Trace("Allocating key in kvstore", nil, logrus.Fields{fieldKey: key})

	k := key.GetKey()
	lock, err := a.backend.Lock(ctx, key)
	if err != nil {
		return 0, false, err
	}

	defer lock.Unlock()

	// fetch first key that matches /value/<key> while ignoring the
	// node suffix
	value, err := a.Get(ctx, key)
	if err != nil {
		return 0, false, err
	}

	kvstore.Trace("kvstore state is: ", nil, logrus.Fields{fieldID: value})

	if value != 0 {
		_, err := a.localKeys.allocate(k, key, value)
		if err != nil {
			return 0, false, fmt.Errorf("unable to reserve local key '%s': %s", k, err)
		}

		if err = a.backend.AcquireReference(ctx, value, key); err != nil {
			a.localKeys.release(k)
			return 0, false, fmt.Errorf("unable to create slave key '%s': %s", k, err)
		}

		// mark the key as verified in the local cache
		if err := a.localKeys.verify(k); err != nil {
			log.WithError(err).Error("BUG: Unable to verify local key")
		}

		return value, false, nil
	}

	id, strID, unmaskedID := a.selectAvailableID()
	if id == 0 {
		return 0, false, fmt.Errorf("no more available IDs in configured space")
	}

	kvstore.Trace("Selected available key", nil, logrus.Fields{fieldID: id})

	releaseKeyAndID := func() {
		a.localKeys.release(k)
		a.idPool.Release(unmaskedID)
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
		return 0, false, fmt.Errorf("another writer has allocated this key")
	}

	value, err = a.GetNoCache(ctx, key)
	if err != nil {
		releaseKeyAndID()
		return 0, false, err
	}

	if value != 0 {
		releaseKeyAndID()
		return 0, false, fmt.Errorf("master key already exists")
	}

	err = a.backend.AllocateID(ctx, id, key)
	if err != nil {
		// Creation failed. Another agent most likely beat us to allocting this
		// ID, retry.
		releaseKeyAndID()
		return 0, false, fmt.Errorf("unable to allocate ID %s for key %s: %s", strID, key, err)
	}

	// Notify pool that leased ID is now in-use.
	a.idPool.Use(unmaskedID)

	if err = a.backend.AcquireReference(ctx, id, key); err != nil {
		// We will leak the master key here as the key has already been
		// exposed and may be in use by other nodes. The garbage
		// collector will release it again.
		a.localKeys.release(k)
		return 0, false, fmt.Errorf("slave key creation failed '%s': %s", k, err)
	}

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
		k     = key.GetKey()
	)

	log.WithField(fieldKey, key).Info("Allocating key")

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

	// make a copy of the template and customize it
	boff := a.backoffTemplate
	boff.Name = key.String()

	for attempt := 0; attempt < maxAllocAttempts; attempt++ {
		// FIXME: Add non-locking variant
		value, isNew, err = a.lockedAllocate(ctx, key)
		if err == nil {
			a.mainCache.insert(key, value)
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

// Get returns the ID which is allocated to a key. Returns an ID of NoID if no ID
// has been allocated to this key yet.
func (a *Allocator) Get(ctx context.Context, key AllocatorKey) (idpool.ID, error) {
	if id := a.mainCache.get(key.GetKey()); id != idpool.NoID {
		return id, nil
	}

	return a.GetNoCache(ctx, key)
}

// Get returns the ID which is allocated to a key in the kvstore
func (a *Allocator) GetNoCache(ctx context.Context, key AllocatorKey) (idpool.ID, error) {
	return a.backend.Get(ctx, key)
}

// GetByID returns the key associated with an ID. Returns nil if no key is
// associated with the ID.
func (a *Allocator) GetByID(id idpool.ID) (AllocatorKey, error) {
	if key := a.mainCache.getByID(id); key != nil {
		return key, nil
	}

	return a.backend.GetByID(id)
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

	k := key.GetKey()
	// release the key locally, if it was the last use, remove the node
	// specific value key to remove the global reference mark
	lastUse, err = a.localKeys.release(k)
	if err != nil {
		return
	}

	if lastUse {
		a.backend.Release(ctx, key)
	}

	return
}

// RunGC scans the kvstore for unused master keys and removes them
func (a *Allocator) RunGC(staleKeysPrevRound map[string]uint64) (map[string]uint64, error) {
	return a.backend.RunGC(staleKeysPrevRound)
}

func (a *Allocator) DeleteAllKeys() {
	a.backend.DeleteAllKeys()
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
		a.backend.UpdateKey(id, value, false)
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
