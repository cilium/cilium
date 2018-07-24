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
	"errors"
	"fmt"
	"math/rand"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/cilium/cilium/pkg/backoff"
	"github.com/cilium/cilium/pkg/kvstore"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
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

	// allocAttemptsWatermark defines the watermark at what point we will
	// attempt to clear the cache before re-attempting to allocate
	allocAttemptsWatermark = 12

	// listTimeout is the time to wait for the initial list operation to
	// succeed when creating a new allocator
	listTimeout = 3 * time.Minute

	// gcInterval is the interval in which allocator identities are
	// attempted to be expired from the kvstore
	gcInterval = time.Duration(10) * time.Minute

	// NoID is a special ID that represents "no ID available"
	NoID ID = 0
)

// ID is the identified type which is being allocated. An ID maps to an
// AllocatorKey and back.
type ID uint64

// String returns the string representation of an allocated ID
func (i ID) String() string {
	return strconv.FormatUint(uint64(i), 10)
}

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

	// basePrefix is the prefix in the kvstore that all keys share which
	// are being managed by this allocator. The basePrefix typically
	// consists of something like: "space/project/allocatorName"
	basePrefix string

	// idPrefix is the kvstore key prefix for all master keys. It is being
	// derived from the basePrefix.
	idPrefix string

	// valuePrefix is the kvstore key prefix for all slave keys. It is
	// being derived from the basePrefix.
	valuePrefix string

	// lockPrefix is the prefix to use for all kvstore locks. This prefix
	// is different from the idPrefix and valuePrefix to simplify watching
	// for ID and key changes.
	lockPrefix string

	// min is the lower limit when allocating IDs. The allocator will never
	// allocate an ID lesser than this value.
	min ID

	// max is the upper limit when allocating IDs. The allocator will never
	// allocate an ID greater than this value.
	max ID

	// prefixMask if set, will be ORed to all selected IDs prior to
	// allocation
	prefixMask ID

	// localKeys contains all keys including their reference count for keys
	// which have been allocated and are in local use
	localKeys *localKeys

	// suffix is the suffix attached to keys which must be node specific,
	// this is typical set to the node's IP address
	suffix string

	// lockless is true if allocation can be done lockless. This depends on
	// the underlying kvstore backend
	lockless bool

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

	// randomIDs is a slice of random IDs between a.min and a.max
	randomIDs []int
}

func locklessCapability() bool {
	required := kvstore.CapabilityCreateIfExists | kvstore.CapabilityDeleteOnZeroCount
	return kvstore.GetCapabilities()&required == required
}

// AllocatorOption is the base type for allocator options
type AllocatorOption func(*Allocator)

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
func NewAllocator(basePath string, typ AllocatorKey, opts ...AllocatorOption) (*Allocator, error) {
	if kvstore.Client() == nil {
		return nil, fmt.Errorf("kvstore client not configured")
	}

	a := &Allocator{
		keyType:      typ,
		basePrefix:   basePath,
		idPrefix:     path.Join(basePath, "id"),
		valuePrefix:  path.Join(basePath, "value"),
		lockPrefix:   path.Join(basePath, "locks"),
		min:          1,
		max:          ID(^uint64(0)),
		localKeys:    newLocalKeys(),
		stopGC:       make(chan struct{}, 0),
		suffix:       uuid.NewUUID().String()[:10],
		lockless:     locklessCapability(),
		remoteCaches: map[*RemoteCache]struct{}{},
		backoffTemplate: backoff.Exponential{
			Min:    time.Duration(20) * time.Millisecond,
			Factor: 2.0,
		},
	}

	for _, fn := range opts {
		fn(a)
	}

	a.mainCache = newCache(kvstore.Client(), a.idPrefix)

	// invalid prefixes are only deleted from the main cache
	a.mainCache.deleteInvalidPrefixes = true

	if a.suffix == "<nil>" {
		return nil, errors.New("Allocator suffix is <nil> and unlikely unique")
	}

	if a.min < 1 {
		return nil, errors.New("minimum ID must be >= 1")
	}

	if a.max <= a.min {
		return nil, errors.New("Maximum ID must be greater than minimum ID")
	}

	go func() {
		if err := a.mainCache.startAndWait(a); err != nil {
			log.WithError(err).Fatalf("Unable to watch allocation prefix")
		}

		a.startGC()
	}()

	return a, nil
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

// WithSuffix sets the suffix of the allocator to the specified value
func WithSuffix(v string) AllocatorOption {
	return func(a *Allocator) { a.suffix = v }
}

// WithMin sets the minimum identifier to be allocated
func WithMin(id ID) AllocatorOption {
	return func(a *Allocator) { a.min = id }
}

// WithMax sets the maximum identifier to be allocated
func WithMax(id ID) AllocatorOption {
	return func(a *Allocator) { a.max = id }
}

// WithPrefixMask sets the prefix used for all ID allocations. If set, the mask
// will be ORed to all selected IDs prior to allocation. It is the
// responsibility of the caller to ensure that the mask is not conflicting with
// min..max.
func WithPrefixMask(mask ID) AllocatorOption {
	return func(a *Allocator) { a.prefixMask = mask }
}

// Delete deletes an allocator and stops the garbage collector
func (a *Allocator) Delete() {
	close(a.stopGC)
	a.mainCache.stop()

	if a.events != nil {
		close(a.events)
	}
}

// lockPath locks a key in the scope of an allocator
func (a *Allocator) lockPath(key string) (*kvstore.Lock, error) {
	suffix := strings.TrimPrefix(key, a.basePrefix)
	return kvstore.LockPath(path.Join(a.lockPrefix, suffix))
}

// DeleteAllKeys will delete all keys
func (a *Allocator) DeleteAllKeys() {
	kvstore.DeletePrefix(a.basePrefix)
}

// RangeFunc is the function called by RangeCache
type RangeFunc func(ID, AllocatorKey)

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

func invalidKey(key, prefix string, deleteInvalid bool) {
	log.WithFields(logrus.Fields{fieldKey: key, fieldPrefix: prefix}).Warning("Found invalid key outside of prefix")

	if deleteInvalid {
		kvstore.Delete(key)
	}
}

var (
	idRandomizer      = rand.New(rand.NewSource(time.Now().UnixNano()))
	idRandomizerMutex lock.Mutex
)

func (a *Allocator) newRandomIDs() {
	idRandomizerMutex.Lock()
	a.randomIDs = idRandomizer.Perm(int(a.max - a.min + 1))
	idRandomizerMutex.Unlock()
}

// Naive ID allocation mechanism.
func (a *Allocator) selectAvailableID() (ID, string) {
	a.mainCache.mutex.RLock()
	defer a.mainCache.mutex.RUnlock()

	// Perform two attempts to select an available ID:
	// 1. The first attempt walks through the remaining IDs in the current
	//    random sequence. This attempt represents the likely available IDs
	//    but does not include IDs that may have been released again since
	//    the sequence was generated
	// 2. The second attempt tries again using a newly allocated random
	//    sequence spanning the entire range of available IDs. This attempt
	//    is guaranteed to try all available IDs, if this attempt fails, no
	//    more IDs are avaiable. The 2nd attempt is always required for the
	//    first ever allocation and in case the first attempt consumes the
	//    last available ID in the sequence.
	for attempt := 0; attempt < 2; attempt++ {
		for i, r := range a.randomIDs {
			id := ID(r) + a.min
			if _, ok := a.mainCache.cache[id]; !ok && a.localKeys.lookupID(id) == "" {
				// remove the previously tried IDs that are already in
				// use from the list of IDs to attempt allocation
				a.randomIDs = a.randomIDs[i+1:]
				id |= a.prefixMask
				return id, id.String()
			}
		}

		if attempt == 0 {
			a.newRandomIDs()
		}
	}

	return 0, ""
}

func (a *Allocator) createValueNodeKey(key string, newID ID) error {
	// add a new key /value/<key>/<node> to account for the reference
	// The key is protected with a TTL/lease and will expire after LeaseTTL
	valueKey := path.Join(a.valuePrefix, key, a.suffix)
	if err := kvstore.Update(valueKey, []byte(newID.String()), true); err != nil {
		return fmt.Errorf("unable to create value-node key '%s': %s", valueKey, err)
	}

	return nil
}

// AllocatorKey is the interface to implement in order for a type to be used as
// key for the allocator
type AllocatorKey interface {
	// GetKey must return the key in string representation
	GetKey() string

	// PutKey must transform the key in string representation back into its
	// original type
	PutKey(v string) (AllocatorKey, error)

	// String must return the key in human readable string representation
	String() string
}

func (a *Allocator) lockedAllocate(key AllocatorKey) (ID, bool, error) {
	kvstore.Trace("Allocating key in kvstore", nil, logrus.Fields{fieldKey: key})

	// fetch first key that matches /value/<key> while ignoring the
	// node suffix
	value, err := a.Get(key)
	if err != nil {
		return 0, false, err
	}

	k := key.GetKey()
	kvstore.Trace("kvstore state is: ", nil, logrus.Fields{fieldID: value})

	if value != 0 {
		_, err := a.localKeys.allocate(k, value)
		if err != nil {
			return 0, false, fmt.Errorf("unable to reserve local key '%s': %s", k, err)
		}

		if err = a.createValueNodeKey(k, value); err != nil {
			a.localKeys.release(k)
			return 0, false, fmt.Errorf("unable to create slave key '%s': %s", k, err)
		}

		// mark the key as verified in the local cache
		if err := a.localKeys.verify(k); err != nil {
			log.WithError(err).Error("BUG: Unable to verify local key")
		}

		return value, false, nil
	}

	id, strID := a.selectAvailableID()
	if id == 0 {
		return 0, false, fmt.Errorf("no more available IDs in configured space")
	}

	kvstore.Trace("Selected available key", nil, logrus.Fields{fieldID: id})

	oldID, err := a.localKeys.allocate(k, id)
	if err != nil {
		return 0, false, fmt.Errorf("unable to reserve local key '%s': %s", k, err)
	}

	// Another local writer beat us to allocating an ID for the same key,
	// start over
	if id != oldID {
		a.localKeys.release(k)
		return 0, false, fmt.Errorf("another writer has allocated this key")
	}

	lock, err := a.lockPath(k)
	if err != nil {
		a.localKeys.release(k)
		return 0, false, fmt.Errorf("unable to lock key: %s", err)
	}

	value, err = a.GetNoCache(key)
	if err != nil {
		a.localKeys.release(k)
		lock.Unlock()
		return 0, false, err
	}

	if value != 0 {
		a.localKeys.release(k)
		lock.Unlock()
		return 0, false, fmt.Errorf("master key already exists")
	}

	// create /id/<ID> and fail if it already exists
	keyPath := path.Join(a.idPrefix, strID)
	err = kvstore.CreateOnly(keyPath, []byte(k), false)
	if err != nil {
		// Creation failed. Another agent most likely beat us to allocting this
		// ID, retry.
		a.localKeys.release(k)
		lock.Unlock()
		return 0, false, fmt.Errorf("unable to create master key '%s': %s", keyPath, err)
	}

	if err = a.createValueNodeKey(k, id); err != nil {
		// We will leak the master key here as the key has already been
		// exposed and may be in use by other nodes. The garbage
		// collector will release it again.
		a.localKeys.release(k)
		lock.Unlock()
		return 0, false, fmt.Errorf("slave key creation failed '%s': %s", k, err)
	}

	lock.Unlock()

	return id, true, nil
}

// Allocate will retrieve the ID for the provided key. If no ID has been
// allocated for this key yet, a key will be allocated. If allocation fails,
// most likely due to a parallel allocation of the same ID by another user,
// allocation is re-attempted for maxAllocAttempts times.
//
// Returns the ID allocated to the key, if the ID had to be allocated, then
// true is returned. An error is returned in case of failure.
func (a *Allocator) Allocate(key AllocatorKey) (ID, bool, error) {
	var (
		err   error
		value ID
		isNew bool
		k     = key.GetKey()
	)

	kvstore.Trace("Allocating key", nil, logrus.Fields{fieldKey: key})

	// Check our list of local keys already in use and increment the
	// refcnt. The returned key must be released afterwards. No kvstore
	// operation was performed for this allocation
	if val := a.localKeys.use(k); val != NoID {
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
		value, isNew, err = a.lockedAllocate(key)
		if err == nil {
			a.mainCache.insert(key, value)
			return value, isNew, nil
		}

		kvstore.Trace("Allocation attempt failed", err, logrus.Fields{fieldKey: key, logfields.Attempt: attempt})

		// We have reached a watermark in allocation attempts. The
		// failure is somewhat persistent. There are multiple reasons
		// including:
		// - continued connectivity problem to kvstore
		// - stale local cache due to backlog in processing of kvstore
		//   events
		//
		// To prevent the stale local ache
		if attempt == allocAttemptsWatermark {
			if err := a.mainCache.restart(a); err != nil {
				log.WithError(err).Warning("Unable to clear and refill allocator cache")
			}
		}

		boff.Wait()
	}

	return 0, false, err
}

// Get returns the ID which is allocated to a key. Returns an ID of NoID if no ID
// has been allocated to this key yet.
func (a *Allocator) Get(key AllocatorKey) (ID, error) {
	if id := a.mainCache.get(key.GetKey()); id != NoID {
		return id, nil
	}

	return a.GetNoCache(key)
}

// Get returns the ID which is allocated to a key in the kvstore
func (a *Allocator) GetNoCache(key AllocatorKey) (ID, error) {
	prefix := path.Join(a.valuePrefix, key.GetKey())
	value, err := kvstore.GetPrefix(prefix)
	kvstore.Trace("AllocateGet", err, logrus.Fields{fieldPrefix: prefix, fieldValue: value})
	if err != nil || value == nil {
		return 0, err
	}

	id, err := strconv.ParseUint(string(value), 10, 64)
	if err != nil {
		return NoID, fmt.Errorf("unable to parse value '%s': %s", value, err)
	}

	return ID(id), nil
}

// GetByID returns the key associated with an ID. Returns nil if no key is
// associated with the ID.
func (a *Allocator) GetByID(id ID) (AllocatorKey, error) {
	if key := a.mainCache.getByID(id); key != nil {
		return key, nil
	}

	v, err := kvstore.Get(path.Join(a.idPrefix, id.String()))
	if err != nil {
		return nil, err
	}

	return a.keyType.PutKey(string(v))
}

// Release releases the use of an ID associated with the provided key. After
// the last user has released the ID, the key is removed in the KVstore and
// the returned lastUse value is true.
func (a *Allocator) Release(key AllocatorKey) (err error) {
	k := key.GetKey()
	// release the key locally, if it was the last use, remove the node
	// specific value key to remove the global reference mark
	lastUse, err := a.localKeys.release(k)
	if err != nil {
		return
	}

	if lastUse {
		valueKey := path.Join(a.valuePrefix, k, a.suffix)
		if err := kvstore.Delete(valueKey); err != nil {
			log.WithError(err).WithFields(logrus.Fields{fieldKey: key}).Warning("Ignoring node specific ID")
		}

		// if a.lockless {
		// FIXME: etcd 3.3 will make it possible to do a lockless
		// cleanup of the ID and release it right away. For now we rely
		// on the GC to kick in a release unused IDs.
		// }
	}

	return
}

func (a *Allocator) runGC() error {
	// fetch list of all /id/ keys
	allocated, err := kvstore.ListPrefix(a.idPrefix)
	if err != nil {
		return fmt.Errorf("list failed: %s", err)
	}

	// iterate over /id/
	for key, v := range allocated {
		// if a.lockless {
		// FIXME: Add DeleteOnZeroCount support
		// }

		lock, err := a.lockPath(key)
		if err != nil {
			continue
		}

		// fetch list of all /value/<key> keys
		uses, err := kvstore.ListPrefix(path.Join(a.valuePrefix, string(v)))
		if err != nil {
			lock.Unlock()
			continue
		}

		// if ID has no user, delete it
		if len(uses) == 0 {
			kvstore.Delete(key)
		}

		lock.Unlock()
	}

	return nil
}

func (a *Allocator) startGC() {
	go func(a *Allocator) {
		for {
			if err := a.runGC(); err != nil {
				log.WithError(err).WithFields(logrus.Fields{fieldPrefix: a.idPrefix}).
					Debug("Unable to run garbage collector")
			}

			select {
			case <-a.stopGC:
				log.WithFields(logrus.Fields{fieldPrefix: a.idPrefix}).
					Debug("Stopped garbage collector")
				return
			case <-time.After(gcInterval):
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
	ID ID

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
		cache:     newCache(backend, path.Join(prefix, "id")),
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
