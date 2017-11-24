// Copyright 2016-2017 Authors of Cilium
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
	"fmt"
	"math/rand"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/cilium/cilium/pkg/kvstore"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/node"

	"github.com/sirupsen/logrus"
)

var (
	// log is the k8s package logger object.
	log = logrus.WithField(logfields.LogSubsys, "allocator")
)

const (
	// maxAllocAttempts is the number of attempted allocation requests
	// performed before failing.
	maxAllocAttempts = 16

	// listTimeout is the time to wait for the initial list operation to
	// succeed when creating a new allocator
	listTimeout = 10 * time.Second

	gcInterval = time.Duration(10) * time.Minute
)

// ID is the allocated identifier which maps to a key
type ID uint64

const (
	// NoID represents ID not available
	NoID ID = 0
)

// String returns the string representation of an allocated ID
func (i ID) String() string {
	return strconv.FormatUint(uint64(i), 10)
}

// IDMap provides mapping from ID to key
type IDMap map[ID]AllocatorKey

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
//   key must be considered to be in use on cluster level.
//
//   Slave keys are protected by a lease and will automatically get removed
//   after ~ kstore.LeaseTTL if the node does not renew in time.
//
// Master key:
//    - basePath/id/1001 => key1
//    - basePath/id/1002 => key2
//
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
//       etcd: Create is made conditional on existance of master key
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
//
// Release:
//  1. Reduce local reference count until last use (no kvstore interactions)
//  2. Delete slave key (basePath/value/key1/node1)
//     This automatically guarantees that when the last node has relesed the
//     key, the key is no longer found by Get()
//  3. If the node goes down, all slave keys of that node are removed after
//     the TTL expires (auto release).
//
// Garbage collector:
type Allocator struct {
	// Events is a channel which will receive AllocatorEvent as IDs are
	// added, modified or removed from the allocator
	Events AllocatorEventChan

	// keyType is the type to be used as allocator key
	keyType AllocatorKey

	cache IDMap
	mutex lock.RWMutex

	// basePrefix is the base prefix shared by all other prefixes
	basePrefix string

	// idPrefix is the kvstore key prefix for the master key
	idPrefix string

	// valuePrefix is the kvstore key prefix for the slave keys
	valuePrefix string

	// lockPrefix is the prefix to use to lock the entire distributed
	// allocator for complex operations which are not doable with CAS
	lockPrefix string

	// min is the lower limit when allocating IDs
	min ID

	// max is the upper limit when allocating IDs
	max ID

	// localKeys contains all keys including their reference count for keys
	// which have been allocated and are in local use
	localKeys *localKeys

	// suffix is the suffix attached to keys which must be node specific,
	// this is typical set to the node's IP address
	suffix string

	// lockless is true if allocation can be done lockless. This depends on
	// the underlying kvstore backend
	lockless bool

	idWatcherStop chan struct{}
	stopGC        chan struct{}

	skipCache bool
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
		keyType:     typ,
		basePrefix:  basePath,
		idPrefix:    path.Join(basePath, "id"),
		valuePrefix: path.Join(basePath, "value"),
		lockPrefix:  path.Join(basePath, "locks"),
		min:         1,
		max:         ID(^uint64(0)),
		localKeys:   newLocalKeys(),
		stopGC:      make(chan struct{}, 0), // unbuffered channel so gc is stopped in sync
		suffix:      node.GetExternalIPv4().String(),
		cache:       IDMap{},
		lockless:    locklessCapability(),
	}

	for _, fn := range opts {
		fn(a)
	}

	if a.min < 1 {
		return nil, fmt.Errorf("minimum ID must be >= 1")
	}

	waitWatch := a.startWatch()
	a.startGC()

	// Wait for watcher to be started and for list operation to succeed
	select {
	case <-waitWatch:
	case <-time.After(listTimeout):
		return nil, fmt.Errorf("Time out while waiting for list operation to complete")
	}

	return a, nil
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

// Delete deletes an allocator and stops the garbage collector
func (a *Allocator) Delete() {
	close(a.stopGC)
	a.stopWatch()
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
	a.mutex.RLock()
	for k, v := range a.cache {
		cb(k, v)
	}
	a.mutex.RUnlock()
}

func invalidKey(key, prefix string, deleteInvalid bool) {
	log.WithFields(logrus.Fields{fieldKey: key, fieldPrefix: prefix}).Warning("Found invalid key outside of prefix")

	if deleteInvalid {
		kvstore.Delete(key)
	}
}

func (a *Allocator) keyToID(key string, deleteInvalid bool) ID {
	if !strings.HasPrefix(key, a.idPrefix) {
		invalidKey(key, a.idPrefix, deleteInvalid)
		return NoID
	}

	suffix := strings.TrimPrefix(key, a.idPrefix)
	if suffix[0] == '/' {
		suffix = suffix[1:]
	}

	id, err := strconv.ParseUint(suffix, 10, 64)
	if err != nil {
		invalidKey(key, a.idPrefix, deleteInvalid)
		return NoID
	}

	return ID(id)
}

var (
	idRandomizer = rand.New(rand.NewSource(time.Now().UnixNano()))
)

// Naive ID allocation mechanism.
func (a *Allocator) selectAvailableID() (ID, string) {
	a.mutex.RLock()
	defer a.mutex.RUnlock()

	for _, r := range idRandomizer.Perm(int(a.max - a.min + 1)) {
		id := ID(r) + a.min
		if _, ok := a.cache[id]; !ok && a.localKeys.lookupID(id) == "" {
			return id, id.String()
		}
	}

	return 0, ""
}

func (a *Allocator) createValueNodeKey(key string, newID ID) error {
	// add a new key /value/<key>/<node> to account for the reference
	// The key is protected with a TTL/lease and will expire after LeaseTTL
	valueKey := path.Join(a.valuePrefix, key, a.suffix)
	return kvstore.CreateOnly(valueKey, []byte(newID.String()), true)
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
	// fetch first key that matches /value/<key> while ignoring the
	// node suffix
	value, err := a.Get(key)
	if err != nil {
		return 0, false, err
	}

	k := key.GetKey()

	if value != 0 {
		if err = a.createValueNodeKey(k, value); err != nil {
			return 0, false, fmt.Errorf("unable to create slave key: %s", err)
		}

		_, err := a.localKeys.allocate(k, value)
		if err != nil {
			return 0, false, fmt.Errorf("unable to reserve local key: %s", err)
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
		return 0, false, fmt.Errorf("unable to reserve local key: %s", err)
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

	// create /id/<ID> and fail if it already exists
	err = kvstore.CreateOnly(path.Join(a.idPrefix, strID), []byte(k), false)
	if err != nil {
		// Creation failed. Another agent most likely beat us to allocting this
		// ID, retry.
		a.localKeys.release(k)
		lock.Unlock()
		return 0, false, fmt.Errorf("unable to create master key: %s", err)
	}

	if err = a.createValueNodeKey(k, id); err != nil {
		// We will leak the master key here as the key has already been
		// exposed and may be in use by other nodes. The garbage
		// collector will release it again.
		a.localKeys.release(k)
		lock.Unlock()
		return 0, false, fmt.Errorf("slave key creation failed: %s", err)
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
	if !a.skipCache {
		val := a.localKeys.use(k)
		if val != NoID {
			kvstore.Trace("Reusing local id", nil, logrus.Fields{fieldID: val, fieldKey: key})
			a.cache[val] = key
			return val, false, nil
		}
	}

	kvstore.Trace("Allocating from kvstore", nil, logrus.Fields{fieldKey: key})

	for attempt := 0; attempt < maxAllocAttempts; attempt++ {
		// FIXME: Add non-locking variant
		value, isNew, err = a.lockedAllocate(key)
		if err == nil {
			a.cache[value] = key
			return value, isNew, nil
		}

		kvstore.Trace("Allocation attempt failed", err, logrus.Fields{fieldKey: key, logfields.Attempt: attempt})
	}

	return 0, false, fmt.Errorf("max allocation attempts reached, last error: %s", err)
}

// Get returns the ID which is allocated to a key. Returns an ID of NoID if no ID
// has been allocated to this key yet.
func (a *Allocator) Get(key AllocatorKey) (ID, error) {
	if !a.skipCache {
		a.mutex.RLock()
		for k, v := range a.cache {
			if v.GetKey() == key.GetKey() {
				a.mutex.RUnlock()
				return k, nil
			}
		}
		a.mutex.RUnlock()
	}

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
	if !a.skipCache {
		a.mutex.RLock()
		if v, ok := a.cache[id]; ok {
			a.mutex.RUnlock()
			return v, nil
		}
		a.mutex.RUnlock()
	}

	v, err := kvstore.Get(path.Join(a.idPrefix, id.String()))
	if err != nil {
		return nil, err
	}

	return a.keyType.PutKey(string(v))
}

// Release releases the use of an ID associated with the provided key. After
// the last user has released the ID, the key is removed in the KVstore.
func (a *Allocator) Release(key AllocatorKey) error {
	k := key.GetKey()
	// release the key locally, if it was the last use, remove the node
	// specific value key to remove the global reference mark
	lastUse, err := a.localKeys.release(k)
	if err != nil {
		return err
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

	return nil
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

type waitChan chan bool

func (a *Allocator) startWatch() waitChan {
	a.Events = make(AllocatorEventChan, 1024)
	a.idWatcherStop = make(chan struct{}, 0)

	successChan := make(waitChan)

	go func(a *Allocator) {
		watcher := kvstore.ListAndWatch(a.idPrefix, a.idPrefix, 512)

		for {
			select {
			case event := <-watcher.Events:
				if event.Typ == kvstore.EventTypeListDone {
					// report that the list
					// operation has been completed
					// and the allocator is ready
					// to use
					successChan <- true
					continue
				}

				id := a.keyToID(event.Key, true)
				if id != 0 {
					a.mutex.Lock()

					var key AllocatorKey

					if len(event.Value) > 0 {
						var err error
						key, err = a.keyType.PutKey(string(event.Value))
						if err != nil {
							log.WithError(err).WithFields(logrus.Fields{fieldKey: event.Value}).
								Warning("Unable to unmarshal allocator key")
						}
					}

					switch event.Typ {
					case kvstore.EventTypeCreate, kvstore.EventTypeModify:
						kvstore.Trace("Adding id to cache", nil, logrus.Fields{fieldKey: key, fieldID: id})
						a.cache[id] = key
					case kvstore.EventTypeDelete:
						kvstore.Trace("Removing id from cache", nil, logrus.Fields{fieldID: id})
						delete(a.cache, id)
					}
					a.mutex.Unlock()

					a.Events <- AllocatorEvent{
						Typ: event.Typ,
						ID:  ID(id),
						Key: key,
					}
				}

			case <-a.idWatcherStop:
				watcher.Stop()
				return
			}
		}
	}(a)

	return successChan
}

func (a *Allocator) stopWatch() {
	if a.Events != nil {
		close(a.Events)
		close(a.idWatcherStop)
	}
}
