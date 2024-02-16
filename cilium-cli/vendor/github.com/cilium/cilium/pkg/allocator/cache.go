// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package allocator

import (
	"context"
	"sync"

	"github.com/sirupsen/logrus"

	"github.com/cilium/cilium/pkg/controller"
	"github.com/cilium/cilium/pkg/idpool"
	"github.com/cilium/cilium/pkg/kvstore"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/stream"
	"github.com/cilium/cilium/pkg/time"
)

// backendOpTimeout is the time allowed for operations sent to backends in
// response to events such as create/modify/delete.
const backendOpTimeout = 10 * time.Second

// idMap provides mapping from ID to an AllocatorKey
type idMap map[idpool.ID]AllocatorKey

// keyMap provides mapping from AllocatorKey to ID
type keyMap map[string]idpool.ID

type cache struct {
	controllers *controller.Manager

	allocator *Allocator

	stopChan chan struct{}

	// mutex protects all cache data structures
	mutex lock.RWMutex

	// cache is a local cache of all IDs allocated in the kvstore. It is
	// being maintained by watching for kvstore events and can thus lag
	// behind.
	cache idMap

	// keyCache shadows cache and allows access by key
	keyCache keyMap

	// nextCache is the cache is constantly being filled by startWatch(),
	// when startWatch has successfully performed the initial fill using
	// ListPrefix, the cache above will be pointed to nextCache. If the
	// startWatch() fails to perform the initial list, then the cache is
	// never pointed to nextCache. This guarantees that a valid cache is
	// kept at all times.
	nextCache idMap

	// nextKeyCache follows the same logic as nextCache but for keyCache
	nextKeyCache keyMap

	listDone waitChan

	// stopWatchWg is a wait group that gets conditions added when a
	// watcher is started with the conditions marked as done when the
	// watcher has exited
	stopWatchWg sync.WaitGroup

	changeSrc         stream.Observable[AllocatorChange]
	emitChange        func(AllocatorChange)
	completeChangeSrc func(error)
}

func newCache(a *Allocator) (c cache) {
	c = cache{
		allocator:   a,
		cache:       idMap{},
		keyCache:    keyMap{},
		stopChan:    make(chan struct{}),
		controllers: controller.NewManager(),
	}
	c.changeSrc, c.emitChange, c.completeChangeSrc = stream.Multicast[AllocatorChange]()
	return
}

type waitChan chan struct{}

// CacheMutations are the operations given to a Backend's ListAndWatch command.
// They are called on changes to identities.
type CacheMutations interface {
	// OnListDone is called when the initial full-sync is complete.
	OnListDone()

	// OnAdd is called when a new key->ID appears.
	OnAdd(id idpool.ID, key AllocatorKey)

	// OnModify is called when a key->ID mapping is modified. This may happen
	// when leases are updated, and does not mean the actual mapping had changed.
	OnModify(id idpool.ID, key AllocatorKey)

	// OnDelete is called when a key->ID mapping is removed. This may trigger
	// master-key protection, if enabled, where the local allocator will recreate
	// the key->ID association is recreated because the local node is still using
	// it.
	OnDelete(id idpool.ID, key AllocatorKey)
}

func (c *cache) sendEvent(typ kvstore.EventType, id idpool.ID, key AllocatorKey) {
	if events := c.allocator.events; events != nil {
		events <- AllocatorEvent{Typ: typ, ID: id, Key: key}
	}
}

func (c *cache) OnListDone() {
	c.mutex.Lock()
	// nextCache is valid, point the live cache to it
	c.cache = c.nextCache
	c.keyCache = c.nextKeyCache
	c.mutex.Unlock()

	log.Debug("Initial list of identities received")

	// report that the list operation has
	// been completed and the allocator is
	// ready to use
	close(c.listDone)
}

func (c *cache) OnAdd(id idpool.ID, key AllocatorKey) {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	c.nextCache[id] = key
	if key != nil {
		c.nextKeyCache[c.allocator.encodeKey(key)] = id
	}
	c.allocator.idPool.Remove(id)

	c.emitChange(AllocatorChange{Kind: AllocatorChangeUpsert, ID: id, Key: key})

	c.sendEvent(kvstore.EventTypeCreate, id, key)
}

func (c *cache) OnModify(id idpool.ID, key AllocatorKey) {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	if k, ok := c.nextCache[id]; ok {
		delete(c.nextKeyCache, c.allocator.encodeKey(k))
	}

	c.nextCache[id] = key
	if key != nil {
		c.nextKeyCache[c.allocator.encodeKey(key)] = id
	}

	c.emitChange(AllocatorChange{Kind: AllocatorChangeUpsert, ID: id, Key: key})

	c.sendEvent(kvstore.EventTypeModify, id, key)
}

func (c *cache) OnDelete(id idpool.ID, key AllocatorKey) {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	c.onDeleteLocked(id, key, true)
}

const syncIdentityControllerGroup = "sync-identity"

func syncControllerName(id idpool.ID) string {
	return syncIdentityControllerGroup + "-" + id.String()
}

// no max interval by default, exposed as a variable for testing.
var masterKeyRecreateMaxInterval = time.Duration(0)

var syncIdentityGroup = controller.NewGroup(syncIdentityControllerGroup)

// onDeleteLocked must be called while holding c.Mutex for writing
func (c *cache) onDeleteLocked(id idpool.ID, key AllocatorKey, recreateMissingLocalKeys bool) {
	a := c.allocator
	if a.enableMasterKeyProtection && recreateMissingLocalKeys {
		if value := a.localKeys.lookupID(id); value != nil {
			c.controllers.UpdateController(syncControllerName(id), controller.ControllerParams{
				Context:          context.Background(),
				MaxRetryInterval: masterKeyRecreateMaxInterval,
				Group:            syncIdentityGroup,
				DoFunc: func(ctx context.Context) error {
					c.mutex.Lock()
					defer c.mutex.Unlock()
					// For each attempt, check if this ciliumidentity is still a candidate for recreation.
					// It's possible that since the last iteration that this agent has legitimately deleted
					// the key, in which case we can stop trying to recreate it.
					if value := c.allocator.localKeys.lookupID(id); value == nil {
						return nil
					}

					ctx, cancel := context.WithTimeout(ctx, backendOpTimeout)
					defer cancel()

					// Each iteration will attempt to grab the key reference, if that succeeds
					// then this completes (i.e. the key exists).
					// Otherwise we will attempt to create the key, this process repeats until
					// the key is created.
					if err := a.backend.UpdateKey(ctx, id, value, true); err != nil {
						log.WithField("id", id).WithError(err).Error("OnDelete MasterKeyProtection update for key")
						return err
					}
					log.WithField("id", id).Info("OnDelete MasterKeyProtection update succeeded")
					return nil
				},
			})

			return
		}
	}

	if k, ok := c.nextCache[id]; ok && k != nil {
		delete(c.nextKeyCache, c.allocator.encodeKey(k))
	}

	delete(c.nextCache, id)
	a.idPool.Insert(id)

	c.emitChange(AllocatorChange{Kind: AllocatorChangeDelete, ID: id, Key: key})

	c.sendEvent(kvstore.EventTypeDelete, id, key)
}

// start requests a LIST operation from the kvstore and starts watching the
// prefix in a go subroutine.
func (c *cache) start() waitChan {
	c.listDone = make(waitChan)

	c.mutex.Lock()

	// start with a fresh nextCache
	c.nextCache = idMap{}
	c.nextKeyCache = keyMap{}
	c.mutex.Unlock()

	c.stopWatchWg.Add(1)

	go func() {
		c.allocator.backend.ListAndWatch(context.TODO(), c, c.stopChan)
		c.stopWatchWg.Done()
	}()

	return c.listDone
}

func (c *cache) stop() {
	close(c.stopChan)
	c.stopWatchWg.Wait()
	// Drain/stop any remaining sync identity controllers.
	// Backend watch is now stopped, any running controllers attempting to
	// sync identities will complete and stop (possibly in a unresolved state).
	c.controllers.RemoveAllAndWait()
	c.completeChangeSrc(nil)
}

// drain emits a deletion event for all known IDs. It must be called after the
// cache has been stopped, to ensure that no new events can be received afterwards.
func (c *cache) drain() {
	// Make sure we wait until the watch loop has been properly stopped.
	c.stopWatchWg.Wait()

	c.mutex.Lock()
	for id, key := range c.nextCache {
		c.onDeleteLocked(id, key, false)
	}
	c.mutex.Unlock()
}

// drainIf emits a deletion event for all known IDs that are stale according to
// the isStale function. It must be called after the cache has been stopped, to
// ensure that no new events can be received afterwards.
func (c *cache) drainIf(isStale func(id idpool.ID) bool) {
	// Make sure we wait until the watch loop has been properly stopped, otherwise
	// new IDs might be added afterwards we complete the draining process.
	c.stopWatchWg.Wait()

	c.mutex.Lock()
	for id, key := range c.nextCache {
		if isStale(id) {
			c.onDeleteLocked(id, key, false)
			log.WithFields(logrus.Fields{fieldID: id, fieldKey: key}).
				Debug("Stale identity deleted")
		}
	}
	c.mutex.Unlock()
}

func (c *cache) get(key string) idpool.ID {
	c.mutex.RLock()
	if id, ok := c.keyCache[key]; ok {
		c.mutex.RUnlock()
		return id
	}
	c.mutex.RUnlock()

	return idpool.NoID
}

func (c *cache) getByID(id idpool.ID) AllocatorKey {
	c.mutex.RLock()
	if v, ok := c.cache[id]; ok {
		c.mutex.RUnlock()
		return v
	}
	c.mutex.RUnlock()

	return nil
}

func (c *cache) foreach(cb RangeFunc) {
	c.mutex.RLock()
	for k, v := range c.cache {
		cb(k, v)
	}
	c.mutex.RUnlock()
}

func (c *cache) insert(key AllocatorKey, val idpool.ID) {
	c.mutex.Lock()
	c.nextCache[val] = key
	c.nextKeyCache[c.allocator.encodeKey(key)] = val
	c.mutex.Unlock()
}

func (c *cache) numEntries() int {
	c.mutex.RLock()
	defer c.mutex.RUnlock()
	return len(c.nextCache)
}

type AllocatorChangeKind string

const (
	AllocatorChangeSync   AllocatorChangeKind = "sync"
	AllocatorChangeUpsert AllocatorChangeKind = "upsert"
	AllocatorChangeDelete AllocatorChangeKind = "delete"
)

type AllocatorChange struct {
	Kind AllocatorChangeKind
	ID   idpool.ID
	Key  AllocatorKey
}

// Observe the allocator changes. Conforms to stream.Observable.
// Replays the current state of the cache when subscribing.
func (c *cache) Observe(ctx context.Context, next func(AllocatorChange), complete func(error)) {
	// This short-lived go routine serves the purpose of replaying the current state of the cache before starting
	// to observe the actual source changeSrc. ChangeSrc is backed by a stream.FuncObservable, that will start its own
	// go routine. Therefore, the current go routine will stop and free the lock on the mutex after the registration.
	go func() {
		// Wait until initial listing has completed before
		// replaying the state.
		select {
		case <-c.listDone:
		case <-ctx.Done():
			complete(ctx.Err())
			return
		}

		c.mutex.RLock()
		defer c.mutex.RUnlock()

		for id, key := range c.cache {
			next(AllocatorChange{Kind: AllocatorChangeUpsert, ID: id, Key: key})
		}

		// Emit a sync event to inform the subscriber that it has received a consistent
		// initial state.
		next(AllocatorChange{Kind: AllocatorChangeSync})

		// And subscribe to new events. Since we held the read-lock there won't be any
		// missed or duplicate events.
		c.changeSrc.Observe(ctx, next, complete)
	}()

}
