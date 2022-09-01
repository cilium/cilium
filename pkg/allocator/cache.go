// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package allocator

import (
	"context"
	"sync"
	"time"

	"github.com/cilium/cilium/pkg/idpool"
	"github.com/cilium/cilium/pkg/kvstore"
	"github.com/cilium/cilium/pkg/lock"
)

// backendOpTimeout is the time allowed for operations sent to backends in
// response to events such as create/modify/delete.
const backendOpTimeout = 10 * time.Second

// idMap provides mapping from ID to an AllocatorKey
type idMap map[idpool.ID]AllocatorKey

// keyMap provides mapping from AllocatorKey to ID
type keyMap map[string]idpool.ID

type cache struct {
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
}

func newCache(a *Allocator) cache {
	return cache{
		allocator: a,
		cache:     idMap{},
		keyCache:  keyMap{},
		stopChan:  make(chan struct{}),
	}
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

	c.sendEvent(kvstore.EventTypeModify, id, key)
}

func (c *cache) OnDelete(id idpool.ID, key AllocatorKey) {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	a := c.allocator
	if a.enableMasterKeyProtection {
		if value := a.localKeys.lookupID(id); value != nil {
			ctx, cancel := context.WithTimeout(context.TODO(), backendOpTimeout)
			defer cancel()
			err := a.backend.UpdateKey(ctx, id, value, true)
			if err != nil {
				log.WithError(err).Errorf("OnDelete MasterKeyProtection update for key %q", id)
			}
			return
		}
	}

	if k, ok := c.nextCache[id]; ok && k != nil {
		delete(c.nextKeyCache, c.allocator.encodeKey(k))
	}

	delete(c.nextCache, id)
	a.idPool.Insert(id)

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
