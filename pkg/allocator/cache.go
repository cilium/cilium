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
	"sync"

	"github.com/cilium/cilium/pkg/idpool"
	"github.com/cilium/cilium/pkg/kvstore"
	"github.com/cilium/cilium/pkg/lock"
)

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

type waitChan chan bool

type CacheMutations interface {
	OnListDone()
	OnAdd(id idpool.ID, key AllocatorKey)
	OnModify(id idpool.ID, key AllocatorKey)
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
		c.nextKeyCache[key.GetKey()] = id
	}
	c.allocator.idPool.Remove(id)

	c.sendEvent(kvstore.EventTypeCreate, id, key)
}

func (c *cache) OnModify(id idpool.ID, key AllocatorKey) {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	if k, ok := c.nextCache[id]; ok {
		delete(c.nextKeyCache, k.GetKey())
	}

	c.nextCache[id] = key
	if key != nil {
		c.nextKeyCache[key.GetKey()] = id
	}

	c.sendEvent(kvstore.EventTypeModify, id, key)
}

func (c *cache) OnDelete(id idpool.ID, key AllocatorKey) {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	a := c.allocator
	if a.enableMasterKeyProtection {
		if value := a.localKeys.lookupID(id); value != nil {
			a.backend.UpdateKey(id, value, true)
			return
		}
	}

	if k, ok := c.nextCache[id]; ok && k != nil {
		delete(c.nextKeyCache, k.GetKey())
	}

	delete(c.nextCache, id)
	a.idPool.Insert(id)

	c.sendEvent(kvstore.EventTypeDelete, id, key)
}

// start requests a LIST operation from the kvstore and starts watching the
// prefix in a go subroutine.
func (c *cache) start(a *Allocator) waitChan {
	c.listDone = make(waitChan)

	c.mutex.Lock()

	// start with a fresh nextCache
	c.nextCache = idMap{}
	c.nextKeyCache = keyMap{}
	c.mutex.Unlock()

	c.stopWatchWg.Add(1)

	go func() {
		c.allocator.backend.ListAndWatch(c, c.stopChan)
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
	c.nextKeyCache[key.GetKey()] = val
	c.mutex.Unlock()
}
