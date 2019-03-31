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
	"strconv"
	"strings"
	"sync"

	"github.com/cilium/cilium/pkg/idpool"
	"github.com/cilium/cilium/pkg/kvstore"
	kvstoreallocator "github.com/cilium/cilium/pkg/kvstore/allocator"
	"github.com/cilium/cilium/pkg/lock"

	"github.com/sirupsen/logrus"
)

// idMap provides mapping from ID to an AllocatorKey
type idMap map[idpool.ID]kvstoreallocator.AllocatorKey

// keyMap provides mapping from AllocatorKey to ID
type keyMap map[string]idpool.ID

type cache struct {
	backend  kvstore.BackendOperations
	prefix   string
	stopChan chan bool

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

	// stopWatchWg is a wait group that gets conditions added when a
	// watcher is started with the conditions marked as done when the
	// watcher has exited
	stopWatchWg sync.WaitGroup

	// deleteInvalid enables deletion of identities outside of the valid
	// prefix
	deleteInvalidPrefixes bool
}

func newCache(backend kvstore.BackendOperations, prefix string) cache {
	return cache{
		backend:  backend,
		prefix:   prefix,
		cache:    idMap{},
		keyCache: keyMap{},
		stopChan: make(chan bool, 1),
	}
}

type waitChan chan bool

func (c *cache) getLogger() *logrus.Entry {
	status, err := c.backend.Status()

	return log.WithFields(logrus.Fields{
		"kvstoreStatus": status,
		"kvstoreErr":    err,
		"prefix":        c.prefix,
	})
}

func invalidKey(key, prefix string, deleteInvalid bool) {
	log.WithFields(logrus.Fields{fieldKey: key, fieldPrefix: prefix}).Warning("Found invalid key outside of prefix")

	if deleteInvalid {
		kvstore.Delete(key)
	}
}

func (c *cache) keyToID(key string, deleteInvalid bool) idpool.ID {
	if !strings.HasPrefix(key, c.prefix) {
		invalidKey(key, c.prefix, deleteInvalid)
		return idpool.NoID
	}

	suffix := strings.TrimPrefix(key, c.prefix)
	if suffix[0] == '/' {
		suffix = suffix[1:]
	}

	id, err := strconv.ParseUint(suffix, 10, 64)
	if err != nil {
		invalidKey(key, c.prefix, deleteInvalid)
		return idpool.NoID
	}

	return idpool.ID(id)
}

// start requests a LIST operation from the kvstore and starts watching the
// prefix in a go subroutine.
func (c *cache) start(a *Allocator) waitChan {
	listDone := make(waitChan)

	c.mutex.Lock()

	// start with a fresh nextCache
	c.nextCache = idMap{}
	c.nextKeyCache = keyMap{}
	c.mutex.Unlock()

	c.stopWatchWg.Add(1)

	go func() {
		<-c.backend.Connected()
		logger := c.getLogger()
		logger.Info("Starting to watch allocation changes")

		watcher := c.backend.ListAndWatch(c.prefix, c.prefix, 512)

		for {
			select {
			case event, ok := <-watcher.Events:
				if !ok {
					goto abort
				}
				if event.Typ == kvstore.EventTypeListDone {
					c.mutex.Lock()
					// nextCache is valid, point the live cache to it
					c.cache = c.nextCache
					c.keyCache = c.nextKeyCache
					c.mutex.Unlock()

					// report that the list operation has
					// been completed and the allocator is
					// ready to use
					close(listDone)
					continue
				}

				id := c.keyToID(event.Key, c.deleteInvalidPrefixes)
				if id != 0 {
					c.mutex.Lock()

					var key kvstoreallocator.AllocatorKey

					if len(event.Value) > 0 {
						var err error
						key, err = a.keyType.PutKey(string(event.Value))
						if err != nil {
							c.getLogger().WithError(err).WithField(fieldKey, event.Value).
								Warning("Unable to unmarshal allocator key")
						}
					}
					debugFields := c.getLogger().WithFields(logrus.Fields{fieldKey: key, fieldID: id})

					switch event.Typ {
					case kvstore.EventTypeCreate:
						kvstore.Trace("Adding id to cache", nil, debugFields.Data)
						c.nextCache[id] = key
						if key != nil {
							c.nextKeyCache[key.GetKey()] = id
						}
						a.idPool.Remove(id)

					case kvstore.EventTypeModify:
						kvstore.Trace("Modifying id in cache", nil, debugFields.Data)
						if k, ok := c.nextCache[id]; ok {
							delete(c.nextKeyCache, k.GetKey())
						}

						c.nextCache[id] = key
						if key != nil {
							c.nextKeyCache[key.GetKey()] = id
						}

					case kvstore.EventTypeDelete:
						kvstore.Trace("Removing id from cache", nil, debugFields.Data)

						if a.enableMasterKeyProtection {
							if value := a.localKeys.lookupID(id); value != "" {
								a.backend.RecreateMasterKey(id, value, true)
								break
							}
						}

						if k, ok := c.nextCache[id]; ok && k != nil {
							delete(c.nextKeyCache, k.GetKey())
						}

						delete(c.nextCache, id)
						a.idPool.Insert(id)
					}
					c.mutex.Unlock()

					if a.events != nil {
						a.events <- AllocatorEvent{
							Typ: event.Typ,
							ID:  idpool.ID(id),
							Key: key,
						}
					}
				}

			case <-c.stopChan:
				goto abort
			}
		}

	abort:
		watcher.Stop()
		// Signal that watcher is done
		c.stopWatchWg.Done()
	}()

	return listDone
}

func (c *cache) stop() {
	select {
	case c.stopChan <- true:
	default:
	}
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

func (c *cache) getByID(id idpool.ID) kvstoreallocator.AllocatorKey {
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

func (c *cache) insert(key kvstoreallocator.AllocatorKey, val idpool.ID) {
	c.mutex.Lock()
	c.nextCache[val] = key
	c.nextKeyCache[key.GetKey()] = val
	c.mutex.Unlock()
}
