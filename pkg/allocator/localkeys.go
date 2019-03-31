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
	"fmt"

	"github.com/cilium/cilium/pkg/idpool"
	"github.com/cilium/cilium/pkg/kvstore"
	"github.com/cilium/cilium/pkg/lock"

	"github.com/sirupsen/logrus"
)

type localKey struct {
	val    idpool.ID
	key    AllocatorKey
	refcnt uint64

	// verified is true when the key has been synced with the kvstore
	verified bool
}

// localKeys is a map of keys in use locally. Keys can be used multiple times.
// A refcnt is managed to know when a key is no longer in use
type localKeys struct {
	lock.RWMutex
	keys map[string]*localKey
	ids  map[idpool.ID]*localKey
}

func newLocalKeys() *localKeys {
	return &localKeys{
		keys: map[string]*localKey{},
		ids:  map[idpool.ID]*localKey{},
	}
}

// allocate creates an entry for key in localKeys if needed and increments the
// refcnt. The value associated with the key must match the local cache or an
// error is returned
func (lk *localKeys) allocate(keyString string, key AllocatorKey, val idpool.ID) (idpool.ID, error) {
	lk.Lock()
	defer lk.Unlock()

	if k, ok := lk.keys[keyString]; ok {
		if val != k.val {
			return idpool.NoID, fmt.Errorf("local key already allocated with different value (%s != %s)", val, k.val)
		}

		k.refcnt++
		kvstore.Trace("Incremented local key refcnt", nil, logrus.Fields{fieldKey: keyString, fieldID: val, fieldRefCnt: k.refcnt})
		return k.val, nil
	}

	k := &localKey{key: key, val: val, refcnt: 1}
	lk.keys[keyString] = k
	lk.ids[val] = k
	kvstore.Trace("New local key", nil, logrus.Fields{fieldKey: keyString, fieldID: val, fieldRefCnt: 1})
	return val, nil
}

func (lk *localKeys) verify(key string) error {
	lk.Lock()
	defer lk.Unlock()

	if k, ok := lk.keys[key]; ok {
		k.verified = true
		kvstore.Trace("Local key verified", nil, logrus.Fields{fieldKey: key})
		return nil
	}

	return fmt.Errorf("key %s not found", key)
}

// lookupKey returns the idpool.ID of the key is present in the map of keys.
// if it isn't present, returns idpool.NoID
func (lk *localKeys) lookupKey(key string) idpool.ID {
	lk.RLock()
	defer lk.RUnlock()

	if k, ok := lk.keys[key]; ok {
		return k.val
	}

	return idpool.NoID
}

// lookupID returns the key for a given ID or an empty string
func (lk *localKeys) lookupID(id idpool.ID) AllocatorKey {
	lk.RLock()
	defer lk.RUnlock()

	if k, ok := lk.ids[id]; ok {
		return k.key
	}

	return nil
}

// use increments the refcnt of the key and returns its value
func (lk *localKeys) use(key string) idpool.ID {
	lk.Lock()
	defer lk.Unlock()

	if k, ok := lk.keys[key]; ok {
		// unverified keys behave as if they do not exist
		if !k.verified {
			return idpool.NoID
		}

		k.refcnt++
		kvstore.Trace("Incremented local key refcnt", nil, logrus.Fields{fieldKey: key, fieldID: k.val, fieldRefCnt: k.refcnt})
		return k.val
	}

	return idpool.NoID
}

// release releases the refcnt of a key. When the last reference was released,
// the key is deleted and the returned lastUse value is true.
func (lk *localKeys) release(key string) (lastUse bool, err error) {
	lk.Lock()
	defer lk.Unlock()
	if k, ok := lk.keys[key]; ok {
		k.refcnt--
		kvstore.Trace("Decremented local key refcnt", nil, logrus.Fields{fieldKey: key, fieldID: k.val, fieldRefCnt: k.refcnt})
		if k.refcnt == 0 {
			delete(lk.keys, key)
			delete(lk.ids, k.val)
			return true, nil
		}

		return false, nil
	}

	return false, fmt.Errorf("unable to find key in local cache")
}

func (lk *localKeys) getVerifiedIDs() map[idpool.ID]AllocatorKey {
	ids := map[idpool.ID]AllocatorKey{}
	lk.RLock()
	for id, localKey := range lk.ids {
		if localKey.verified {
			ids[id] = localKey.key
		}
	}
	lk.RUnlock()

	return ids
}
