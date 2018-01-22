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

	"github.com/cilium/cilium/pkg/kvstore"
	"github.com/cilium/cilium/pkg/lock"

	"github.com/sirupsen/logrus"
)

type localKey struct {
	val    ID
	refcnt uint64
}

type localKeyMap map[string]*localKey

// localKeys is a map of keys in use locally. Keys can be used multiple times.
// A refcnt is managed to know when a key is no longer in use
type localKeys struct {
	lock.RWMutex
	keys localKeyMap
}

func newLocalKeys() *localKeys {
	return &localKeys{keys: localKeyMap{}}
}

// allocate creates an entry for key in localKeys if needed and increments the
// refcnt. The value associated with the key must match the local cache or an
// error is returned
func (lk *localKeys) allocate(key string, val ID) (ID, error) {
	lk.Lock()
	defer lk.Unlock()

	if k, ok := lk.keys[key]; ok {
		if val != k.val {
			return NoID, fmt.Errorf("local key already allocated with different value (%s != %s)", val, k.val)
		}

		k.refcnt++
		kvstore.Trace("Incremented local key refcnt", nil, logrus.Fields{fieldKey: key, fieldID: val, fieldRefCnt: k.refcnt})
		return k.val, nil
	}

	lk.keys[key] = &localKey{val: val, refcnt: 1}
	kvstore.Trace("New local key", nil, logrus.Fields{fieldKey: key, fieldID: val, fieldRefCnt: 1})
	return val, nil
}

// lookupID returns the key for a given ID or an empty string
func (lk *localKeys) lookupID(id ID) string {
	lk.RLock()
	defer lk.RUnlock()

	for k, v := range lk.keys {
		if v.val == id {
			return k
		}
	}

	return ""
}

// use increments the refcnt of the key and returns its value
func (lk *localKeys) use(key string) ID {
	lk.Lock()
	defer lk.Unlock()

	if k, ok := lk.keys[key]; ok {
		k.refcnt++
		kvstore.Trace("Incremented local key refcnt", nil, logrus.Fields{fieldKey: key, fieldID: k.val, fieldRefCnt: k.refcnt})
		return k.val
	}

	return NoID
}

// release releases the refcnt of a key. When the last reference was released,
// the key is deleted
func (lk *localKeys) release(key string) (bool, error) {
	lk.Lock()
	defer lk.Unlock()
	if k, ok := lk.keys[key]; ok {
		k.refcnt--
		kvstore.Trace("Decremented local key refcnt", nil, logrus.Fields{fieldKey: key, fieldID: k.val, fieldRefCnt: k.refcnt})
		if k.refcnt == 0 {
			delete(lk.keys, key)
			return true, nil
		}

		return false, nil
	}

	return false, fmt.Errorf("unable to find key")
}
