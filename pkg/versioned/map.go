// Copyright 2018 Authors of Cilium
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

package versioned

import (
	"github.com/cilium/cilium/pkg/lock"
)

// UUID is the UUID for the object that is going to be stored in the map.
type UUID string

// Map maps a UUID to an Object.
type Map map[UUID]Object

// NewMap returns an initialized Map.
func NewMap() Map {
	return make(Map)
}

// Add maps the uuid to the given obj.
func (m Map) Add(uuid UUID, obj Object) {
	m[uuid] = obj
}

// Delete deletes the value that maps uuid in the map. Returns true or false
// if the object existed in the map before deletion.
func (m Map) Delete(uuid UUID) bool {
	_, exists := m[uuid]
	if exists {
		delete(m, uuid)
	}
	return exists
}

// Get returns the object that maps to the given uuid and returns true or false
// either the object exists or not.
func (m Map) Get(uuid UUID) (Object, bool) {
	o, exists := m[uuid]
	return o, exists
}

// DeepEqualFunc should return true or false if both interfaces `o1` and `o2`
// are considered equal.
type DeepEqualFunc func(o1, o2 interface{}) bool

// ComparableMap is a map that can store Objects that are comparable between
// each other.
type ComparableMap struct {
	Map
	DeepEquals DeepEqualFunc
}

// NewComparableMap returns an initialized map with the equalFunc set as the
// DeepEquals of the map.
func NewComparableMap(equalFunc DeepEqualFunc) *ComparableMap {
	return &ComparableMap{
		Map:        NewMap(),
		DeepEquals: equalFunc,
	}
}

// AddEqual maps `uuid` to `newObj` if the object to be inserted has a newer
// Version than the one already mapped in the map. Returns false if the object
// inserted is not mapped yet or if the object has a newer version and
// is not deeply equal to the object already stored.
func (m *ComparableMap) AddEqual(uuid UUID, newObj Object) bool {
	oldObj, ok := m.Map.Get(uuid)
	if ok {
		// small performance optimization where we only add
		// an object if the version is newer than the one we have.
		if newObj.CompareVersion(oldObj) > 0 {
			m.Map.Add(uuid, newObj)
			return m.DeepEquals(oldObj.Data, newObj.Data)
		}
		return true
	}
	m.Map.Add(uuid, newObj)
	return false
}

// SyncComparableMap is a thread-safe wrapper around ComparableMap.
type SyncComparableMap struct {
	mutex *lock.RWMutex
	cm    *ComparableMap
}

// NewSyncComparableMap returns a thread-safe ComparableMap.
func NewSyncComparableMap(def DeepEqualFunc) *SyncComparableMap {
	return &SyncComparableMap{
		mutex: &lock.RWMutex{},
		cm:    NewComparableMap(def),
	}
}

// Add maps the uuid to the given obj without any comparison.
func (sm *SyncComparableMap) Add(uuid UUID, obj Object) {
	sm.mutex.Lock()
	sm.cm.Add(uuid, obj)
	sm.mutex.Unlock()
}

// AddEqual maps `uuid` to `newObj` if the object to be inserted has a newer
// Version than the one already mapped in the map. Returns false if the object
// inserted is not mapped yet or if the object has a newer version and
// is not deeply equal to the object already stored.
func (sm *SyncComparableMap) AddEqual(uuid UUID, obj Object) bool {
	sm.mutex.Lock()
	added := sm.cm.AddEqual(uuid, obj)
	sm.mutex.Unlock()
	return added
}

// Delete deletes the value that maps uuid in the map. Returns true of false
// if the object existed in the map before deletion.
func (sm *SyncComparableMap) Delete(uuid UUID) bool {
	sm.mutex.Lock()
	exists := sm.cm.Delete(uuid)
	sm.mutex.Unlock()
	return exists
}

// Get returns the object that maps to the given uuid and returns true or false
// either the object exists or not.
func (sm *SyncComparableMap) Get(uuid UUID) (Object, bool) {
	sm.mutex.RLock()
	v, e := sm.cm.Get(uuid)
	sm.mutex.RUnlock()
	return v, e
}

// Replace is a thread-safe function that can be used to perform multiple
// operations in the map atomically.
// Parameters:
//  * replace: if not nil, replace is called with the internal ComparableMap,
//    the returned ComparableMap will be set as the new internal ComparableMap.
//    If an error is returned, the replace operation won't take place.
// In case both `iterate` and `replace` are provided, `iterate` is executed
// first and `replace` is executed afterwards.
func (sm *SyncComparableMap) Replace(replace func(old *ComparableMap) (*ComparableMap, error)) error {
	sm.mutex.Lock()
	defer sm.mutex.Unlock()
	if replace != nil {
		newMap, err := replace(sm.cm)
		if err != nil {
			return err
		}
		sm.cm = newMap
	}
	return nil
}
