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

// Package pkg/k8s/client/clientset keeps the version of a particular structure.
package versioned

import (
	"strconv"

	"github.com/cilium/cilium/pkg/lock"
)

type Object struct {
	Data    interface{}
	Version Version
}

type Version int64

func ParseVersion(s string) Version {
	i, _ := strconv.ParseInt(s, 10, 64)
	return Version(i)
}

type Equals func(o1, o2 interface{}) bool

type UUID string

type Map map[UUID]Object

type EqualsMap struct {
	Map Map
	E   Equals
}

func NewMap(e Equals) *EqualsMap {
	return &EqualsMap{
		Map: map[UUID]Object{},
		E:   e,
	}
}

// Add returns true if the object is equal from the one in the map, false
// otherwise.
func (m EqualsMap) AddEqual(uuid UUID, obj Object) bool {
	oldObj, ok := m.Map[uuid]
	if ok {
		// small performance optimization where we only add
		// an object if the version is newer than the one we have.
		if obj.Version > oldObj.Version {
			m.Map[uuid] = obj
			return m.E(oldObj.Data, obj.Data)
		}
		return true
	} else {
		m.Map[uuid] = obj
		return false
	}
}

// Add returns true if the object was different from the one in the map, false
// otherwise.
func (m Map) Add(uuid UUID, obj Object) {
	m[uuid] = obj
}

func (m Map) Get(uuid UUID) (Object, bool) {
	o, exists := m[uuid]
	return o, exists
}

func (m EqualsMap) Get(uuid UUID) (Object, bool) {
	return m.Map.Get(uuid)
}

func (m EqualsMap) Delete(uuid UUID) bool {
	_, exists := m.Map[uuid]
	if exists {
		delete(m.Map, uuid)
	}
	return exists
}

type SyncMap struct {
	m *EqualsMap
	lock.RWMutex
}

func NewSyncMap(e Equals) *SyncMap {
	return &SyncMap{
		m: NewMap(e),
	}
}

func (sm *SyncMap) Add(uuid UUID, obj Object) {
	sm.Lock()
	sm.m.Map.Add(uuid, obj)
	sm.Unlock()
}

func (sm *SyncMap) AddEqual(uuid UUID, obj Object) bool {
	sm.Lock()
	added := sm.m.AddEqual(uuid, obj)
	sm.Unlock()
	return added
}

func (sm *SyncMap) Delete(uuid UUID) bool {
	sm.Lock()
	exists := sm.m.Delete(uuid)
	sm.Unlock()
	return exists
}

func (sm *SyncMap) Get(uuid UUID) (Object, bool) {
	sm.Lock()
	v, e := sm.m.Get(uuid)
	sm.Unlock()
	return v, e
}

func (sm *SyncMap) DoLocked(i func(key UUID, value Object), replace func(old *EqualsMap) (*EqualsMap, error)) error {
	sm.Lock()
	defer sm.Unlock()
	if i != nil {
		for k, v := range sm.m.Map {
			i(k, v)
		}
	}
	if replace != nil {
		newMap, err := replace(sm.m)
		if err != nil {
			return err
		}
		sm.m = newMap
	}
	return nil
}
