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

package lbmap

import (
	"fmt"

	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/lock"
)

type serviceValueMap map[BackendAddrID]ServiceValue

type bpfBackend struct {
	id       BackendAddrID
	isHole   bool
	bpfValue ServiceValue
}

type bpfService struct {
	// mutex protects access to all members of bpfService
	mutex lock.RWMutex

	frontendKey ServiceKey

	// backendsByMapIndex is the 1:1 representation of service backends as
	// written into the BPF map. As service backends are scaled up or down,
	// duplicate entries may be required to avoid moving backends to
	// different map index slots. This map represents this and thus may
	// contain duplicate backend entries in different map index slots.
	backendsByMapIndex map[int]*bpfBackend

	// uniqueBackends is a map of all service backends indexed by service
	// backend ID. A backend may be listed multiple times in
	// backendsByMapIndex, it will only be listed once in uniqueBackends.
	uniqueBackends serviceValueMap

	// slaveSlotByBackendAddrID is a map of slot numbers within the legacy
	// service of slaves which are identified by the legacy ID. Used to
	// map legacy svc backends by svc v2 for the backward compatibility.
	slaveSlotByBackendAddrID map[BackendAddrID]int

	// backendsV2 is a map of all service v2 backends indexed by the legacy IDs.
	// A backend can only be listed once in the map.
	// TODO(brb) use list instead to preserve the ordering when svc backends change.
	backendsV2 map[BackendAddrID]ServiceValue
}

func newBpfService(key ServiceKey) *bpfService {
	return &bpfService{
		frontendKey:              key,
		backendsByMapIndex:       map[int]*bpfBackend{},
		uniqueBackends:           map[BackendAddrID]ServiceValue{},
		slaveSlotByBackendAddrID: map[BackendAddrID]int{},
		backendsV2:               map[BackendAddrID]ServiceValue{},
	}
}

func (b *bpfService) addBackend(backend ServiceValue) int {
	b.mutex.Lock()
	defer b.mutex.Unlock()

	nextSlot := len(b.backendsByMapIndex) + 1
	b.backendsByMapIndex[nextSlot] = &bpfBackend{
		bpfValue: backend,
		id:       backend.BackendAddrID(),
	}

	b.uniqueBackends[backend.BackendAddrID()] = backend

	return nextSlot
}

func (b *bpfService) deleteBackend(backend ServiceValue) {
	b.mutex.Lock()
	defer b.mutex.Unlock()

	idToRemove := backend.BackendAddrID()
	indicesToRemove := []int{}
	duplicateCount := map[BackendAddrID]int{}

	for index, backend := range b.backendsByMapIndex {
		// create a slice of all backend indices that match the backend
		// ID (ip, port, revnat id)
		if idToRemove == backend.id {
			indicesToRemove = append(indicesToRemove, index)
		} else {
			duplicateCount[backend.id]++
		}
	}

	// select the backend with the most duplicates that is not the backend
	var lowestCount int
	var fillBackendID BackendAddrID
	for backendID, count := range duplicateCount {
		if lowestCount == 0 || count < lowestCount {
			lowestCount = count
			fillBackendID = backendID
		}
	}

	if fillBackendID == "" {
		// No more entries to fill in, we can remove all backend slots
		b.backendsByMapIndex = map[int]*bpfBackend{}
	} else {
		fillBackend := &bpfBackend{
			id:       fillBackendID,
			isHole:   true,
			bpfValue: b.uniqueBackends[fillBackendID],
		}
		for _, removeIndex := range indicesToRemove {
			b.backendsByMapIndex[removeIndex] = fillBackend
		}
	}

	delete(b.uniqueBackends, idToRemove)
	delete(b.slaveSlotByBackendAddrID, backend.BackendAddrID())
}

func (b *bpfService) getBackends() []ServiceValue {
	b.mutex.RLock()
	backends := make([]ServiceValue, len(b.backendsByMapIndex))
	dstIndex := 0
	for i := 1; i <= len(b.backendsByMapIndex); i++ {
		if b.backendsByMapIndex[i] == nil {
			log.Errorf("BUG: hole found in backendsByMapIndex: %#v", b.backendsByMapIndex)
			continue
		}

		backends[dstIndex] = b.backendsByMapIndex[i].bpfValue
		dstIndex++
	}
	b.mutex.RUnlock()
	return backends
}

// getSlaveSlot returns a slot number (lb{4,6}_key.slave) in the given service.
// The slot number points to any backend identified by the addr ID in the
// legacy service.
//
// As the legacy svc maps are append-only, we can point to any slot number
// in the v2 svc.
func (b *bpfService) getSlaveSlot(id BackendAddrID) (int, bool) {
	b.mutex.RLock()
	defer b.mutex.RUnlock()

	slot, found := b.slaveSlotByBackendAddrID[id]
	return slot, found
}

type lbmapCache struct {
	mutex             lock.Mutex
	entries           map[string]*bpfService
	backendRefCount   map[BackendAddrID]int
	backendIDByAddrID map[BackendAddrID]uint16
}

func newLBMapCache() lbmapCache {
	return lbmapCache{
		entries:           map[string]*bpfService{},
		backendRefCount:   map[BackendAddrID]int{},
		backendIDByAddrID: map[BackendAddrID]uint16{},
	}
}

func createBackendsMap(backends []ServiceValue) serviceValueMap {
	m := serviceValueMap{}
	for _, b := range backends {
		m[b.BackendAddrID()] = b
	}
	return m
}

// restoreService restores service cache of the given legacy svc. If v2Exists
// is set, the cache for the respective svc v2 is restored as well.
func (l *lbmapCache) restoreService(svc loadbalancer.LBSVC, v2Exists bool) error {
	l.mutex.Lock()
	defer l.mutex.Unlock()

	serviceKey, serviceValues, err := LBSVC2ServiceKeynValue(svc)
	if err != nil {
		return err
	}

	frontendID := serviceKey.String()

	bpfSvc, ok := l.entries[frontendID]
	if !ok {
		bpfSvc = newBpfService(serviceKey)
		l.entries[frontendID] = bpfSvc
	}

	for index, backend := range serviceValues {
		b := &bpfBackend{
			id:       backend.BackendAddrID(),
			bpfValue: backend,
		}
		if _, ok := bpfSvc.uniqueBackends[backend.BackendAddrID()]; ok {
			b.isHole = true
		} else {
			bpfSvc.uniqueBackends[backend.BackendAddrID()] = backend
			bpfSvc.slaveSlotByBackendAddrID[backend.BackendAddrID()] = index + 1
		}

		bpfSvc.backendsByMapIndex[index+1] = b
	}

	if v2Exists {
		for addrID, backend := range bpfSvc.uniqueBackends {
			bpfSvc.backendsV2[addrID] = backend
			l.addBackendV2Locked(addrID)
		}
	}

	return nil
}

// prepareUpdate prepares the caches to reflect the changes in the given svc.
// The given backends should not contain a service value of a master service.
func (l *lbmapCache) prepareUpdate(fe ServiceKey, backends []ServiceValue) (
	*bpfService, map[uint16]ServiceValue, []uint16, error) {

	l.mutex.Lock()
	defer l.mutex.Unlock()

	frontendID := fe.String()

	bpfSvc, ok := l.entries[frontendID]
	if !ok {
		bpfSvc = newBpfService(fe)
		l.entries[frontendID] = bpfSvc
	}

	newBackendsMap := createBackendsMap(backends)
	toRemoveBackendIDs := []uint16{}
	toAddBackendIDs := map[uint16]ServiceValue{}

	// Step 1: Delete all backends that no longer exist. This will not
	// actually remove the backends but overwrite all slave slots that
	// point to the removed backend with the backend that has the least
	// duplicated slots.
	for addrID, b := range bpfSvc.uniqueBackends {
		if _, ok := newBackendsMap[addrID]; !ok {
			bpfSvc.deleteBackend(b)
			delete(bpfSvc.slaveSlotByBackendAddrID, addrID)
		}
	}
	// Step 2: Delete all backends that no longer exist in the service v2.
	for addrID := range bpfSvc.backendsV2 {
		if _, ok := newBackendsMap[addrID]; !ok {
			isLastInstanceRemoved, err := l.delBackendV2Locked(addrID)
			if err != nil {
				return nil, nil, nil, err
			}
			if isLastInstanceRemoved {
				toRemoveBackendIDs = append(toRemoveBackendIDs,
					l.backendIDByAddrID[addrID])
				delete(l.backendIDByAddrID, addrID)
			}
			delete(bpfSvc.backendsV2, addrID)
		}
	}

	// Step 3: Add all backends that don't exist in the legacy service yet.
	for _, b := range backends {
		if _, ok := bpfSvc.uniqueBackends[b.BackendAddrID()]; !ok {
			addrID := b.BackendAddrID()
			pos := bpfSvc.addBackend(b)
			bpfSvc.slaveSlotByBackendAddrID[addrID] = pos
		}
	}
	// Step 4: Add all backends that don't exist in the service v2 yet.
	for _, b := range backends {
		addrID := b.BackendAddrID()
		if _, ok := bpfSvc.backendsV2[addrID]; !ok {
			bpfSvc.backendsV2[addrID] = b
			isNew := l.addBackendV2Locked(addrID)
			if isNew {
				toAddBackendIDs[l.backendIDByAddrID[addrID]] = b
			}
		}
	}

	return bpfSvc, toAddBackendIDs, toRemoveBackendIDs, nil
}

func (l *lbmapCache) delete(fe ServiceKey) {
	l.mutex.Lock()
	delete(l.entries, fe.String())
	l.mutex.Unlock()
}

func (l *lbmapCache) getSlaveSlot(fe ServiceKeyV2, addrID BackendAddrID) (int, bool) {
	l.mutex.Lock()
	defer l.mutex.Unlock()

	frontendID := fe.String()
	bpfSvc, found := l.entries[frontendID]
	if !found {
		return 0, false
	}

	pos, found := bpfSvc.slaveSlotByBackendAddrID[addrID]
	if !found {
		return 0, false
	}

	return pos, true
}

// addBackendV2Locked increments a ref count for the given backend and returns
// whether any instance of the backend existed before.
func (l *lbmapCache) addBackendV2Locked(addrID BackendAddrID) bool {
	l.backendRefCount[addrID]++
	return l.backendRefCount[addrID] == 1
}

// delBackendV2Locked decrements a ref count for the given backend aand returns
// whether there are any instance of the backend left.
func (l *lbmapCache) delBackendV2Locked(addrID BackendAddrID) (bool, error) {
	count, found := l.backendRefCount[addrID]
	if !found {
		return false, fmt.Errorf("backend %s not found", addrID)
	}

	if count == 1 {
		delete(l.backendRefCount, addrID)
		return true, nil
	}

	l.backendRefCount[addrID]--
	return false, nil
}

func (l *lbmapCache) addBackendIDs(backendIDs map[BackendAddrID]uint16) {
	l.mutex.Lock()
	defer l.mutex.Unlock()

	for addrID, backendID := range backendIDs {
		l.backendIDByAddrID[addrID] = backendID
	}
}

// filterNewBackends filters out backends which already exists from the given
// map (i.e. keeps only new backends).
func (l *lbmapCache) filterNewBackends(backends map[BackendAddrID]ServiceValue) map[BackendAddrID]ServiceValue {

	l.mutex.Lock()
	defer l.mutex.Unlock()

	newBackends := map[BackendAddrID]ServiceValue{}

	for addrID, b := range backends {
		if _, found := l.backendIDByAddrID[addrID]; !found {
			newBackends[addrID] = b
		}
	}

	return newBackends
}

func (l *lbmapCache) getBackendIDByAddrID(addrID BackendAddrID) uint16 {
	l.mutex.Lock()
	defer l.mutex.Unlock()

	return l.backendIDByAddrID[addrID]
}
