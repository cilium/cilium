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

type serviceValueMap map[string]ServiceValue

type bpfBackend struct {
	id       string
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

	// TODO(brb) comment
	backendPos map[string]int
}

func newBpfService(key ServiceKey) *bpfService {
	return &bpfService{
		frontendKey:        key,
		backendsByMapIndex: map[int]*bpfBackend{},
		uniqueBackends:     map[string]ServiceValue{},
		backendPos:         map[string]int{},
	}
}

func (b *bpfService) addBackend(backend ServiceValue) int {
	b.mutex.Lock()
	defer b.mutex.Unlock()

	nextSlot := len(b.backendsByMapIndex) + 1
	b.backendsByMapIndex[nextSlot] = &bpfBackend{
		bpfValue: backend,
		id:       backend.String(),
	}

	b.uniqueBackends[backend.String()] = backend

	return nextSlot
}

func (b *bpfService) deleteBackend(backend ServiceValue) {
	b.mutex.Lock()
	defer b.mutex.Unlock()

	idToRemove := backend.String()
	indicesToRemove := []int{}
	duplicateCount := map[string]int{}

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
	var fillBackendID string
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

type lbmapCache struct {
	mutex           lock.Mutex
	svcBackendsByID map[string]map[uint16]struct{} // svc ID -> [backend ID]
	backendRefCount map[uint16]int                 // backend ID -> count
	entries         map[string]*bpfService
}

func newLBMapCache() lbmapCache {
	return lbmapCache{
		entries:         map[string]*bpfService{},
		svcBackendsByID: make(map[string]map[uint16]struct{}),
		backendRefCount: map[uint16]int{},
	}
}

func createBackendsMap(backends []ServiceValue) serviceValueMap {
	m := serviceValueMap{}
	for _, b := range backends {
		m[b.String()] = b
	}
	return m
}

func (l *lbmapCache) restoreService(svc loadbalancer.LBSVC) error {
	l.mutex.Lock()
	defer l.mutex.Unlock()

	frontendID := svc.FE.String()

	serviceKey, serviceValues, err := LBSVC2ServiceKeynValue(svc)
	if err != nil {
		return err
	}

	bpfSvc, ok := l.entries[frontendID]
	if !ok {
		bpfSvc = newBpfService(serviceKey)
		l.entries[frontendID] = bpfSvc
	}

	// TODO(brb) backendPos

	for index, backend := range serviceValues {
		b := &bpfBackend{
			id:       backend.String(),
			bpfValue: backend,
		}
		if _, ok := bpfSvc.uniqueBackends[backend.String()]; ok {
			b.isHole = true
		} else {
			bpfSvc.uniqueBackends[backend.String()] = backend
		}

		bpfSvc.backendsByMapIndex[index+1] = b
	}

	return nil
}

func (l *lbmapCache) getLegacyBackendPosition(fe *Service4KeyV2, legacyBackendID string) (int, bool) {
	l.mutex.Lock()
	defer l.mutex.Unlock()

	frontendID := fe.String()
	bpfSvc, found := l.entries[frontendID]
	if !found {
		return 0, false
	}

	pos, found := bpfSvc.backendPos[legacyBackendID]
	if !found {
		return 0, false
	}

	return pos, true
}

func (l *lbmapCache) prepareUpdate(fe ServiceKey, backends []ServiceValue) *bpfService {
	l.mutex.Lock()
	defer l.mutex.Unlock()

	frontendID := fe.String()

	bpfSvc, ok := l.entries[frontendID]
	if !ok {
		bpfSvc = newBpfService(fe)
		l.entries[frontendID] = bpfSvc
	}

	newBackendsMap := createBackendsMap(backends)

	// Step 1: Delete all backends that no longer exist. This will not
	// actually remove the backends but overwrite all slave slots that
	// point to the removed backend with the backend that has the least
	// duplicated slots.
	for key, b := range bpfSvc.uniqueBackends {
		if _, ok := newBackendsMap[key]; !ok {
			bpfSvc.deleteBackend(b)
			delete(bpfSvc.backendPos, b.BackendString())
		}
	}

	// Step 2: Add all backends that don't exist yet.
	for _, b := range backends {
		if _, ok := bpfSvc.uniqueBackends[b.String()]; !ok {
			pos := bpfSvc.addBackend(b)
			bpfSvc.backendPos[b.BackendString()] = pos
		}
	}

	return bpfSvc
}

func (l *lbmapCache) delete(fe ServiceKey) {
	l.mutex.Lock()
	delete(l.entries, fe.String())
	l.mutex.Unlock()
}

// Returns new backend IDs which need to be inserted into the BPF map
// TODO(brb) we need to define svcID type, otherwise someome will make for sure a mistake!
func (l *lbmapCache) addServiceV2(svcID string, backendIDs []uint16) (map[uint16]struct{}, []uint16, error) {
	l.mutex.Lock()
	defer l.mutex.Unlock()

	toAdd := map[uint16]struct{}{}
	toRemove := []uint16{}

	existingBackendIDs, found := l.svcBackendsByID[svcID]
	if !found {
		existingBackendIDs = map[uint16]struct{}{}
		l.svcBackendsByID[svcID] = existingBackendIDs
	}

	backendIDsMap := map[uint16]struct{}{}
	for _, id := range backendIDs {
		backendIDsMap[id] = struct{}{}
		if _, found := existingBackendIDs[id]; !found {
			if add := l.addBackendV2Locked(id); add {
				toAdd[id] = struct{}{}
			}
		}
	}

	for id := range existingBackendIDs {
		if _, found := backendIDsMap[id]; !found {
			removed, err := l.delBackendV2Locked(id)
			if err != nil {
				return nil, nil, err
			}
			if removed {
				toRemove = append(toRemove, id)
			}
		}
	}

	l.svcBackendsByID[svcID] = backendIDsMap

	return toAdd, toRemove, nil
}

func (l *lbmapCache) removeServiceV2(svcID string) (int, []uint16, error) {
	l.mutex.Lock()
	defer l.mutex.Unlock()

	toRemove := []uint16{}

	existingBackendIDs, found := l.svcBackendsByID[svcID]
	if !found {
		// TODO(brb) is it really an error? maybe k8s can be out of sync :/
		return 0, nil, fmt.Errorf("svc not found: %s", svcID)
	}

	count := len(existingBackendIDs)

	for id := range existingBackendIDs {
		remove, err := l.delBackendV2Locked(id)
		if err != nil {
			return 0, nil, err
		}
		if remove {
			toRemove = append(toRemove, id)
		}
	}

	delete(l.svcBackendsByID, svcID)

	return count, toRemove, nil
}

// Returns true if new
func (l *lbmapCache) addBackendV2Locked(id uint16) bool {
	l.backendRefCount[id]++

	return l.backendRefCount[id] == 1
}

func (l *lbmapCache) delBackendV2Locked(id uint16) (bool, error) {
	count, found := l.backendRefCount[id]
	if !found {
		return false, fmt.Errorf("backend %d not found", id)
	}

	if count == 1 {
		delete(l.backendRefCount, id)
		return true, nil
	}

	l.backendRefCount[id]--
	return false, nil
}
