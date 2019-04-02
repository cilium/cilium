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
}

func newBpfService(key ServiceKey) *bpfService {
	return &bpfService{
		frontendKey:        key,
		backendsByMapIndex: map[int]*bpfBackend{},
		uniqueBackends:     map[BackendAddrID]ServiceValue{},
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
	mutex   lock.Mutex
	entries map[string]*bpfService
}

func newLBMapCache() lbmapCache {
	return lbmapCache{
		entries: map[string]*bpfService{},
	}
}

func createBackendsMap(backends []ServiceValue) serviceValueMap {
	m := serviceValueMap{}
	for _, b := range backends {
		m[b.BackendAddrID()] = b
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
		}
	}

	// Step 2: Add all backends that don't exist yet.
	for _, b := range backends {
		if _, ok := bpfSvc.uniqueBackends[b.String()]; !ok {
			bpfSvc.addBackend(b)
		}
	}

	return bpfSvc
}

func (l *lbmapCache) delete(fe ServiceKey) {
	l.mutex.Lock()
	delete(l.entries, fe.String())
	l.mutex.Unlock()
}
