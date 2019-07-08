// Copyright 2018-2019 Authors of Cilium
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
)

// serviceValueMap is a mapping from the Backend (IP:PORT) to its corresponding
// map value.
type serviceValueMap map[BackendAddrID]ServiceValue

type bpfBackend struct {
	id       BackendAddrID
	isHole   bool
	bpfValue ServiceValue
}

type bpfService struct {
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

	// backendsV2 is a map of all service v2 backends indexed by the legacy IDs.
	// A backend can only be listed once in the map.
	// TODO(brb) use list instead to preserve the ordering when svc backends change.
	backendsV2 serviceValueMap
}

func newBpfService(key ServiceKey) *bpfService {
	return &bpfService{
		frontendKey:        key,
		backendsByMapIndex: map[int]*bpfBackend{},
		uniqueBackends:     serviceValueMap{},
		backendsV2:         serviceValueMap{},
	}
}

// getBackendsV2 makes a copy of backendsV2, so that they are safe to use
// after the bpfService lock has been released.
func (b *bpfService) getBackendsV2() serviceValueMap {
	backends := make(serviceValueMap, len(b.backendsV2))
	for addrID, backend := range b.backendsV2 {
		backends[addrID] = backend
	}

	return backends
}

type lbmapCache struct {
	entries           map[string]*bpfService
	backendRefCount   map[BackendAddrID]int
	backendIDByAddrID map[BackendAddrID]BackendKey
}

func newLBMapCache() lbmapCache {
	return lbmapCache{
		entries:           map[string]*bpfService{},
		backendRefCount:   map[BackendAddrID]int{},
		backendIDByAddrID: map[BackendAddrID]BackendKey{},
	}
}

func createBackendsMap(backends []ServiceValue) serviceValueMap {
	m := serviceValueMap{}
	for _, b := range backends {
		m[b.BackendAddrID()] = b
	}
	return m
}

// restoreService restores service cache of the given legacy and v2 service.
func (l *lbmapCache) restoreService(svc loadbalancer.LBSVC) error {
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

	for _, backend := range serviceValues {
		addrID := backend.BackendAddrID()
		if _, found := bpfSvc.backendsV2[addrID]; !found {
			l.addBackendV2Locked(addrID)
		}
		bpfSvc.backendsV2[addrID] = backend
	}

	return nil
}

// prepareUpdate prepares the caches to reflect the changes in the given svc.
// The given backends should not contain a service value of a master service.
func (l *lbmapCache) prepareUpdate(fe ServiceKey, backends []ServiceValue) (
	*bpfService, map[loadbalancer.BackendID]ServiceValue, []BackendKey, error) {

	frontendID := fe.String()

	bpfSvc, ok := l.entries[frontendID]
	if !ok {
		bpfSvc = newBpfService(fe)
		l.entries[frontendID] = bpfSvc
	}

	newBackendsMap := createBackendsMap(backends)
	toRemoveBackendIDs := []BackendKey{}
	toAddBackendIDs := map[loadbalancer.BackendID]ServiceValue{}

	// Step 1: Delete all backends that no longer exist.
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

	// Step 2: Add all backends that don't exist in the service yet.
	for _, b := range backends {
		addrID := b.BackendAddrID()
		if _, ok := bpfSvc.backendsV2[addrID]; !ok {
			bpfSvc.backendsV2[addrID] = b
			isNew := l.addBackendV2Locked(addrID)
			if isNew {
				toAddBackendIDs[l.backendIDByAddrID[addrID].GetID()] = b
			}
		}
	}

	return bpfSvc, toAddBackendIDs, toRemoveBackendIDs, nil
}

func (l *lbmapCache) delete(fe ServiceKey) {
	delete(l.entries, fe.String())
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

func (l *lbmapCache) addBackendIDs(backendIDs map[BackendAddrID]BackendKey) {
	for addrID, backendID := range backendIDs {
		l.backendIDByAddrID[addrID] = backendID
	}
}

// filterNewBackends filters out backends which already exists from the given
// map (i.e. keeps only new backends).
func (l *lbmapCache) filterNewBackends(backends serviceValueMap) serviceValueMap {
	newBackends := serviceValueMap{}

	for addrID, b := range backends {
		if _, found := l.backendIDByAddrID[addrID]; !found {
			newBackends[addrID] = b
		}
	}

	return newBackends
}

func (l *lbmapCache) getBackendKey(addrID BackendAddrID) BackendKey {
	return l.backendIDByAddrID[addrID]
}

// removeServiceV2 removes the service v2 from the cache.
func (l *lbmapCache) removeServiceV2(svcKey ServiceKeyV2) ([]BackendKey, int, error) {
	frontendID := svcKey.String()
	bpfSvc, ok := l.entries[frontendID]
	if !ok {
		return nil, 0, fmt.Errorf("Service %s not found", frontendID)
	}

	backendsToRemove := []BackendKey{}
	count := len(bpfSvc.backendsV2)

	for addrID := range bpfSvc.backendsV2 {
		isLastInstance, err := l.delBackendV2Locked(addrID)
		if err != nil {
			return nil, 0, err
		}
		if isLastInstance {
			backendsToRemove = append(backendsToRemove, l.backendIDByAddrID[addrID])
			delete(l.backendIDByAddrID, addrID)
		}
	}

	// FIXME(brb) uncomment the following line after we have removed the support for
	// legacy svc.
	//delete(l.entries, frontendID)

	return backendsToRemove, count, nil
}

// removeBackendsWithRefCountZero removes backends from the cache which are not
// used by any service.
func (l *lbmapCache) removeBackendsWithRefCountZero() map[BackendAddrID]BackendKey {
	removed := make(map[BackendAddrID]BackendKey)

	for addrID, id := range l.backendIDByAddrID {
		if l.backendRefCount[addrID] == 0 {
			delete(l.backendIDByAddrID, addrID)
			removed[addrID] = id
		}
	}

	return removed
}
