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
)

type serviceValueMap map[string]ServiceValue

type bpfBackend struct {
	id       string
	isHole   bool
	bpfValue ServiceValue
}

type bpfService struct {
	// holes lists all backend indices that are currently filling in as
	// hole
	holes []int

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
		uniqueBackends:     map[string]ServiceValue{},
	}
}

func (b *bpfService) addBackend(backend ServiceValue) {
	if len(b.holes) > 0 {
		// Retrieve map index of next hole and remove it from the list
		index := b.holes[0]
		b.holes = b.holes[1:]

		// Fill in backend in already existing hole that currently
		// holds a duplicate
		b.backendsByMapIndex[index].bpfValue = backend
		b.backendsByMapIndex[index].id = backend.String()
		b.backendsByMapIndex[index].isHole = false
	} else {
		// No holes, we need to allocate a new backend slot
		nextSlot := len(b.uniqueBackends) + 1
		b.backendsByMapIndex[nextSlot] = &bpfBackend{
			bpfValue: backend,
			id:       backend.String(),
		}
	}

	b.uniqueBackends[backend.String()] = backend
}

func (b *bpfService) deleteBackend(backend ServiceValue) {
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
		b.holes = []int{}
		b.backendsByMapIndex = map[int]*bpfBackend{}
	} else {
		fillBackend := &bpfBackend{
			id:       fillBackendID,
			isHole:   true,
			bpfValue: b.uniqueBackends[fillBackendID],
		}
		for _, removeIndex := range indicesToRemove {
			if !b.backendsByMapIndex[removeIndex].isHole {
				b.holes = append(b.holes, removeIndex)
			}
			b.backendsByMapIndex[removeIndex] = fillBackend
		}
	}

	delete(b.uniqueBackends, idToRemove)
}

func (b *bpfService) getBackends() []ServiceValue {
	backends := make([]ServiceValue, len(b.backendsByMapIndex))
	for i := 1; i <= len(b.backendsByMapIndex); i++ {
		backends[i-1] = b.backendsByMapIndex[i].bpfValue
	}
	return backends
}

type lbmapCache struct {
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
		m[b.String()] = b
	}
	return m
}

func (l *lbmapCache) restoreService(svc loadbalancer.LBSVC) error {
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
			bpfSvc.holes = append(bpfSvc.holes, index+1)
		} else {
			bpfSvc.uniqueBackends[backend.String()] = backend
		}

		bpfSvc.backendsByMapIndex[index+1] = b
	}

	return nil
}

func (l *lbmapCache) prepareUpdate(fe ServiceKey, backends []ServiceValue) *bpfService {
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

	// Step 2: Add all backends that don't exist yet. This will use up
	// holes that have been created by deleteBackend() first before adding
	// new slave slots.
	for _, b := range backends {
		if _, ok := bpfSvc.uniqueBackends[b.String()]; !ok {
			bpfSvc.addBackend(b)
		}
	}

	return bpfSvc
}

func (l *lbmapCache) delete(fe ServiceKey) {
	delete(l.entries, fe.String())
}
