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

type serviceValueMap map[string]ServiceValue

type bpfBackend struct {
	id       string
	isHole   bool
	bpfValue ServiceValue
}

type bpfService struct {
	numUniqueBackends int

	// holes lists all backend indices that are currently filling in as
	// hole
	holes []int

	frontendKey ServiceKey
	backends    map[int]*bpfBackend

	existingBackendsMap serviceValueMap
}

func newBpfService(key ServiceKey) *bpfService {
	return &bpfService{
		frontendKey:         key,
		backends:            map[int]*bpfBackend{},
		existingBackendsMap: map[string]ServiceValue{},
	}
}

func (b *bpfService) addBackend(backend ServiceValue) {
	if len(b.holes) > 0 {
		index := b.holes[0]
		b.holes = b.holes[1:]
		b.backends[index].bpfValue = backend
		b.backends[index].id = backend.String()
		b.backends[index].isHole = false
	} else {
		b.numUniqueBackends++
		b.backends[b.numUniqueBackends] = &bpfBackend{
			bpfValue: backend,
			id:       backend.String(),
		}
	}

	b.existingBackendsMap[backend.String()] = backend
}

func (b *bpfService) deleteBackend(backend ServiceValue) {
	idToRemove := backend.String()
	indicesToRemove := []int{}
	duplicateCount := map[string]int{}

	for index, backend := range b.backends {
		if backend.id != idToRemove {
			duplicateCount[backend.id]++
		}

		// create a slice of all backend indices that match the backend
		// ID (ip, port, revnat id)
		if idToRemove == backend.id {
			indicesToRemove = append(indicesToRemove, index)
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
		b.backends = map[int]*bpfBackend{}
		b.numUniqueBackends = 0
	} else {
		fillBackend := &bpfBackend{
			id:       fillBackendID,
			isHole:   true,
			bpfValue: b.existingBackendsMap[fillBackendID],
		}
		for _, removeIndex := range indicesToRemove {
			if !b.backends[removeIndex].isHole {
				b.holes = append(b.holes, removeIndex)
			}
			b.backends[removeIndex] = fillBackend
		}
	}

	delete(b.existingBackendsMap, idToRemove)
}

func (b *bpfService) getBackends() []ServiceValue {
	backends := make([]ServiceValue, len(b.backends))
	for i := 1; i < b.numUniqueBackends; i++ {
		backends[i-1] = b.backends[i].bpfValue
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
	for key, b := range bpfSvc.existingBackendsMap {
		if _, ok := newBackendsMap[key]; !ok {
			bpfSvc.deleteBackend(b)
		}
	}

	// Step 2: Add all backends that don't exist yet. This will use up
	// holes that have been created by deleteBackend() first before adding
	// new slave slots.
	for _, b := range backends {
		if _, ok := bpfSvc.existingBackendsMap[b.String()]; !ok {
			bpfSvc.addBackend(b)
		}
	}

	return bpfSvc
}

func (l *lbmapCache) delete(fe ServiceKey) {
	delete(l.entries, fe.String())
}
