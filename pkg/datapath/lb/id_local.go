// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package lb

import (
	"fmt"

	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/lock"
)

// IDAllocator contains an internal state of the ID allocator.
type IDAllocator struct {
	// Protects entitiesID, entities, nextID and maxID
	lock.RWMutex

	// entitiesID is a map of all entities indexed by frontend or backend ID
	entitiesID map[uint32]*loadbalancer.L3n4AddrID

	// entities is a map of all entities indexed by L3n4Addr.StringID()
	entities map[string]uint32

	// nextID is the next ID to attempt to allocate
	nextID uint32

	// maxID is the maximum ID available for allocation
	maxID uint32

	// initNextID is the initial nextID
	initNextID uint32

	// initMaxID is the initial maxID
	initMaxID uint32
}

var (
	frontendIDAlloc = NewIDAllocator(FirstFreeFrontendID, MaxSetOfFrontendID)
	backendIDAlloc  = NewIDAllocator(FirstFreeBackendID, MaxSetOfBackendID)
)

// NewIDAllocator creates a new ID allocator instance.
func NewIDAllocator(nextID uint32, maxID uint32) *IDAllocator {
	return &IDAllocator{
		entitiesID: map[uint32]*loadbalancer.L3n4AddrID{},
		entities:   map[string]uint32{},
		nextID:     nextID,
		maxID:      maxID,
		initNextID: nextID,
		initMaxID:  maxID,
	}
}

func (alloc *IDAllocator) addID(fe loadbalancer.L3n4Addr, id uint32) *loadbalancer.L3n4AddrID {
	feID := newID(fe, id)
	alloc.entitiesID[id] = feID
	alloc.entities[fe.StringID()] = id

	return feID
}

func (alloc *IDAllocator) acquireLocalID(fe loadbalancer.L3n4Addr, desiredID uint32) (*loadbalancer.L3n4AddrID, error) {
	alloc.Lock()
	defer alloc.Unlock()

	if feID, ok := alloc.entities[fe.StringID()]; ok {
		if fe, ok := alloc.entitiesID[feID]; ok {
			return fe, nil
		}
	}

	if desiredID != 0 {
		foundFE, ok := alloc.entitiesID[desiredID]
		if !ok {
			if desiredID >= alloc.nextID {
				// We don't set nextID to desiredID+1 here, as we don't want to
				// duplicate the logic which deals with the rollover. Next
				// invocation of acquireLocalID(..., 0) will fix the nextID.
				alloc.nextID = desiredID
			}
			return alloc.addID(fe, desiredID), nil
		}
		return nil, fmt.Errorf("ID %d is already registered to %q",
			desiredID, foundFE)
	}

	startingID := alloc.nextID
	rollover := false
	for {
		if alloc.nextID == startingID && rollover {
			break
		} else if alloc.nextID == alloc.maxID {
			alloc.nextID = alloc.initNextID
			rollover = true
		}

		if _, ok := alloc.entitiesID[alloc.nextID]; !ok {
			feID := alloc.addID(fe, alloc.nextID)
			alloc.nextID++
			return feID, nil
		}

		alloc.nextID++
	}

	return nil, fmt.Errorf("no ID available")
}

func (alloc *IDAllocator) getLocalID(id uint32) (*loadbalancer.L3n4AddrID, error) {
	alloc.RLock()
	defer alloc.RUnlock()

	if fe, ok := alloc.entitiesID[id]; ok {
		return fe, nil
	}

	return nil, nil
}

func (alloc *IDAllocator) deleteLocalID(id uint32) error {
	alloc.Lock()
	defer alloc.Unlock()

	if fe, ok := alloc.entitiesID[id]; ok {
		delete(alloc.entitiesID, id)
		delete(alloc.entities, fe.StringID())
	}

	return nil
}

func (alloc *IDAllocator) lookupLocalID(fe loadbalancer.L3n4Addr) (uint32, error) {
	alloc.RLock()
	defer alloc.RUnlock()

	if feID, ok := alloc.entities[fe.StringID()]; ok {
		return feID, nil
	}

	return 0, fmt.Errorf("ID not found")
}

func (alloc *IDAllocator) setLocalIDSpace(next, max uint32) error {
	alloc.Lock()
	alloc.nextID = next
	alloc.maxID = max
	alloc.Unlock()

	return nil
}

func (alloc *IDAllocator) getLocalMaxID() (uint32, error) {
	alloc.RLock()
	defer alloc.RUnlock()
	return alloc.nextID, nil
}

func (alloc *IDAllocator) resetLocalID() {
	alloc.Lock()
	alloc.entitiesID = map[uint32]*loadbalancer.L3n4AddrID{}
	alloc.entities = map[string]uint32{}
	alloc.nextID = alloc.initNextID
	alloc.maxID = alloc.initMaxID
	alloc.Unlock()
}

func newID(fe loadbalancer.L3n4Addr, id uint32) *loadbalancer.L3n4AddrID {
	return &loadbalancer.L3n4AddrID{
		L3n4Addr: fe,
		ID:       loadbalancer.ID(id),
	}
}
