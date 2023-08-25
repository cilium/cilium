// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package service

import (
	"fmt"

	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/lock"
)

// IDAllocator contains an internal state of the ID allocator.
type IDAllocator struct {
	// Protects entitiesID, entities, nextID and maxID
	lock.RWMutex

	// entitiesID is a map of all entities indexed by service or backend ID
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
	serviceIDAlloc = NewIDAllocator(FirstFreeServiceID, MaxSetOfServiceID)
	backendIDAlloc = NewIDAllocator(FirstFreeBackendID, MaxSetOfBackendID)
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

func (alloc *IDAllocator) addID(svc loadbalancer.L3n4Addr, id uint32) *loadbalancer.L3n4AddrID {
	svcID := newID(svc, id)
	alloc.entitiesID[id] = svcID
	alloc.entities[svc.StringID()] = id

	return svcID
}

func (alloc *IDAllocator) acquireLocalID(svc loadbalancer.L3n4Addr, desiredID uint32) (*loadbalancer.L3n4AddrID, error) {
	alloc.Lock()
	defer alloc.Unlock()

	if svcID, ok := alloc.entities[svc.StringID()]; ok {
		if svc, ok := alloc.entitiesID[svcID]; ok {
			return svc, nil
		}
	}

	if desiredID != 0 {
		foundSVC, ok := alloc.entitiesID[desiredID]
		if !ok {
			if desiredID >= alloc.nextID {
				// We don't set nextID to desiredID+1 here, as we don't want to
				// duplicate the logic which deals with the rollover. Next
				// invocation of acquireLocalID(..., 0) will fix the nextID.
				alloc.nextID = desiredID
			}
			return alloc.addID(svc, desiredID), nil
		}
		return nil, fmt.Errorf("Service ID %d is already registered to %q",
			desiredID, foundSVC)
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
			svcID := alloc.addID(svc, alloc.nextID)
			alloc.nextID++
			return svcID, nil
		}

		alloc.nextID++
	}

	return nil, fmt.Errorf("no service ID available")
}

func (alloc *IDAllocator) getLocalID(id uint32) (*loadbalancer.L3n4AddrID, error) {
	alloc.RLock()
	defer alloc.RUnlock()

	if svc, ok := alloc.entitiesID[id]; ok {
		return svc, nil
	}

	return nil, nil
}

func (alloc *IDAllocator) deleteLocalID(id uint32) error {
	alloc.Lock()
	defer alloc.Unlock()

	if svc, ok := alloc.entitiesID[id]; ok {
		delete(alloc.entitiesID, id)
		delete(alloc.entities, svc.StringID())
	}

	return nil
}

func (alloc *IDAllocator) lookupLocalID(svc loadbalancer.L3n4Addr) (uint32, error) {
	alloc.RLock()
	defer alloc.RUnlock()

	if svcID, ok := alloc.entities[svc.StringID()]; ok {
		return svcID, nil
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

func newID(svc loadbalancer.L3n4Addr, id uint32) *loadbalancer.L3n4AddrID {
	return &loadbalancer.L3n4AddrID{
		L3n4Addr: svc,
		ID:       loadbalancer.ID(id),
	}
}
