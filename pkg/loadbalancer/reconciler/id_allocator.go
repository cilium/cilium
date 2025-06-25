// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package reconciler

import (
	"fmt"

	"github.com/cilium/cilium/pkg/loadbalancer"
)

// idAllocator contains an internal state of the ID allocator.
type idAllocator struct {
	// entitiesID is a map of all entities indexed by service or backend ID
	entitiesID map[loadbalancer.ID]loadbalancer.L3n4Addr

	// entities is a map of all entities indexed by L3n4Addr.StringID()
	entities map[loadbalancer.L3n4Addr]loadbalancer.ID

	// nextID is the next ID to attempt to allocate
	nextID loadbalancer.ID

	// maxID is the maximum ID available for allocation
	maxID loadbalancer.ID

	// initNextID is the initial nextID
	initNextID loadbalancer.ID

	// initMaxID is the initial maxID
	initMaxID loadbalancer.ID
}

const (
	// firstFreeServiceID is the first ID for which the services should be assigned.
	firstFreeServiceID = loadbalancer.ID(1)

	// maxSetOfServiceID is maximum number of set of service IDs that can be stored
	// in the kvstore or the local ID allocator.
	maxSetOfServiceID = loadbalancer.ID(0xFFFF)

	// firstFreeBackendID is the first ID for which the backend should be assigned.
	// BPF datapath assumes that backend_id cannot be 0.
	firstFreeBackendID = loadbalancer.ID(1)

	// maxSetOfBackendID is maximum number of set of backendIDs IDs that can be
	// stored in the local ID allocator.
	maxSetOfBackendID = loadbalancer.ID(0xFFFFFFFF)
)

func newIDAllocator(nextID loadbalancer.ID, maxID loadbalancer.ID) idAllocator {
	return idAllocator{
		entitiesID: map[loadbalancer.ID]loadbalancer.L3n4Addr{},
		entities:   map[loadbalancer.L3n4Addr]loadbalancer.ID{},
		nextID:     nextID,
		maxID:      maxID,
		initNextID: nextID,
		initMaxID:  maxID,
	}
}

func (alloc *idAllocator) addID(svc loadbalancer.L3n4Addr, id loadbalancer.ID) loadbalancer.ID {
	alloc.entitiesID[id] = svc
	alloc.entities[svc] = id
	return id
}

func (alloc *idAllocator) acquireLocalID(svc loadbalancer.L3n4Addr) (loadbalancer.ID, error) {
	if svcID, ok := alloc.entities[svc]; ok {
		return svcID, nil
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

	return 0, fmt.Errorf("no service ID available")
}

func (alloc *idAllocator) deleteLocalID(id loadbalancer.ID) {
	if svc, ok := alloc.entitiesID[id]; ok {
		delete(alloc.entitiesID, id)
		delete(alloc.entities, svc)
	}
}

func (alloc *idAllocator) lookupLocalID(svc loadbalancer.L3n4Addr) (loadbalancer.ID, error) {
	if svcID, ok := alloc.entities[svc]; ok {
		return svcID, nil
	}

	return 0, fmt.Errorf("ID not found")
}
