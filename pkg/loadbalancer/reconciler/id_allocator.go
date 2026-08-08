// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package reconciler

import (
	"fmt"

	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/metrics/metric"
)

type idConstraint interface {
	loadbalancer.ServiceID | loadbalancer.BackendID
}

type idAllocatorMetrics struct {
	capacity           metric.Gauge
	allocations        metric.Gauge
	allocationAttempts metric.Counter
	allocationFailures metric.Counter
}

// idAllocator contains an internal state of the ID allocator.
type idAllocator[ID idConstraint] struct {
	// idToAddr maps ID to address
	idToAddr map[ID]loadbalancer.L3n4Addr

	// addrToId maps address to ID
	addrToId map[loadbalancer.L3n4Addr]ID

	// nextID is the next ID to attempt to allocate
	nextID ID

	// maxID is the exclusive upper bound of the ID allocation range
	maxID ID

	// initNextID is the initial nextID
	initNextID ID

	// initMaxID is the initial exclusive upper bound of the ID allocation range
	initMaxID ID

	// metrics are updated on mutation so scrapes do not need to read allocator state
	metrics idAllocatorMetrics
}

const (
	// firstFreeServiceID is the first ID for which the services should be assigned.
	firstFreeServiceID = loadbalancer.ServiceID(1)

	// maxSetOfServiceID is the exclusive upper bound of the service ID allocation
	// range.
	maxSetOfServiceID = loadbalancer.ServiceID(0xFFFF)

	// firstFreeBackendID is the first ID for which the backend should be assigned.
	// BPF datapath assumes that backend_id cannot be 0.
	firstFreeBackendID = loadbalancer.BackendID(1)

	// maxSetOfBackendID is the exclusive upper bound of the backend ID allocation
	// range.
	maxSetOfBackendID = loadbalancer.BackendID(0xFFFFFFFF)
)

func newIDAllocator[ID idConstraint](nextID ID, maxID ID, metrics idAllocatorMetrics) idAllocator[ID] {
	alloc := idAllocator[ID]{
		idToAddr:   map[ID]loadbalancer.L3n4Addr{},
		addrToId:   map[loadbalancer.L3n4Addr]ID{},
		nextID:     nextID,
		maxID:      maxID,
		initNextID: nextID,
		initMaxID:  maxID,
		metrics:    metrics,
	}

	// Initialise allocator metrics
	alloc.metrics.capacity.Set(float64(uint64(maxID) - uint64(nextID)))
	alloc.updateAllocationMetric()

	return alloc
}

func (alloc *idAllocator[ID]) addID(addr loadbalancer.L3n4Addr, id ID) ID {
	alloc.idToAddr[id] = addr
	alloc.addrToId[addr] = id
	alloc.updateAllocationMetric()
	return id
}

func (alloc *idAllocator[ID]) acquireLocalID(svc loadbalancer.L3n4Addr) (ID, error) {
	if id, ok := alloc.addrToId[svc]; ok {
		return id, nil
	}

	alloc.metrics.allocationAttempts.Inc()

	startingID := alloc.nextID
	rollover := false
	for {
		if alloc.nextID == startingID && rollover {
			break
		} else if alloc.nextID == alloc.maxID {
			alloc.nextID = alloc.initNextID
			rollover = true
		}

		if _, ok := alloc.idToAddr[alloc.nextID]; !ok {
			svcID := alloc.addID(svc, alloc.nextID)
			alloc.nextID++
			return svcID, nil
		}

		alloc.nextID++
	}

	alloc.metrics.allocationFailures.Inc()
	return 0, fmt.Errorf("no ID available")
}

func (alloc *idAllocator[ID]) deleteLocalID(id ID) {
	if addr, ok := alloc.idToAddr[id]; ok {
		delete(alloc.idToAddr, id)
		delete(alloc.addrToId, addr)
		alloc.updateAllocationMetric()
	}
}

func (alloc *idAllocator[ID]) updateAllocationMetric() {
	alloc.metrics.allocations.Set(float64(len(alloc.idToAddr)))
}

func (alloc *idAllocator[ID]) lookupLocalID(addr loadbalancer.L3n4Addr) (ID, error) {
	if id, ok := alloc.addrToId[addr]; ok {
		return id, nil
	}

	return 0, fmt.Errorf("ID not found")
}
