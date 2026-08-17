// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package reconciler

import (
	"fmt"

	"github.com/cilium/cilium/pkg/loadbalancer"
)

type idConstraint interface {
	loadbalancer.ServiceID | loadbalancer.BackendID
}

// idAllocator contains an internal state of the ID allocator.
type idAllocator[ID idConstraint] struct {
	// idToAddr maps ID to address
	idToAddr map[ID]loadbalancer.L3n4Addr

	// addrToId maps address to ID
	addrToId map[loadbalancer.L3n4Addr]ID

	// nextID is the next ID to attempt to allocate
	nextID ID

	// maxID is the maximum ID available for allocation
	maxID ID

	// initNextID is the initial nextID
	initNextID ID

	// initMaxID is the initial maxID
	initMaxID ID

	// Metrics is the metrics package
	metrics Metrics

	// metricsTypeLabel is the label to attach to the metrics
	metricsTypeLabel TypeLabel
}

const (
	// firstFreeServiceID is the first ID for which the services should be assigned.
	firstFreeServiceID = loadbalancer.ServiceID(1)

	// maxSetOfServiceID is maximum number of set of service IDs that can be stored
	// in the kvstore or the local ID allocator.
	maxSetOfServiceID = loadbalancer.ServiceID(0xFFFF)

	// firstFreeBackendID is the first ID for which the backend should be assigned.
	// BPF datapath assumes that backend_id cannot be 0.
	firstFreeBackendID = loadbalancer.BackendID(1)

	// maxSetOfBackendID is maximum number of set of backendIDs IDs that can be
	// stored in the local ID allocator.
	maxSetOfBackendID = loadbalancer.BackendID(0xFFFFFFFF)
)

func newIDAllocator[ID idConstraint](nextID ID, maxID ID, metrics Metrics, metricsTypeLabel TypeLabel) idAllocator[ID] {
	allocator := idAllocator[ID]{
		idToAddr:   map[ID]loadbalancer.L3n4Addr{},
		addrToId:   map[loadbalancer.L3n4Addr]ID{},
		nextID:     nextID,
		maxID:      maxID,
		initNextID: nextID,
		initMaxID:  maxID,

		metrics:           metrics,
		metricsTypeLabel:  metricsTypeLabel,
	}
	allocator.updateIDMetrics()
	return allocator
}

func (alloc *idAllocator[ID]) updateIDMetrics() {
	limit := alloc.maxID-alloc.initNextID;
	allocated := len(alloc.idToAddr);
	alloc.metrics.SetKeysLimit(alloc.metricsTypeLabel, uint32(limit));
	alloc.metrics.SetKeysAllocated(alloc.metricsTypeLabel, uint32(allocated));
	if limit <= 0 {
		// If the limit of the keyspace is not positive, just set the pressure to 1.0
		// (maximum pressure). Technically it's undefined, but this way we'll still
		// trigger monitoring alerts that are looking at keyspace pressure even if the
		// keyspace is configured to be zero or negitive and no IDs can be assigned.
		alloc.metrics.SetKeyspacePressure(alloc.metricsTypeLabel, 1.0)
	} else {
		alloc.metrics.SetKeyspacePressure(alloc.metricsTypeLabel, float64(allocated)/float64(limit))
	}
}

func (alloc *idAllocator[ID]) addID(addr loadbalancer.L3n4Addr, id ID) ID {
	alloc.idToAddr[id] = addr
	alloc.addrToId[addr] = id
	alloc.updateIDMetrics()
	return id
}

func (alloc *idAllocator[ID]) acquireLocalID(svc loadbalancer.L3n4Addr) (ID, error) {
	if id, ok := alloc.addrToId[svc]; ok {
		return id, nil
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

		if _, ok := alloc.idToAddr[alloc.nextID]; !ok {
			svcID := alloc.addID(svc, alloc.nextID)
			alloc.nextID++
			return svcID, nil
		}

		alloc.nextID++
	}

	return 0, fmt.Errorf("no ID available")
}

func (alloc *idAllocator[ID]) deleteLocalID(id ID) {
	if addr, ok := alloc.idToAddr[id]; ok {
		delete(alloc.idToAddr, id)
		delete(alloc.addrToId, addr)
		alloc.updateIDMetrics()
	}
}

func (alloc *idAllocator[ID]) lookupLocalID(addr loadbalancer.L3n4Addr) (ID, error) {
	if id, ok := alloc.addrToId[addr]; ok {
		return id, nil
	}

	return 0, fmt.Errorf("ID not found")
}
