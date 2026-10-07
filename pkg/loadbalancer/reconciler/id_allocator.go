// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package reconciler

import (
	"fmt"

	"k8s.io/apimachinery/pkg/util/sets"

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
	// idToAddrs maps an allocated ID to the addresses that own it. An ID has
	// more than one owner when restored protocol aliases of the same frontend
	// share it. Restored addresses that have not been updated yet are also
	// recorded (see reserveID), which keeps their ID from being allocated.
	idToAddrs map[ID]sets.Set[loadbalancer.L3n4Addr]

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
		idToAddrs:  map[ID]sets.Set[loadbalancer.L3n4Addr]{},
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

// reserveID marks the ID as owned by addr without assigning it to addr. It is
// used for restored IDs that are not yet claimed by a frontend.
func (alloc *idAllocator[ID]) reserveID(addr loadbalancer.L3n4Addr, id ID) {
	owners, ok := alloc.idToAddrs[id]
	if !ok {
		owners = sets.New[loadbalancer.L3n4Addr]()
		alloc.idToAddrs[id] = owners
	}
	owners.Insert(addr)
	alloc.updateAllocationMetric()
}

func (alloc *idAllocator[ID]) addID(addr loadbalancer.L3n4Addr, id ID) ID {
	alloc.reserveID(addr, id)
	alloc.addrToId[addr] = id
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

		if _, ok := alloc.idToAddrs[alloc.nextID]; !ok {
			svcID := alloc.addID(svc, alloc.nextID)
			alloc.nextID++
			return svcID, nil
		}

		alloc.nextID++
	}

	alloc.metrics.allocationFailures.Inc()
	return 0, fmt.Errorf("no ID available")
}

// deleteLocalID drops the ID of addr. The ID becomes available again once it
// has no other owner.
func (alloc *idAllocator[ID]) deleteLocalID(addr loadbalancer.L3n4Addr) {
	if id, ok := alloc.addrToId[addr]; ok {
		delete(alloc.addrToId, addr)
		alloc.releaseID(addr, id)
	}
}

// releaseID removes addr as an owner of the ID.
func (alloc *idAllocator[ID]) releaseID(addr loadbalancer.L3n4Addr, id ID) {
	owners := alloc.idToAddrs[id]
	owners.Delete(addr)
	if owners.Len() == 0 {
		delete(alloc.idToAddrs, id)
	}
	alloc.updateAllocationMetric()
}

// otherOwnerMatches returns true if an owner of the ID other than addr satisfies match.
func (alloc *idAllocator[ID]) otherOwnerMatches(addr loadbalancer.L3n4Addr, id ID, match func(owner loadbalancer.L3n4Addr) bool) bool {
	for owner := range alloc.idToAddrs[id] {
		if owner != addr && match(owner) {
			return true
		}
	}
	return false
}

// claimedOwnerMatches returns true if an owner that is claimed with the ID satisfies match.
// The state of the other owners, which are restored with the ID but use another one, or
// that are not updated yet, does not belong to the ID.
func (alloc *idAllocator[ID]) claimedOwnerMatches(id ID, match func(owner loadbalancer.L3n4Addr) bool) bool {
	for owner := range alloc.idToAddrs[id] {
		if alloc.addrToId[owner] == id && match(owner) {
			return true
		}
	}
	return false
}

// otherClaimedOwnerMatches is like claimedOwnerMatches, but ignores addr.
func (alloc *idAllocator[ID]) otherClaimedOwnerMatches(addr loadbalancer.L3n4Addr, id ID, match func(owner loadbalancer.L3n4Addr) bool) bool {
	return alloc.claimedOwnerMatches(id, func(owner loadbalancer.L3n4Addr) bool {
		return owner != addr && match(owner)
	})
}

// hasOtherOwnerOnIP returns true if an owner of the ID other than addr has the same IP.
// The aliases of an IP share its wildcard service entry.
func (alloc *idAllocator[ID]) hasOtherOwnerOnIP(addr loadbalancer.L3n4Addr, id ID) bool {
	return alloc.otherOwnerMatches(addr, id, func(owner loadbalancer.L3n4Addr) bool {
		return owner.Addr() == addr.Addr()
	})
}

// hasClaimedOwner returns true if a frontend of the IP family owns the ID, as opposed
// to an ID that is only reserved for a restored frontend that has not been updated.
func (alloc *idAllocator[ID]) hasClaimedOwner(id ID, ipv6 bool) bool {
	return alloc.claimedOwnerMatches(id, func(owner loadbalancer.L3n4Addr) bool {
		return owner.IsIPv6() == ipv6
	})
}

func (alloc *idAllocator[ID]) updateAllocationMetric() {
	alloc.metrics.allocations.Set(float64(len(alloc.idToAddrs)))
}

func (alloc *idAllocator[ID]) lookupLocalID(addr loadbalancer.L3n4Addr) (ID, error) {
	if id, ok := alloc.addrToId[addr]; ok {
		return id, nil
	}

	return 0, fmt.Errorf("ID not found")
}
