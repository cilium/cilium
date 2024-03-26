// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package endpointmanager

import (
	"fmt"

	"github.com/cilium/cilium/pkg/idpool"
)

const (
	minID = idpool.ID(1)
	maxID = idpool.ID(4095)
)

type epIDAllocator struct {
	pool *idpool.IDPool
}

func newEPIDAllocator() *epIDAllocator {
	return &epIDAllocator{
		pool: idpool.NewIDPool(minID, maxID),
	}
}

// allocate returns a new random ID from the pool
func (a *epIDAllocator) allocate() uint16 {
	id := a.pool.AllocateID()

	// Out of endpoint IDs
	if id == idpool.NoID {
		return uint16(0)
	}

	return uint16(id)
}

// reuse grabs a specific endpoint ID for reuse. This can be used when
// restoring endpoints.
func (a *epIDAllocator) reuse(id uint16) error {
	if idpool.ID(id) < minID {
		return fmt.Errorf("unable to reuse endpoint: %d < %d", id, minID)
	}

	// When restoring endpoints, the existing endpoint ID can be outside of
	// the range. This is fine (tm) and we can just skip to reserve the ID
	// from the pool as the pool will not cover it.
	if idpool.ID(id) > maxID {
		return nil
	}

	if !a.pool.Remove(idpool.ID(id)) {
		return fmt.Errorf("endpoint ID %d is already in use", id)
	}

	return nil
}

// release releases an endpoint ID that was previously allocated or reused
func (a *epIDAllocator) release(id uint16) error {
	if !a.pool.Insert(idpool.ID(id)) {
		return fmt.Errorf("Unable to release endpoint ID %d", id)
	}

	return nil
}
