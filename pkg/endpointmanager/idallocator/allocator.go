// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package idallocator

import (
	"fmt"

	"github.com/cilium/cilium/pkg/idpool"
)

const (
	minID = idpool.ID(1)
	maxID = idpool.ID(4095)
)

var (
	pool = idpool.NewIDPool(minID, maxID)
)

// ReallocatePool starts over with a new pool. This function is only used for
// tests and its implementation is not optimized for production.
func ReallocatePool() {
	for i := uint16(minID); i <= uint16(maxID); i++ {
		Release(i)
	}
}

// Allocate returns a new random ID from the pool
func Allocate() uint16 {
	id := pool.AllocateID()

	// Out of endpoint IDs
	if id == idpool.NoID {
		return uint16(0)
	}

	return uint16(id)
}

// Reuse grabs a specific endpoint ID for reuse. This can be used when
// restoring endpoints.
func Reuse(id uint16) error {
	if idpool.ID(id) < minID {
		return fmt.Errorf("unable to reuse endpoint: %d < %d", id, minID)
	}

	// When restoring endpoints, the existing endpoint ID can be outside of
	// the range. This is fine (tm) and we can just skip to reserve the ID
	// from the pool as the pool will not cover it.
	if idpool.ID(id) > maxID {
		return nil
	}

	if !pool.Remove(idpool.ID(id)) {
		return fmt.Errorf("endpoint ID %d is already in use", id)
	}

	return nil
}

// Release releases an endpoint ID that was previously allocated or reused
func Release(id uint16) error {
	if !pool.Insert(idpool.ID(id)) {
		return fmt.Errorf("Unable to release endpoint ID %d", id)
	}

	return nil
}
