// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package basicallocator

import (
	"fmt"
	"strconv"

	"github.com/cilium/cilium/pkg/idpool"
)

// BasicIDAllocator is used for managing a range of identities (unsigned
// integers) in a very simple way, by allocating specified or random identities,
// and returning them to the available pool.
// Concurrency control (mutex locks) is built into IDPool.
type BasicIDAllocator struct {
	idPool     idpool.IDPool
	minIDValue idpool.ID
	maxIDValue idpool.ID
}

// NewBasicIDAllocator creates a new BasicIDAllocator for ID values between
// the provided minIDValue and maxIDValue.
func NewBasicIDAllocator(minIDValue, maxIDValue idpool.ID) *BasicIDAllocator {
	return &BasicIDAllocator{
		idPool:     idpool.NewIDPool(minIDValue, maxIDValue),
		minIDValue: minIDValue,
		maxIDValue: maxIDValue,
	}
}

func (b *BasicIDAllocator) AllocateRandom() (idpool.ID, error) {
	id := b.idPool.AllocateID()
	if id == idpool.NoID {
		return id, fmt.Errorf("failed to allocate random ID")
	}

	return id, nil
}

func (b *BasicIDAllocator) Allocate(id idpool.ID) error {
	if !b.IsInPoolRange(id) {
		return fmt.Errorf("cannot allocate %d because it's out of the pool range [%d, %d]", id, b.minIDValue, b.maxIDValue)
	}

	idRemovedFromPool := b.idPool.Remove(id)
	if !idRemovedFromPool {
		return fmt.Errorf("failed to allocate ID=%d", id)
	}

	return nil
}

func (b *BasicIDAllocator) ReturnToAvailablePool(id idpool.ID) error {
	if !b.IsInPoolRange(id) {
		return fmt.Errorf("cannot return %d to the available pool because it's out of the pool range [%d, %d]", id, b.minIDValue, b.maxIDValue)
	}

	returnedToPool := b.idPool.Insert(id)
	if !returnedToPool {
		return fmt.Errorf("failed to return ID %d to available pool", id)
	}

	return nil
}

func (b *BasicIDAllocator) IsInPoolRange(id idpool.ID) bool {
	return id >= b.minIDValue && id <= b.maxIDValue
}

func (b *BasicIDAllocator) ValidateIDString(idStr string) (int64, error) {
	idInt, err := strconv.Atoi(idStr)
	if err != nil {
		return 0, fmt.Errorf("failed to validate id(%d): %v", idInt, err)
	}

	if idInt < 0 {
		return 0, fmt.Errorf("failed to validate id(%d), id cannot be negative", idInt)
	}

	idInt64 := int64(idInt)

	if !b.IsInPoolRange(idpool.ID(idInt64)) {
		return 0, fmt.Errorf("failed to validate id(%d), out of the pool range [%d, %d]", idInt, b.minIDValue, b.maxIDValue)
	}

	return idInt64, nil
}
