// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package allocator

import (
	"errors"
	"net"

	"github.com/cilium/cilium/pkg/ipam/types"
)

var errNotSupported = errors.New("Operation not supported")

// NoOpAllocator implements Allocator with no-op behavior
type NoOpAllocator struct{}

// GetPoolQuota returns the total available pool quota. This is always 0.
func (n *NoOpAllocator) GetPoolQuota() types.PoolQuotaMap {
	return types.PoolQuotaMap{}
}

// FirstPoolWithAvailableQuota returns the first pool ID in the list of pools
// with available addresses. This function always returns types.PoolNotExists
func (n *NoOpAllocator) FirstPoolWithAvailableQuota(preferredPoolIDs []types.PoolID) (types.PoolID, int) {
	return types.PoolNotExists, 0
}

// Allocate allocates a paritcular IP in a particular pool. This function
// always returns an error as this operation is not supported for the no-op
// allocator.
func (n *NoOpAllocator) Allocate(poolID types.PoolID, ip net.IP) error {
	return errNotSupported
}

// AllocateMany allocates multiple IP addresses. The operation succeeds if all
// IPs can be allocated. On failure, all IPs are released again.
func (n *NoOpAllocator) AllocateMany(poolID types.PoolID, num int) ([]net.IP, error) {
	return nil, errNotSupported
}

// ReleaseMany releases a slice of IP addresses. This function has no effect
func (n *NoOpAllocator) ReleaseMany(poolID types.PoolID, ips []net.IP) error {
	return nil
}

// PoolExists returns true if an allocation pool exists. This function always
// returns false.
func (n *NoOpAllocator) PoolExists(poolID types.PoolID) bool {
	return false
}
