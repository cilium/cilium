// Copyright 2019-2020 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

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
