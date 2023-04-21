// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package allocator

import (
	"net"

	"github.com/cilium/cilium/pkg/ipam/types"
)

// Allocator provides an IP allocator based on a list of Pools
//
// Implementations:
//   - PoolGroupAllocator
//   - NoOpAllocator
type Allocator interface {
	GetPoolQuota() types.PoolQuotaMap
	Allocate(poolID types.PoolID, ip net.IP) error
	AllocateMany(poolID types.PoolID, num int) ([]net.IP, error)
	ReleaseMany(poolID types.PoolID, ips []net.IP) error
}
