// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package allocator

import (
	"fmt"
	"net"

	"github.com/cilium/cilium/pkg/cidr"
	"github.com/cilium/cilium/pkg/ipam/service/ipallocator"
	"github.com/cilium/cilium/pkg/ipam/types"
)

// PoolAllocator is an IP allocator allocating out of a particular CIDR pool
type PoolAllocator struct {
	PoolID         types.PoolID
	AllocationCIDR *cidr.CIDR
	allocator      *ipallocator.Range
}

// NewPoolAllocator returns a new Allocator
func NewPoolAllocator(poolID types.PoolID, allocationCIDR *cidr.CIDR) (*PoolAllocator, error) {
	allocator, err := ipallocator.NewCIDRRange(allocationCIDR.IPNet)
	if err != nil {
		return nil, fmt.Errorf("unable to create IP allocator: %s", err)
	}

	return &PoolAllocator{PoolID: poolID, allocator: allocator, AllocationCIDR: allocationCIDR}, nil
}

// Free returns the number of available IPs for allocation
func (s *PoolAllocator) Free() int {
	return s.allocator.Free()
}

// Allocate allocates a particular IP
func (s *PoolAllocator) Allocate(ip net.IP) error {
	return s.allocator.Allocate(ip)
}

// AllocateMany allocates multiple IP addresses. The operation succeeds if all
// IPs can be allocated. On failure, all IPs are released again.
func (s *PoolAllocator) AllocateMany(num int) ([]net.IP, error) {
	ips := make([]net.IP, 0, num)

	for i := 0; i < num; i++ {
		ip, err := s.allocator.AllocateNext()
		if err != nil {
			for _, ip = range ips {
				s.allocator.Release(ip)
			}
			return nil, err
		}

		ips = append(ips, ip)
	}

	return ips, nil
}

// ReleaseMany releases a slice of IP addresses
func (s *PoolAllocator) ReleaseMany(ips []net.IP) {
	for _, ip := range ips {
		s.allocator.Release(ip)
	}
}
