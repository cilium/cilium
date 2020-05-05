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
	"fmt"
	"net"

	"github.com/cilium/cilium/pkg/cidr"
	"github.com/cilium/cilium/pkg/ipam/types"

	"github.com/cilium/ipam/service/ipallocator"
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
