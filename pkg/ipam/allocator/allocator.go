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
	"github.com/cilium/cilium/pkg/lock"

	"github.com/cilium/ipam/service/ipallocator"
)

// Allocator is an IP allocator allocating out of a particular subnet/CIDR
type Allocator struct {
	SubnetID  string
	allocator *ipallocator.Range
}

// NewAllocator returns a new Allocator
func NewAllocator(subnetID string, allocationCIDR *cidr.CIDR) (*Allocator, error) {
	allocator, err := ipallocator.NewCIDRRange(allocationCIDR.IPNet)
	if err != nil {
		return nil, fmt.Errorf("unable to create IP allocator: %s", err)
	}

	return &Allocator{
		SubnetID:  subnetID,
		allocator: allocator,
	}, nil
}

// Free returns the number of available IPs for allocation
func (s *Allocator) Free() int {
	return s.allocator.Free()
}

// AllocateNext returns the next available IP
func (s *Allocator) AllocateNext() (net.IP, error) {
	return s.allocator.AllocateNext()
}

// Allocate allocates a particular IP
func (s *Allocator) Allocate(ip net.IP) error {
	return s.allocator.Allocate(ip)
}

// AllocateMany allocates multiple IP addresses. The operation succeeds if all
// IPs can be allocated. On failure, all IPs are released again.
func (s *Allocator) AllocateMany(num int) ([]net.IP, error) {
	var ips []net.IP

	for i := 0; i < num; i++ {
		ip, err := s.AllocateNext()
		if err != nil {
			for _, ip = range ips {
				s.Release(ip)
			}
			return nil, err
		}

		ips = append(ips, ip)
	}

	return ips, nil
}

// Release releaes an IP address
func (s *Allocator) Release(ip net.IP) error {
	return s.allocator.Release(ip)
}

// ReleaseMany releases a slice of IP addresses
func (s *Allocator) ReleaseMany(ips []net.IP) {
	for _, ip := range ips {
		s.Release(ip)
	}
}

// GroupAllocator is an allocator to allocate from a group of subnets
type GroupAllocator struct {
	mutex      lock.RWMutex
	allocators map[string]*Allocator
}

// NewGroupAllocator returns a new group allocator based on a map of subnets
func NewGroupAllocator(subnets types.SubnetMap) (*GroupAllocator, error) {
	g := &GroupAllocator{
		allocators: map[string]*Allocator{},
	}

	// Create subnet allocators for all identified subnets
	for _, subnet := range subnets {
		if subnet.CIDR == nil {
			continue
		}

		a, err := NewAllocator(subnet.ID, subnet.CIDR)
		if err != nil {
			return nil, err
		}
		g.allocators[subnet.ID] = a
	}

	return g, nil
}

// GetPoolQuota returns the number of available IPs in all IP pools
func (g *GroupAllocator) GetPoolQuota() types.PoolQuotaMap {
	pool := types.PoolQuotaMap{}

	g.mutex.RLock()
	for subnetID, allocator := range g.allocators {
		pool[types.PoolID(subnetID)] = types.PoolQuota{AvailableIPs: allocator.Free()}
	}
	g.mutex.RUnlock()

	return pool
}

// GetAllocator returns the allocator for a subnet
func (g *GroupAllocator) GetAllocator(subnetID string) *Allocator {
	g.mutex.RLock()
	defer g.mutex.RUnlock()

	return g.allocators[subnetID]
}

// SubnetIDs returns the list of subnets covered by the group allocator
func (g *GroupAllocator) SubnetIDs() (ids []string) {
	g.mutex.RLock()
	defer g.mutex.RUnlock()

	for subnetID := range g.allocators {
		ids = append(ids, subnetID)
	}

	return
}
