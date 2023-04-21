// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package allocator

import (
	"errors"
	"net"

	"github.com/sirupsen/logrus"

	"github.com/cilium/cilium/pkg/ipam/types"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

var (
	errPoolNotExists = errors.New("pool does not exist")
	log              = logging.DefaultLogger.WithField(logfields.LogSubsys, "ipam-allocator")
)

// PoolGroupAllocator is an allocator to allocate from a group of subnets
type PoolGroupAllocator struct {
	mutex      lock.RWMutex
	allocators map[types.PoolID]*PoolAllocator
}

// NewPoolGroupAllocator returns a new allocator able to allocate out of a group of pools.
func NewPoolGroupAllocator(subnets types.SubnetMap) (*PoolGroupAllocator, error) {
	g := &PoolGroupAllocator{allocators: map[types.PoolID]*PoolAllocator{}}

	// Create subnet allocators for all identified subnets
	for _, subnet := range subnets {
		if subnet.CIDR == nil {
			continue
		}

		a, err := NewPoolAllocator(types.PoolID(subnet.ID), subnet.CIDR)
		if err != nil {
			return nil, err
		}
		g.allocators[types.PoolID(subnet.ID)] = a
	}

	return g, nil
}

// AddressIterator is the required interface to allow iterating over a
// structure which holds a set of addresses
type AddressIterator interface {
	ForeachAddress(instanceID string, fn types.AddressIterator) error
}

// ReserveAddresses reserves all addresses returned by an AddressIterator.
// Invalid IPs or failures to allocate are logged
func (g *PoolGroupAllocator) ReserveAddresses(iterator AddressIterator) {
	iterator.ForeachAddress("", func(instanceID, interfaceID, ipString, poolID string, address types.Address) error {
		ip := net.ParseIP(ipString)
		if ip != nil {
			if err := g.Allocate(types.PoolID(poolID), ip); err != nil {
				log.WithFields(logrus.Fields{
					"instance":  instanceID,
					"interface": interfaceID,
					"ip":        ipString,
				}).WithError(err).Warning("Unable to allocate IP in internal allocator")
			}
		} else {
			log.WithFields(logrus.Fields{
				"instance":  instanceID,
				"interface": interfaceID,
				"ip":        ipString,
			}).Warning("Unable to parse IP")
		}
		return nil
	})
}

// GetPoolQuota returns the number of available IPs in all IP pools
func (g *PoolGroupAllocator) GetPoolQuota() types.PoolQuotaMap {
	pool := types.PoolQuotaMap{}

	g.mutex.RLock()
	for poolID, allocator := range g.allocators {
		pool[poolID] = types.PoolQuota{AvailableIPs: allocator.Free()}
	}
	g.mutex.RUnlock()

	return pool
}

// AllocateMany allocates multiple IP addresses. The operation succeeds if all
// IPs can be allocated. On failure, all IPs are released again.
func (g *PoolGroupAllocator) AllocateMany(poolID types.PoolID, num int) ([]net.IP, error) {
	allocator := g.getAllocator(poolID)
	if allocator == nil {
		return nil, errPoolNotExists
	}

	return allocator.AllocateMany(num)
}

// Allocate allocates a paritcular IP in a particular pool
func (g *PoolGroupAllocator) Allocate(poolID types.PoolID, ip net.IP) error {
	var allocator *PoolAllocator

	switch poolID {
	case types.PoolUnspec:
		g.mutex.RLock()
		for _, a := range g.allocators {
			if a.AllocationCIDR.IPNet.Contains(ip) {
				allocator = a
				break
			}
		}
		g.mutex.RUnlock()
	default:
		allocator = g.getAllocator(poolID)
	}

	if allocator == nil {
		return errPoolNotExists
	}

	return allocator.Allocate(ip)
}

// ReleaseMany releases a slice of IP addresses. This function has no effect
func (g *PoolGroupAllocator) ReleaseMany(poolID types.PoolID, ips []net.IP) error {
	allocator := g.getAllocator(poolID)
	if allocator == nil {
		return errPoolNotExists
	}

	allocator.ReleaseMany(ips)
	return nil
}

// getAllocator returns the allocator for a subnet
func (g *PoolGroupAllocator) getAllocator(poolID types.PoolID) *PoolAllocator {
	g.mutex.RLock()
	defer g.mutex.RUnlock()

	return g.allocators[poolID]
}
