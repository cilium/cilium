// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package types

import (
	"net"
	"testing"

	check "github.com/cilium/checkmate"

	"github.com/cilium/cilium/pkg/checker"
)

func Test(t *testing.T) {
	check.TestingT(t)
}

type TypesSuite struct{}

var _ = check.Suite(&TypesSuite{})

func (b *TypesSuite) TestTagsMatch(c *check.C) {
	c.Assert(Tags{"1": "1", "2": "2"}.Match(Tags{"1": "1"}), check.Equals, true)
	c.Assert(Tags{"1": "1", "2": "2"}.Match(Tags{"2": "2"}), check.Equals, true)
	c.Assert(Tags{"1": "1", "2": "2"}.Match(Tags{"3": "3"}), check.Equals, false)
}

type mockInterface struct {
	id    string
	pools map[string][]net.IP
}

func (m *mockInterface) InterfaceID() string {
	return m.id
}

func (m *mockInterface) ForeachAddress(instanceID string, fn AddressIterator) error {
	for poolID, ips := range m.pools {
		for _, ip := range ips {
			if err := fn(instanceID, m.id, ip.String(), poolID, ip); err != nil {
				return err
			}
		}
	}

	return nil
}

func (e *TypesSuite) TestForeachAddresses(c *check.C) {
	m := NewInstanceMap()
	m.Update("i-1", InterfaceRevision{
		Resource: &mockInterface{
			id: "intf0",
			pools: map[string][]net.IP{
				"s1": {net.ParseIP("1.1.1.1"), net.ParseIP("2.2.2.2")},
			},
		},
	})
	m.Update("i-2", InterfaceRevision{
		Resource: &mockInterface{
			id: "intf0",
			pools: map[string][]net.IP{
				"s1": {net.ParseIP("3.3.3.3"), net.ParseIP("4.4.4.4")},
			},
		},
	})

	// Iterate over all instances
	addresses := 0
	m.ForeachAddress("", func(instanceID, interfaceID, ip, poolID string, address Address) error {
		_, ok := address.(net.IP)
		c.Assert(ok, check.Equals, true)
		addresses++
		return nil
	})
	c.Assert(addresses, check.Equals, 4)

	// Iterate over "i-1"
	addresses = 0
	m.ForeachAddress("i-1", func(instanceID, interfaceID, ip, poolID string, address Address) error {
		addresses++
		return nil
	})
	c.Assert(addresses, check.Equals, 2)

	// Iterate over all interfaces
	interfaces := 0
	m.ForeachInterface("", func(instanceID, interfaceID string, iface InterfaceRevision) error {
		interfaces++
		return nil
	})
	c.Assert(interfaces, check.Equals, 2)
}

func (e *TypesSuite) TestGetInterface(c *check.C) {
	m := NewInstanceMap()
	rev := InterfaceRevision{
		Resource: &mockInterface{
			id: "intf0",
			pools: map[string][]net.IP{
				"s1": {net.ParseIP("1.1.1.1"), net.ParseIP("2.2.2.2")},
			},
		},
	}
	m.Update("i-1", rev)

	_, ok := m.GetInterface("inexistent", "inexistent")
	c.Assert(ok, check.Equals, false)
	_, ok = m.GetInterface("i-1", "inexistent")
	c.Assert(ok, check.Equals, false)
	_, ok = m.GetInterface("inexistent", "intf0")
	c.Assert(ok, check.Equals, false)
	intf, ok := m.GetInterface("i-1", "intf0")
	c.Assert(ok, check.Equals, true)

	c.Assert(intf, checker.DeepEquals, rev)
}

func (e *TypesSuite) TestInstanceMapNumInstances(c *check.C) {
	m := NewInstanceMap()
	m.Update("i-1", InterfaceRevision{
		Resource: &mockInterface{
			id: "intf0",
			pools: map[string][]net.IP{
				"s1": {net.ParseIP("1.1.1.1"), net.ParseIP("2.2.2.2")},
			},
		},
	})
	m.Update("i-2", InterfaceRevision{
		Resource: &mockInterface{
			id: "intf0",
			pools: map[string][]net.IP{
				"s1": {net.ParseIP("3.3.3.3"), net.ParseIP("4.4.4.4")},
			},
		},
	})
	m.Update("i-2", InterfaceRevision{
		Resource: &mockInterface{
			id: "intf1",
			pools: map[string][]net.IP{
				"s1": {net.ParseIP("4.4.4.4"), net.ParseIP("5.5.5.5")},
			},
		},
	})

	c.Assert(m.NumInstances(), check.Equals, 2)
}

func (e *TypesSuite) TestFirstSubnetWithAvailableAddresses(c *check.C) {
	sm := SubnetMap{
		"s0": &Subnet{AvailableAddresses: 0},
		"s1": &Subnet{AvailableAddresses: 1},
		"s2": &Subnet{AvailableAddresses: 0},
	}

	subnetID, addresses := sm.FirstSubnetWithAvailableAddresses([]PoolID{})
	c.Assert(subnetID, check.Equals, PoolID("s1"))
	c.Assert(addresses, check.Equals, 1)

	sm = SubnetMap{
		"s0": &Subnet{AvailableAddresses: 0},
		"s1": &Subnet{AvailableAddresses: 0},
		"s2": &Subnet{AvailableAddresses: 0},
	}
	subnetID, addresses = sm.FirstSubnetWithAvailableAddresses([]PoolID{})
	c.Assert(subnetID, check.Equals, PoolNotExists)
	c.Assert(addresses, check.Equals, 0)

	sm = SubnetMap{
		"s0": &Subnet{AvailableAddresses: 0},
		"s1": &Subnet{AvailableAddresses: 10},
		"s2": &Subnet{AvailableAddresses: 20},
	}
	subnetID, addresses = sm.FirstSubnetWithAvailableAddresses([]PoolID{"s0", "s1"})
	c.Assert(subnetID, check.Equals, PoolID("s1"))
	c.Assert(addresses, check.Equals, 10)
}
