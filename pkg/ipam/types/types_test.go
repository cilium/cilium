// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package types

import (
	"net"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestTagsMatch(t *testing.T) {
	require.True(t, Tags{"1": "1", "2": "2"}.Match(Tags{"1": "1"}))
	require.True(t, Tags{"1": "1", "2": "2"}.Match(Tags{"2": "2"}))
	require.False(t, Tags{"1": "1", "2": "2"}.Match(Tags{"3": "3"}))
}

type mockInterface struct {
	id    string
	pools map[string][]net.IP
}

func (m *mockInterface) DeepCopyInterface() Interface {
	mc := &mockInterface{
		id:    m.id,
		pools: map[string][]net.IP{},
	}
	for id, pool := range m.pools {
		pc := make([]net.IP, 0, len(pool))
		for _, ip := range pool {
			ipc := net.IP{}
			copy(ipc, ip)
			pc = append(pc, ipc)
		}
		mc.pools[id] = pc
	}
	return mc
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

func TestForeachAddresses(t *testing.T) {
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
		require.True(t, ok)
		addresses++
		return nil
	})
	require.Equal(t, 4, addresses)

	// Iterate over "i-1"
	addresses = 0
	m.ForeachAddress("i-1", func(instanceID, interfaceID, ip, poolID string, address Address) error {
		addresses++
		return nil
	})
	require.Equal(t, 2, addresses)

	// Iterate over all interfaces
	interfaces := 0
	m.ForeachInterface("", func(instanceID, interfaceID string, iface InterfaceRevision) error {
		interfaces++
		return nil
	})
	require.Equal(t, 2, interfaces)
}

func TestGetInterface(t *testing.T) {
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
	require.False(t, ok)
	_, ok = m.GetInterface("i-1", "inexistent")
	require.False(t, ok)
	_, ok = m.GetInterface("inexistent", "intf0")
	require.False(t, ok)
	intf, ok := m.GetInterface("i-1", "intf0")
	require.True(t, ok)

	require.Equal(t, rev, intf)
}

func TestInstanceMapNumInstances(t *testing.T) {
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

	require.Equal(t, 2, m.NumInstances())
}

func TestFirstSubnetWithAvailableAddresses(t *testing.T) {
	sm := SubnetMap{
		"s0": &Subnet{AvailableAddresses: 0},
		"s1": &Subnet{AvailableAddresses: 1},
		"s2": &Subnet{AvailableAddresses: 0},
	}

	subnetID, addresses := sm.FirstSubnetWithAvailableAddresses([]PoolID{})
	require.Equal(t, PoolID("s1"), subnetID)
	require.Equal(t, 1, addresses)

	sm = SubnetMap{
		"s0": &Subnet{AvailableAddresses: 0},
		"s1": &Subnet{AvailableAddresses: 0},
		"s2": &Subnet{AvailableAddresses: 0},
	}
	subnetID, addresses = sm.FirstSubnetWithAvailableAddresses([]PoolID{})
	require.Equal(t, PoolNotExists, subnetID)
	require.Equal(t, 0, addresses)

	sm = SubnetMap{
		"s0": &Subnet{AvailableAddresses: 0},
		"s1": &Subnet{AvailableAddresses: 10},
		"s2": &Subnet{AvailableAddresses: 20},
	}
	subnetID, addresses = sm.FirstSubnetWithAvailableAddresses([]PoolID{"s0", "s1"})
	require.Equal(t, PoolID("s1"), subnetID)
	require.Equal(t, 10, addresses)
}
