// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package fake

import (
	"net/netip"

	"github.com/cilium/cilium/pkg/maps/egressmap"
)

func NewFakePolicyMap4V2() egressmap.PolicyMap4V2 {
	return &fakePolicyMap4V2{
		entries: make(map[egressmap.EgressPolicyKey4]egressmap.EgressPolicyVal4V2),
	}
}

type fakePolicyMap4V2 struct {
	entries map[egressmap.EgressPolicyKey4]egressmap.EgressPolicyVal4V2
}

var _ egressmap.PolicyMap4V2 = &fakePolicyMap4V2{}

func (m *fakePolicyMap4V2) Lookup(sourceIP netip.Addr, destCIDR netip.Prefix) (*egressmap.EgressPolicyVal4V2, error) {
	var key egressmap.EgressPolicyKey4
	key.SourceIP.FromAddr(sourceIP)
	key.DestCIDR.FromAddr(destCIDR.Addr())
	if val, ok := m.entries[key]; ok {
		return &val, nil
	}
	return nil, nil
}

func (m *fakePolicyMap4V2) Update(sourceIP netip.Addr, destCIDR netip.Prefix, egressIP netip.Addr, gatewayIP netip.Addr, egressIfindex uint32) error {
	// Implement the update logic here
	var (
		key egressmap.EgressPolicyKey4
		val egressmap.EgressPolicyVal4V2
	)
	key.SourceIP.FromAddr(sourceIP)
	key.DestCIDR.FromAddr(destCIDR.Addr())
	val.EgressIP.FromAddr(egressIP)
	val.GatewayIP.FromAddr(gatewayIP)
	val.EgressIfindex = egressIfindex
	m.entries[key] = val
	return nil
}

func (m *fakePolicyMap4V2) Delete(sourceIP netip.Addr, destCIDR netip.Prefix) error {
	// Implement the delete logic here
	var key egressmap.EgressPolicyKey4
	key.SourceIP.FromAddr(sourceIP)
	key.DestCIDR.FromAddr(destCIDR.Addr())
	delete(m.entries, key)
	return nil
}

func (m *fakePolicyMap4V2) IterateWithCallback(cb egressmap.EgressPolicyIterateCallbackV2) error {
	// Implement the iterate logic here
	for key, val := range m.entries {
		cb(&key, &val)
	}
	return nil
}

type fakePolicyMap6 struct {
	entries map[egressmap.EgressPolicyKey6]egressmap.EgressPolicyVal6
}

func NewFakePolicyMap6() egressmap.PolicyMap6 {
	return &fakePolicyMap6{
		entries: make(map[egressmap.EgressPolicyKey6]egressmap.EgressPolicyVal6),
	}
}

var _ egressmap.PolicyMap6 = &fakePolicyMap6{}

func (m *fakePolicyMap6) Lookup(sourceIP netip.Addr, destCIDR netip.Prefix) (*egressmap.EgressPolicyVal6, error) {
	var key egressmap.EgressPolicyKey6
	key.SourceIP.FromAddr(sourceIP)
	key.DestCIDR.FromAddr(destCIDR.Addr())
	if val, ok := m.entries[key]; ok {
		return &val, nil
	}
	return nil, nil
}

func (m *fakePolicyMap6) Update(sourceIP netip.Addr, destCIDR netip.Prefix, egressIP netip.Addr, gatewayIP netip.Addr, egressIfindex uint32) error {
	var (
		key egressmap.EgressPolicyKey6
		val egressmap.EgressPolicyVal6
	)
	key.SourceIP.FromAddr(sourceIP)
	key.DestCIDR.FromAddr(destCIDR.Addr())
	val.EgressIP.FromAddr(egressIP)
	val.GatewayIP.FromAddr(gatewayIP)
	val.EgressIfindex = egressIfindex
	m.entries[key] = val
	return nil
}

func (m *fakePolicyMap6) Delete(sourceIP netip.Addr, destCIDR netip.Prefix) error {
	var key egressmap.EgressPolicyKey6
	key.SourceIP.FromAddr(sourceIP)
	key.DestCIDR.FromAddr(destCIDR.Addr())
	delete(m.entries, key)
	return nil
}

func (m *fakePolicyMap6) IterateWithCallback(cb egressmap.EgressPolicyIterateCallback6) error {
	for key, val := range m.entries {
		cb(&key, &val)
	}
	return nil
}
