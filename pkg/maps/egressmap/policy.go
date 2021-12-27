// SPDX-License-Identifier: Apache-2.0
// Copyright 2021 Authors of Cilium

package egressmap

import (
	"fmt"
	"net"
	"unsafe"

	"github.com/cilium/cilium/pkg/ebpf"
	"github.com/cilium/cilium/pkg/types"
)

const (
	// PolicyStaticPrefixBits represents the size in bits of the static
	// prefix part of an egress policy key (i.e. the source IP).
	PolicyStaticPrefixBits = uint32(unsafe.Sizeof(types.IPv4{}) * 8)
)

// EgressPolicyKey4 is the key of an egress policy map.
type EgressPolicyKey4 struct {
	// PrefixLen is full 32 bits of SourceIP + DestCIDR's mask bits
	PrefixLen uint32

	SourceIP types.IPv4
	DestCIDR types.IPv4
}

// EgressPolicyVal4 is the value of an egress policy map.
type EgressPolicyVal4 struct {
	EgressIP  types.IPv4
	GatewayIP types.IPv4
}

// egressPolicyMap is the internal representation of an egress policy map.
type egressPolicyMap struct {
	*ebpf.Map
}

// initEgressPolicyMap initializes the egress policy map.
func initEgressPolicyMap(policyMapName string, create bool) error {
	var m *ebpf.Map

	if create {
		m = ebpf.NewMap(&ebpf.MapSpec{
			Name:       policyMapName,
			Type:       ebpf.LPMTrie,
			KeySize:    uint32(unsafe.Sizeof(EgressPolicyKey4{})),
			ValueSize:  uint32(unsafe.Sizeof(EgressPolicyVal4{})),
			MaxEntries: uint32(MaxPolicyEntries),
			Pinning:    ebpf.PinByName,
		})

		if err := m.OpenOrCreate(); err != nil {
			return err
		}
	} else {
		var err error

		if m, err = ebpf.OpenMap(policyMapName); err != nil {
			return err
		}
	}

	EgressPolicyMap = &egressPolicyMap{
		m,
	}

	return nil
}

// NewEgressPolicyKey4 returns a new EgressPolicyKey4 object representing the
// (source IP, destination CIDR) tuple.
func NewEgressPolicyKey4(sourceIP, destIP net.IP, destinationMask net.IPMask) EgressPolicyKey4 {
	key := EgressPolicyKey4{}

	ones, _ := destinationMask.Size()
	copy(key.SourceIP[:], sourceIP.To4())
	copy(key.DestCIDR[:], destIP.To4())
	key.PrefixLen = PolicyStaticPrefixBits + uint32(ones)

	return key
}

// NewEgressPolicyVal4 returns a new EgressPolicyVal4 object representing for
// the given egress IP and gateway IPs
func NewEgressPolicyVal4(egressIP, gatewayIP net.IP) EgressPolicyVal4 {
	val := EgressPolicyVal4{}

	copy(val.EgressIP[:], egressIP.To4())
	copy(val.GatewayIP[:], gatewayIP.To4())

	return val
}

// Match returns true if the sourceIP and destCIDR parameters match the egress
// policy key.
func (k *EgressPolicyKey4) Match(sourceIP net.IP, destCIDR *net.IPNet) bool {
	return k.GetSourceIP().Equal(sourceIP) &&
		k.GetDestCIDR().String() == destCIDR.String()
}

// GetSourceIP returns the egress policy key's source IP.
func (k *EgressPolicyKey4) GetSourceIP() net.IP {
	return k.SourceIP.IP()
}

// GetDestCIDR returns the egress policy key's destination CIDR.
func (k *EgressPolicyKey4) GetDestCIDR() *net.IPNet {
	return &net.IPNet{
		IP:   k.DestCIDR.IP(),
		Mask: net.CIDRMask(int(k.PrefixLen-PolicyStaticPrefixBits), 32),
	}
}

// Match returns true if the egressIP and gatewayIP parameters match the egress
// policy value.
func (v *EgressPolicyVal4) Match(egressIP, gatewayIP net.IP) bool {
	return v.GetEgressIP().Equal(egressIP) &&
		v.GetGatewayIP().Equal(gatewayIP)
}

// GetEgressIP returns the egress policy value's egress IP.
func (v *EgressPolicyVal4) GetEgressIP() net.IP {
	return v.EgressIP.IP()
}

// GetGatewayIP returns the egress policy value's gateway IP.
func (v *EgressPolicyVal4) GetGatewayIP() net.IP {
	return v.GatewayIP.IP()
}

// String returns the string representation of an egress policy value.
func (v *EgressPolicyVal4) String() string {
	return fmt.Sprintf("%s %s", v.GetGatewayIP(), v.GetEgressIP())
}

// Lookup returns the egress policy object associated with the provided (source
// IP, destination CIDR) tuple.
func (m *egressPolicyMap) Lookup(sourceIP net.IP, destCIDR net.IPNet) (*EgressPolicyVal4, error) {
	key := NewEgressPolicyKey4(sourceIP, destCIDR.IP, destCIDR.Mask)
	val := EgressPolicyVal4{}

	err := m.Map.Lookup(&key, &val)

	return &val, err
}

// Update updates the (sourceIP, destCIDR) egress policy entry with the provided
// egress and gateway IPs.
func (m *egressPolicyMap) Update(sourceIP net.IP, destCIDR net.IPNet, egressIP, gatewayIP net.IP) error {
	key := NewEgressPolicyKey4(sourceIP, destCIDR.IP, destCIDR.Mask)
	val := NewEgressPolicyVal4(egressIP, gatewayIP)

	return m.Map.Update(key, val, 0)
}

// Delete deletes the (sourceIP, destCIDR) egress policy entry.
func (m *egressPolicyMap) Delete(sourceIP net.IP, destCIDR net.IPNet) error {
	key := NewEgressPolicyKey4(sourceIP, destCIDR.IP, destCIDR.Mask)

	return m.Map.Delete(key)
}

// EgressPolicyIterateCallback represents the signature of the callback function
// expected by the IterateWithCallback method, which in turn is used to iterate
// all the keys/values of an egress policy map.
type EgressPolicyIterateCallback func(*EgressPolicyKey4, *EgressPolicyVal4)

// IterateWithCallback iterates through all the keys/values of an egress policy
// map, passing each key/value pair to the cb callback.
func (m egressPolicyMap) IterateWithCallback(cb EgressPolicyIterateCallback) error {
	return m.Map.IterateWithCallback(&EgressPolicyKey4{}, &EgressPolicyVal4{},
		func(k, v interface{}) {
			key := k.(*EgressPolicyKey4)
			value := v.(*EgressPolicyVal4)

			cb(key, value)
		})
}
