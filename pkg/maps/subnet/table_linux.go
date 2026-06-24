// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build linux

package subnet

import (
	"encoding"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/types"
)

// BinaryKey returns the binary representation of the subnet prefix for the eBPF map key.
func (s SubnetTableEntry) BinaryKey() encoding.BinaryMarshaler {
	var ip types.IPv6
	var family uint8

	// Convert netip.Prefix to SubnetMapKey
	addr := s.Key.Addr()

	// Copy the IP address bytes into the IPv6 array
	if addr.Is4() {
		// For IPv4, copy to the last 4 bytes (IPv4-mapped IPv6 format)
		ipv4 := addr.As4()
		copy(ip[:], ipv4[:])
		family = bpf.EndpointKeyIPv4
	} else {
		// For IPv6, copy all 16 bytes
		ipv6 := addr.As16()
		copy(ip[:], ipv6[:])
		family = bpf.EndpointKeyIPv6
	}

	k := SubnetMapKey{
		Prefixlen: getStaticPrefixBits() + uint32(s.Key.Bits()),
		Family:    family,
		IP:        ip,
	}
	return bpf.StructBinaryMarshaler{Target: &k}
}

// BinaryValue returns the binary representation of the identity for the eBPF map value.
func (s SubnetTableEntry) BinaryValue() encoding.BinaryMarshaler {
	v := SubnetMapValue{
		Identity: s.Value,
	}
	return bpf.StructBinaryMarshaler{Target: &v}
}
