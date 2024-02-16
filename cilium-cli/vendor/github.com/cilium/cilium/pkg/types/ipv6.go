// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package types

import (
	"net"
	"net/netip"
)

// IPv6 is the binary representation for encoding in binary structs.
type IPv6 [16]byte

func (v6 IPv6) IP() net.IP {
	return v6[:]
}

func (v6 IPv6) Addr() netip.Addr {
	return netip.AddrFrom16(v6)
}

func (v6 IPv6) String() string {
	return v6.IP().String()
}

// DeepCopyInto is a deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (v6 *IPv6) DeepCopyInto(out *IPv6) {
	copy(out[:], v6[:])
}

// FromAddr will populate the receiver with the specified address if and only
// if the provided address is a valid IPv6 address. Any other address,
// including the "invalid ip" value netip.Addr{} will zero the receiver.
func (v6 *IPv6) FromAddr(addr netip.Addr) {
	if addr.Is6() {
		a := IPv6(addr.As16())
		copy(v6[:], a[:])
	} else {
		clear(v6[:])
	}
}
