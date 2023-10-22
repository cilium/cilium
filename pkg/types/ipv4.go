// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package types

import (
	"net"
	"net/netip"
)

// IPv4 is the binary representation for encoding in binary structs.
type IPv4 [4]byte

func (v4 IPv4) IsZero() bool {
	return v4[0] == 0 && v4[1] == 0 && v4[2] == 0 && v4[3] == 0
}

func (v4 IPv4) IP() net.IP {
	return v4[:]
}

func (v4 IPv4) Addr() netip.Addr {
	return netip.AddrFrom4(v4)
}

func (v4 IPv4) String() string {
	return v4.IP().String()
}

// DeepCopyInto is a deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (v4 *IPv4) DeepCopyInto(out *IPv4) {
	copy(out[:], v4[:])
}

// FromAddr will populate the receiver with the specified address if and only
// if the provided address is a valid IPv4 address. Any other address,
// including the "invalid ip" value netip.Addr{} will zero the receiver.
func (v4 *IPv4) FromAddr(addr netip.Addr) {
	if addr.Is4() {
		a := IPv4(addr.As4())
		copy(v4[:], a[:])
	} else {
		clear(v4[:])
	}
}
