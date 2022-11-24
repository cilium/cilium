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

func (v6 IPv6) MarshalText() ([]byte, error) {
	return []byte(v6.String()), nil
}

func (v4 *IPv6) UnmarshalText(text []byte) error {
	addr, err := netip.ParseAddr(string(text))
	if err != nil {
		return err
	}
	ip := addr.As16()
	copy(v4[:], ip[:])
	return nil
}

// DeepCopyInto is a deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (v6 *IPv6) DeepCopyInto(out *IPv6) {
	copy(out[:], v6[:])
}
