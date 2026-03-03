// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package index

import (
	"bytes"
	"net"
	"net/netip"
)

func NetIP(ip net.IP) Key {
	// Use the 16-byte form to have a constant-size key.
	return bytes.Clone(ip.To16())
}

func NetIPAddr(addr netip.Addr) Key {
	// Use the 16-byte form to have a constant-size key.
	buf := addr.As16()
	return buf[:]
}

func NetIPAddrString(s string) (Key, error) {
	addr, err := netip.ParseAddr(s)
	if err != nil {
		return Key{}, err
	}
	return NetIPAddr(addr), nil
}

func NetIPPrefix(prefix netip.Prefix) Key {
	// Use the 16-byte form plus bits to have a constant-size key.
	addrBytes := prefix.Masked().Addr().As16()
	return append(addrBytes[:], uint8(prefix.Bits()))
}

func NetIPPrefixString(s string) (Key, error) {
	prefix, err := netip.ParsePrefix(s)
	if err != nil {
		return Key{}, err
	}
	return NetIPPrefix(prefix), nil
}
