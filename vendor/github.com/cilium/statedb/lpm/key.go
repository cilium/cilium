// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package lpm

import (
	"encoding/binary"
	"fmt"
	"net/netip"

	"github.com/cilium/statedb/index"
)

// NetIPPrefixToIndexKey encodes prefix as an LPM index key. IPv4-mapped IPv6
// prefixes contained in ::ffff:0:0/96 are canonicalized to IPv4.
func NetIPPrefixToIndexKey(prefix netip.Prefix) index.Key {
	const (
		familyBits           = 8
		mappedIPv4PrefixBits = 96
	)

	prefix = prefix.Masked()
	if prefix.Bits() >= mappedIPv4PrefixBits && prefix.Addr().Is4In6() {
		prefix = netip.PrefixFrom(prefix.Addr().Unmap(), prefix.Bits()-mappedIPv4PrefixBits)
	}

	addr := prefix.Addr()
	var data [1 + 16]byte
	if addr.Is4() {
		data[0] = 4
		addr4 := addr.As4()
		copy(data[1:], addr4[:])
		return mustEncodeLPMKey(data[:1+len(addr4)], PrefixLen(familyBits+prefix.Bits()))
	}

	data[0] = 6
	addr16 := addr.As16()
	copy(data[1:], addr16[:])
	return mustEncodeLPMKey(data[:1+len(addr16)], PrefixLen(familyBits+prefix.Bits()))
}

func NetIPPrefix4ToIndexKey(prefix netip.Prefix) index.Key {
	addr := prefix.Addr().As4()
	bits := prefix.Bits()
	return mustEncodeLPMKey(
		addr[:],
		PrefixLen(bits),
	)
}

func mustEncodeLPMKey(data []byte, prefixLen PrefixLen) index.Key {
	key, err := EncodeLPMKey(data, prefixLen)
	if err != nil {
		panic(err)
	}
	return key
}

func lpmDataLen(prefixLen PrefixLen) int {
	return (int(prefixLen) + 7) / 8
}

// EncodeLPMKey encodes data and its prefix length as an LPM index key. It
// returns an error if data does not contain enough bits for prefixLen.
func EncodeLPMKey(data []byte, prefixLen PrefixLen) (index.Key, error) {
	dataLen := lpmDataLen(prefixLen)
	if dataLen > len(data) {
		return nil, fmt.Errorf("invalid LPM key, data too short (%d) for prefix length (%d)", len(data), prefixLen)
	}
	key := make(index.Key, dataLen, dataLen+2)
	copy(key, data[:dataLen])
	if dataLen > 0 {
		if rem := prefixLen % 8; rem != 0 {
			key[dataLen-1] &= 0xff << (8 - rem)
		}
	}
	return binary.BigEndian.AppendUint16(key, prefixLen), nil
}

func DecodeLPMKey(key index.Key) (data []byte, prefixLen PrefixLen) {
	if len(key) < 2 {
		panic("invalid LPM key")
	}
	data = key[:len(key)-2]
	prefixLen = binary.BigEndian.Uint16(key[len(key)-2:])
	if lpmDataLen(prefixLen) > len(data) {
		panic("prefix length too long in LPM key")
	}
	return
}
