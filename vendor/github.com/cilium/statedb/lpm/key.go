// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package lpm

import (
	"encoding/binary"
	"fmt"
	"net/netip"

	"github.com/cilium/statedb/index"
)

func NetIPPrefixToIndexKey(prefix netip.Prefix) index.Key {
	addr := prefix.Addr().As16()
	bits := prefix.Bits()
	if prefix.Addr().Is4() {
		// As we're working with the 16-byte format we'll need to add
		// the 12 bytes of the IPv4-mapped IPv6 address prefix (::FFFF:).
		bits += 12 * 8
	}
	return EncodeLPMKey(
		addr[:],
		PrefixLen(bits),
	)
}

func NetIPPrefix4ToIndexKey(prefix netip.Prefix) index.Key {
	addr := prefix.Addr().As4()
	bits := prefix.Bits()
	return EncodeLPMKey(
		addr[:],
		PrefixLen(bits),
	)
}

func EncodeLPMKey(data []byte, prefixLen PrefixLen) index.Key {
	dataLen := (prefixLen + 7) / 8
	if int(dataLen) > len(data) {
		panic(fmt.Sprintf("invalid LPM key, data too short (%d) for prefix length (%d)", len(data), prefixLen))
	}
	key := make(index.Key, dataLen, dataLen+2)
	copy(key, data[:dataLen])
	if dataLen > 0 {
		if rem := prefixLen % 8; rem != 0 {
			key[dataLen-1] &= 0xff << (8 - rem)
		}
	}
	return binary.BigEndian.AppendUint16(key, prefixLen)
}

func DecodeLPMKey(key index.Key) (data []byte, prefixLen PrefixLen) {
	if len(key) < 2 {
		panic("invalid LPM key")
	}
	data = key[:len(key)-2]
	prefixLen = binary.BigEndian.Uint16(key[len(key)-2:])
	if int((prefixLen+7)/8) > len(data) {
		panic("prefix length too long in LPM key")
	}
	return
}
