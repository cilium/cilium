// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package index

import (
	"bytes"
	"net"
	"net/netip"
)

func NetIP(ip net.IP) Key {
	return bytes.Clone(ip)
}

func NetIPAddr(addr netip.Addr) Key {
	buf, _ := addr.MarshalBinary()
	return buf
}

func NetIPPrefix(prefix netip.Prefix) Key {
	buf, _ := prefix.MarshalBinary()
	return buf
}
