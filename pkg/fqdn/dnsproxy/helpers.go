// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package dnsproxy

import (
	"fmt"
	"net/netip"

	"github.com/cilium/dns"

	"github.com/cilium/cilium/pkg/u8proto"
)

// lookupTargetDNSServer finds the intended DNS target server for a specific
// request (passed in via ServeDNS). The IP:port:protocol combination is
// returned.
func lookupTargetDNSServer(w dns.ResponseWriter) (proto u8proto.U8proto, server netip.AddrPort, err error) {
	addr := w.LocalAddr()
	ap, err := netip.ParseAddrPort(addr.String())
	if err != nil {
		return u8proto.ANY, netip.AddrPort{}, fmt.Errorf("failed to parse DNS target server address: %w", err)
	}

	switch addr.Network() {
	case "tcp":
		return u8proto.TCP, ap, nil
	case "udp":
		return u8proto.UDP, ap, nil
	default:
		return u8proto.ANY, netip.AddrPort{}, fmt.Errorf("unknown protocol %q", addr.Network())
	}
}
