// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package loadbalancer

import (
	"net/netip"

	"github.com/cilium/cilium/pkg/datapath/tables"
)

// RSSConfig contains the source prefixes used for DSR IPIP RSS.
type RSSConfig struct {
	ipv4Prefix netip.Prefix
	ipv6Prefix netip.Prefix
}

// NewRSSConfig resolves configured RSS prefixes, falling back to preferred
// addresses on the direct-routing device and, finally, unspecified addresses.
func NewRSSConfig(ipv4Prefix, ipv6Prefix netip.Prefix, directRoutingDevice *tables.Device) RSSConfig {
	config := RSSConfig{
		ipv4Prefix: netip.PrefixFrom(netip.IPv4Unspecified(), 32),
		ipv6Prefix: netip.PrefixFrom(netip.IPv6Unspecified(), 128),
	}

	if ipv4Prefix.IsValid() {
		config.ipv4Prefix = ipv4Prefix
	}
	if ipv6Prefix.IsValid() {
		config.ipv6Prefix = ipv6Prefix
	}

	if directRoutingDevice == nil {
		return config
	}

	if !ipv4Prefix.IsValid() {
		if addr := tables.PreferredIPv4Address(directRoutingDevice.Addrs); addr.IsValid() {
			config.ipv4Prefix = netip.PrefixFrom(addr, 32)
		}
	}
	if !ipv6Prefix.IsValid() {
		if addr := tables.PreferredIPv6Address(directRoutingDevice.Addrs); addr.IsValid() {
			config.ipv6Prefix = netip.PrefixFrom(addr, 128)
		}
	}

	return config
}

// IPv4Prefix returns the resolved IPv4 RSS prefix.
func (c RSSConfig) IPv4Prefix() netip.Prefix {
	if !c.ipv4Prefix.IsValid() {
		return netip.PrefixFrom(netip.IPv4Unspecified(), 32)
	}
	return c.ipv4Prefix
}

// IPv6Prefix returns the resolved IPv6 RSS prefix.
func (c RSSConfig) IPv6Prefix() netip.Prefix {
	if !c.ipv6Prefix.IsValid() {
		return netip.PrefixFrom(netip.IPv6Unspecified(), 128)
	}
	return c.ipv6Prefix
}
