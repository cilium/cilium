// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package agent

import (
	"net/netip"

	iputil "github.com/cilium/cilium/pkg/ip"
	"github.com/cilium/cilium/pkg/slices"
)

// addrs converts string IPs to []iputil.Addr for use in tests.
func addrs(ips ...string) []iputil.Addr {
	return slices.Map(ips, func(s string) iputil.Addr {
		return iputil.AddrFrom(netip.MustParseAddr(s))
	})
}

// prefixes converts string CIDRs to []iputil.Prefix for use in tests.
func prefixes(ps ...string) []iputil.Prefix {
	return slices.Map(ps, func(s string) iputil.Prefix {
		return iputil.PrefixFrom(netip.MustParsePrefix(s))
	})
}

// ipMasqMapDummy is a no-op ip-masq-agent map, for the tests that need an
// IPMasqAgent to read its non-masqueraded CIDRs from.
type ipMasqMapDummy struct{}

func (m ipMasqMapDummy) Update(netip.Prefix) error { return nil }

func (m ipMasqMapDummy) Delete(netip.Prefix) error { return nil }

func (m ipMasqMapDummy) Dump() ([]netip.Prefix, error) { return []netip.Prefix{}, nil }
