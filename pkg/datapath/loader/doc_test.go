// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package loader

import (
	"net/netip"

	"gopkg.in/check.v1"
	. "gopkg.in/check.v1"

	"github.com/cilium/cilium/pkg/maps/ctmap"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/option"
)

func (s *LoaderTestSuite) SetUpTest(c *C) {
	ctmap.InitMapInfo(option.CTMapEntriesGlobalTCPDefault, option.CTMapEntriesGlobalAnyDefault, true, true, true)
	node.InitDefaultPrefix("")
	addr, ok := netip.AddrFromSlice(templateIPv4[:])
	c.Assert(ok, check.Equals, true)
	node.SetInternalIPv4Router(&addr)
	node.SetIPv4Loopback(&addr)
}
