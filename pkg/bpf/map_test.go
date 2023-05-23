// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package bpf

import (
	. "github.com/cilium/checkmate"
)

func (s *BPFTestSuite) TestExtractCommonName(c *C) {
	c.Assert(extractCommonName("cilium_calls_1157"), Equals, "calls")
	c.Assert(extractCommonName("cilium_calls_netdev_ns_1"), Equals, "calls")
	c.Assert(extractCommonName("cilium_calls_overlay_2"), Equals, "calls")
	c.Assert(extractCommonName("cilium_ct4_global"), Equals, "ct4_global")
	c.Assert(extractCommonName("cilium_ct_any4_global"), Equals, "ct_any4_global")
	c.Assert(extractCommonName("cilium_events"), Equals, "events")
	c.Assert(extractCommonName("cilium_ipcache"), Equals, "ipcache")
	c.Assert(extractCommonName("cilium_lb4_reverse_nat"), Equals, "lb4_reverse_nat")
	c.Assert(extractCommonName("cilium_lb4_rr_seq"), Equals, "lb4_rr_seq")
	c.Assert(extractCommonName("cilium_lb4_services"), Equals, "lb4_services")
	c.Assert(extractCommonName("cilium_lxc"), Equals, "lxc")
	c.Assert(extractCommonName("cilium_metrics"), Equals, "metrics")
	c.Assert(extractCommonName("cilium_policy"), Equals, "policy")
	c.Assert(extractCommonName("cilium_policy_1157"), Equals, "policy")
	c.Assert(extractCommonName("cilium_policy_reserved_1"), Equals, "policy")
	c.Assert(extractCommonName("cilium_proxy4"), Equals, "proxy4")
	c.Assert(extractCommonName("cilium_tunnel_map"), Equals, "tunnel_map")
}
