// Copyright 2016-2020 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// +build !privileged_tests

package ipam

import (
	"net"

	"github.com/cilium/cilium/pkg/checker"
	"github.com/cilium/cilium/pkg/cidr"
	"github.com/cilium/cilium/pkg/datapath/linux/route"
	"github.com/cilium/cilium/pkg/mac"
	"github.com/cilium/cilium/pkg/node/addressing"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"
	"github.com/cilium/cilium/pkg/option"

	"github.com/vishvananda/netlink"
	"gopkg.in/check.v1"
)

func (s *IPAMSuite) TestNodeRulesAndRoutes(c *check.C) {
	prevEgressMultiHomeIPRuleCompat := option.Config.EgressMultiHomeIPRuleCompat
	prevEnableIPv4Masquerade := option.Config.EnableIPv4Masquerade
	defer func() {
		option.Config.EgressMultiHomeIPRuleCompat = prevEgressMultiHomeIPRuleCompat
		option.Config.EnableIPv4Masquerade = prevEnableIPv4Masquerade
	}()

	node := &nodeTypes.Node{
		IPv4AllocCIDR: cidr.MustParseCIDR("10.1.2.0/24"),
		IPv4NativeRoutingCIDRs: []*cidr.CIDR{
			cidr.MustParseCIDR("10.1.0.0/16"),
			cidr.MustParseCIDR("192.168.0.0/16"),
		},
		Interfaces: []nodeTypes.Interface{
			{
				Gateway: nodeTypes.Address{
					Type: addressing.NodeInternalIP,
					IP:   net.IPv4(10, 11, 224, 1),
				},
				Index:             0,
				MAC:               mustParseMAC(c, "0a:c0:d6:f1:72:a3"),
				EndpointAddresses: []net.IP{},
			},
			{
				Gateway: nodeTypes.Address{
					Type: addressing.NodeInternalIP,
					IP:   net.IPv4(100, 112, 0, 1),
				},
				Index: 1,
				MAC:   mustParseMAC(c, "0a:c5:98:de:c6:5d"),
				EndpointAddresses: []net.IP{
					net.IPv4(100, 112, 10, 244),
					net.IPv4(100, 112, 17, 145),
					net.IPv4(100, 112, 21, 2),
				},
			},
		},
	}

	for _, tc := range []struct {
		egressMultiHomeIPRuleCompat bool
		enableIPv4Masquerade        bool
		expectedRuleStrings         []string
		expectedRouteStrings        []string
	}{
		{
			egressMultiHomeIPRuleCompat: false,
			enableIPv4Masquerade:        false,
			expectedRuleStrings: []string{
				"20: from all to 100.112.10.244/32 lookup main",
				"111: from 100.112.10.244/32 to all lookup 11",
				"20: from all to 100.112.17.145/32 lookup main",
				"111: from 100.112.17.145/32 to all lookup 11",
				"20: from all to 100.112.21.2/32 lookup main",
				"111: from 100.112.21.2/32 to all lookup 11",
			},
			expectedRouteStrings: []string{
				"{Ifindex: 0 Dst: 10.11.224.1/32 Src: <nil> Gw: <nil> Flags: [] Table: 10}",
				"{Ifindex: 0 Dst: 0.0.0.0/0 Src: <nil> Gw: 10.11.224.1 Flags: [] Table: 10}",
				"{Ifindex: 1 Dst: 100.112.0.1/32 Src: <nil> Gw: <nil> Flags: [] Table: 11}",
				"{Ifindex: 0 Dst: 0.0.0.0/0 Src: <nil> Gw: 100.112.0.1 Flags: [] Table: 11}",
			},
		},
		{
			egressMultiHomeIPRuleCompat: false,
			enableIPv4Masquerade:        true,
			expectedRuleStrings: []string{
				"20: from all to 100.112.10.244/32 lookup main",
				"111: from 100.112.10.244/32 to 10.1.0.0/16 lookup 11",
				"111: from 100.112.10.244/32 to 192.168.0.0/16 lookup 11",
				"20: from all to 100.112.17.145/32 lookup main",
				"111: from 100.112.17.145/32 to 10.1.0.0/16 lookup 11",
				"111: from 100.112.17.145/32 to 192.168.0.0/16 lookup 11",
				"20: from all to 100.112.21.2/32 lookup main",
				"111: from 100.112.21.2/32 to 10.1.0.0/16 lookup 11",
				"111: from 100.112.21.2/32 to 192.168.0.0/16 lookup 11",
			},
			expectedRouteStrings: []string{
				"{Ifindex: 0 Dst: 10.11.224.1/32 Src: <nil> Gw: <nil> Flags: [] Table: 10}",
				"{Ifindex: 0 Dst: 0.0.0.0/0 Src: <nil> Gw: 10.11.224.1 Flags: [] Table: 10}",
				"{Ifindex: 1 Dst: 100.112.0.1/32 Src: <nil> Gw: <nil> Flags: [] Table: 11}",
				"{Ifindex: 0 Dst: 0.0.0.0/0 Src: <nil> Gw: 100.112.0.1 Flags: [] Table: 11}",
			},
		},
		{
			egressMultiHomeIPRuleCompat: true,
			enableIPv4Masquerade:        false,
			expectedRuleStrings: []string{
				"20: from all to 100.112.10.244/32 lookup main",
				"110: from 100.112.10.244/32 to all lookup 1",
				"20: from all to 100.112.17.145/32 lookup main",
				"110: from 100.112.17.145/32 to all lookup 1",
				"20: from all to 100.112.21.2/32 lookup main",
				"110: from 100.112.21.2/32 to all lookup 1",
			},
			expectedRouteStrings: []string{
				"{Ifindex: 0 Dst: 10.11.224.1/32 Src: <nil> Gw: <nil> Flags: [] Table: 0}",
				"{Ifindex: 0 Dst: 0.0.0.0/0 Src: <nil> Gw: 10.11.224.1 Flags: [] Table: 0}",
				"{Ifindex: 1 Dst: 100.112.0.1/32 Src: <nil> Gw: <nil> Flags: [] Table: 1}",
				"{Ifindex: 0 Dst: 0.0.0.0/0 Src: <nil> Gw: 100.112.0.1 Flags: [] Table: 1}",
			},
		},
		{
			egressMultiHomeIPRuleCompat: true,
			enableIPv4Masquerade:        true,
			expectedRuleStrings: []string{
				"20: from all to 100.112.10.244/32 lookup main",
				"110: from 100.112.10.244/32 to 10.1.0.0/16 lookup 1",
				"110: from 100.112.10.244/32 to 192.168.0.0/16 lookup 1",
				"20: from all to 100.112.17.145/32 lookup main",
				"110: from 100.112.17.145/32 to 10.1.0.0/16 lookup 1",
				"110: from 100.112.17.145/32 to 192.168.0.0/16 lookup 1",
				"20: from all to 100.112.21.2/32 lookup main",
				"110: from 100.112.21.2/32 to 10.1.0.0/16 lookup 1",
				"110: from 100.112.21.2/32 to 192.168.0.0/16 lookup 1",
			},
			expectedRouteStrings: []string{
				"{Ifindex: 0 Dst: 10.11.224.1/32 Src: <nil> Gw: <nil> Flags: [] Table: 0}",
				"{Ifindex: 0 Dst: 0.0.0.0/0 Src: <nil> Gw: 10.11.224.1 Flags: [] Table: 0}",
				"{Ifindex: 1 Dst: 100.112.0.1/32 Src: <nil> Gw: <nil> Flags: [] Table: 1}",
				"{Ifindex: 0 Dst: 0.0.0.0/0 Src: <nil> Gw: 100.112.0.1 Flags: [] Table: 1}",
			},
		},
	} {
		option.Config.EgressMultiHomeIPRuleCompat = tc.egressMultiHomeIPRuleCompat
		option.Config.EnableIPv4Masquerade = tc.enableIPv4Masquerade
		obtainedRules, obtainedRoutes := nodeRulesAndRoutes(node)
		c.Assert(ruleStrings(obtainedRules), checker.DeepEquals, tc.expectedRuleStrings)
		c.Assert(routeStrings(obtainedRoutes), checker.DeepEquals, tc.expectedRouteStrings)
	}
}

func (s *IPAMSuite) TestNodeCIDRs(c *check.C) {
	prevIPv4NativeRoutingCIDR := option.Config.IPv4NativeRoutingCIDR()
	defer func() {
		option.Config.SetIPv4NativeRoutingCIDR(prevIPv4NativeRoutingCIDR)
	}()
	option.Config.SetIPv4NativeRoutingCIDR(cidr.MustParseCIDR("10.0.0.0/8"))

	node := &nodeTypes.Node{
		IPv4NativeRoutingCIDRs: []*cidr.CIDR{
			cidr.MustParseCIDR("10.1.0.0/16"),
			cidr.MustParseCIDR("192.168.0.0/16"),
		},
	}
	obtained := nodeIPNets(node)
	expected := []*net.IPNet{
		{
			IP:   net.IPv4(10, 0, 0, 0).To4(),
			Mask: net.CIDRMask(8, 32),
		},
		{
			IP:   net.IPv4(10, 1, 0, 0).To4(),
			Mask: net.CIDRMask(16, 32),
		},
		{
			IP:   net.IPv4(192, 168, 0, 0).To4(),
			Mask: net.CIDRMask(16, 32),
		},
	}
	c.Assert(obtained, checker.DeepEquals, expected)
}

func routeStrings(routes []*netlink.Route) []string {
	result := make([]string, 0, len(routes))
	for _, route := range routes {
		result = append(result, route.String())
	}
	return result
}

func ruleStrings(rules []*route.Rule) []string {
	result := make([]string, 0, len(rules))
	for _, rule := range rules {
		result = append(result, rule.String())
	}
	return result
}

func mustParseMAC(c *check.C, s string) mac.MAC {
	mac, err := mac.ParseMAC(s)
	c.Assert(err, check.IsNil)
	return mac
}
