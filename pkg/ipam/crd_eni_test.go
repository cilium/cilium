// Copyright 2021 Authors of Cilium
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
	eniTypes "github.com/cilium/cilium/pkg/aws/eni/types"
	"github.com/cilium/cilium/pkg/checker"
	"github.com/cilium/cilium/pkg/datapath/linux/route"
	ipamTypes "github.com/cilium/cilium/pkg/ipam/types"
	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/vishvananda/netlink"

	"gopkg.in/check.v1"
)

func (s *IPAMSuite) TestCiliumNodeENIRulesAndRoutes(c *check.C) {
	node := &ciliumv2.CiliumNode{
		Spec: ciliumv2.NodeSpec{
			ENI: eniTypes.ENISpec{
				AvailabilityZone:    "us-east-1a",
				FirstInterfaceIndex: newInt(1),
				InstanceType:        "m5d.4xlarge",
				VpcID:               "vpc-09ce2017dbb2d409e",
			},
			IPAM: ipamTypes.IPAMSpec{
				PodCIDRs: []string{
					"10.12.0.0/16",
				},
			},
		},
		Status: ciliumv2.NodeStatus{
			ENI: eniTypes.ENIStatus{
				ENIs: map[string]eniTypes.ENI{
					"eni-0c1acca10397a0187": {
						Addresses: []string{
							"10.11.224.12",
						},
						ID:  "eni-0c1acca10397a0187",
						IP:  "10.11.224.12",
						MAC: "0a:c0:d6:f1:72:a3",
						SecurityGroups: []string{
							"sg-0a57526659c9a4f27",
							"sg-09deda1f9bba50be4",
							"sg-0c8be8f91a918b8e",
						},
						Subnet: eniTypes.AwsSubnet{
							CIDR: "10.11.224.0/23",
							ID:   "subnet-0db942f58edd0f3d6",
						},
						VPC: eniTypes.AwsVPC{
							ID:          "vpc-09ce2017dbb2d409e",
							PrimaryCIDR: "10.11.232.0/21",
							CIDRs: []string{
								"10.11.232.0/21", // VPC CIDR
								"10.11.224.0/21", // Node expansion CIDR
								"100.112.0.0/17", // Pod extension CIDR
							},
						},
					},
					"eni-0d4df16da096110ca": {
						Addresses: []string{
							"100.112.17.145",
							"100.112.21.2",
							"100.112.10.244",
							"100.112.18.53", // Allocated but unused
						},
						Description: "Cilium-CNI (i-04eb084dde5735440)",
						ID:          "eni-0d4df16da096110ca",
						IP:          "100.112.17.145",
						MAC:         "0a:c5:98:de:c6:5d",
						Number:      1,
						SecurityGroups: []string{
							"sg-0a57526659c9a4f27",
							"sg-09deda1f9bba50be4",
							"sg-0c8be8f91a918b8ef",
						},
						Subnet: eniTypes.AwsSubnet{
							CIDR: "100.112.0.0/19",
							ID:   "subnet-04889f3c14b255e1f",
						},
						VPC: eniTypes.AwsVPC{
							PrimaryCIDR: "10.11.232.0/21",
							ID:          "vpc-09ce2017dbb2d409e",
							CIDRs: []string{
								"10.11.232.0/21", // VPC CIDR
								"10.11.224.0/21", // Node expansion CIDR
								"100.112.0.0/17", // Pod extension CIDR
							},
						},
					},
				},
			},
			IPAM: ipamTypes.IPAMStatus{
				Used: ipamTypes.AllocationMap{
					"100.112.17.145": {
						Owner:    "router",
						Resource: "eni-0d4df16da096110ca",
					},
					"100.112.21.2": {
						Owner:    "health",
						Resource: "eni-0d4df16da096110ca",
					},
					"100.112.10.244": {
						Owner:    "kube-system/jaeger-agent-m4x55 [restored]",
						Resource: "eni-0d4df16da096110ca",
					},
				},
			},
		},
	}

	macToNetlinkInterfaceIndex := map[string]int{
		"0a:c0:d6:f1:72:a3": 2, // ENI number 0
		"0a:c5:98:de:c6:5d": 3, // ENI number 1
	}

	for _, tc := range []struct {
		options              ciliumNodeENIRulesAndRoutesOptions
		expectedRuleStrings  []string
		expectedRouteStrings []string
	}{
		{
			options: ciliumNodeENIRulesAndRoutesOptions{
				EgressMultiHomeIPRuleCompat: false,
				EnableIPv4Masquerade:        false,
			},
			expectedRuleStrings: []string{
				"20: from all to 100.112.10.244/32 lookup main",
				"111: from 100.112.10.244/32 to all lookup 11",
				"20: from all to 100.112.17.145/32 lookup main",
				"111: from 100.112.17.145/32 to all lookup 11",
				"20: from all to 100.112.21.2/32 lookup main",
				"111: from 100.112.21.2/32 to all lookup 11",
			},
			expectedRouteStrings: []string{
				"{Ifindex: 3 Dst: 100.112.0.1/32 Src: <nil> Gw: <nil> Flags: [] Table: 11}",
				"{Ifindex: 0 Dst: 0.0.0.0/0 Src: <nil> Gw: 100.112.0.1 Flags: [] Table: 11}",
			},
		},
		{
			options: ciliumNodeENIRulesAndRoutesOptions{
				EgressMultiHomeIPRuleCompat: false,
				EnableIPv4Masquerade:        true,
			},
			expectedRuleStrings: []string{
				"20: from all to 100.112.10.244/32 lookup main",
				"111: from 100.112.10.244/32 to 10.11.232.0/21 lookup 11",
				"111: from 100.112.10.244/32 to 10.11.224.0/21 lookup 11",
				"111: from 100.112.10.244/32 to 100.112.0.0/17 lookup 11",
				"20: from all to 100.112.17.145/32 lookup main",
				"111: from 100.112.17.145/32 to 10.11.232.0/21 lookup 11",
				"111: from 100.112.17.145/32 to 10.11.224.0/21 lookup 11",
				"111: from 100.112.17.145/32 to 100.112.0.0/17 lookup 11",
				"20: from all to 100.112.21.2/32 lookup main",
				"111: from 100.112.21.2/32 to 10.11.232.0/21 lookup 11",
				"111: from 100.112.21.2/32 to 10.11.224.0/21 lookup 11",
				"111: from 100.112.21.2/32 to 100.112.0.0/17 lookup 11",
			},
			expectedRouteStrings: []string{
				"{Ifindex: 3 Dst: 100.112.0.1/32 Src: <nil> Gw: <nil> Flags: [] Table: 11}",
				"{Ifindex: 0 Dst: 0.0.0.0/0 Src: <nil> Gw: 100.112.0.1 Flags: [] Table: 11}",
			},
		},
		{
			options: ciliumNodeENIRulesAndRoutesOptions{
				EgressMultiHomeIPRuleCompat: true,
				EnableIPv4Masquerade:        false,
			},
			expectedRuleStrings: []string{
				"20: from all to 100.112.10.244/32 lookup main",
				"110: from 100.112.10.244/32 to all lookup 3",
				"20: from all to 100.112.17.145/32 lookup main",
				"110: from 100.112.17.145/32 to all lookup 3",
				"20: from all to 100.112.21.2/32 lookup main",
				"110: from 100.112.21.2/32 to all lookup 3",
			},
			expectedRouteStrings: []string{
				"{Ifindex: 3 Dst: 100.112.0.1/32 Src: <nil> Gw: <nil> Flags: [] Table: 3}",
				"{Ifindex: 0 Dst: 0.0.0.0/0 Src: <nil> Gw: 100.112.0.1 Flags: [] Table: 3}",
			},
		},
		{
			options: ciliumNodeENIRulesAndRoutesOptions{
				EgressMultiHomeIPRuleCompat: true,
				EnableIPv4Masquerade:        true,
			},
			expectedRuleStrings: []string{
				"20: from all to 100.112.10.244/32 lookup main",
				"110: from 100.112.10.244/32 to 10.11.232.0/21 lookup 3",
				"110: from 100.112.10.244/32 to 10.11.224.0/21 lookup 3",
				"110: from 100.112.10.244/32 to 100.112.0.0/17 lookup 3",
				"20: from all to 100.112.17.145/32 lookup main",
				"110: from 100.112.17.145/32 to 10.11.232.0/21 lookup 3",
				"110: from 100.112.17.145/32 to 10.11.224.0/21 lookup 3",
				"110: from 100.112.17.145/32 to 100.112.0.0/17 lookup 3",
				"20: from all to 100.112.21.2/32 lookup main",
				"110: from 100.112.21.2/32 to 10.11.232.0/21 lookup 3",
				"110: from 100.112.21.2/32 to 10.11.224.0/21 lookup 3",
				"110: from 100.112.21.2/32 to 100.112.0.0/17 lookup 3",
			},
			expectedRouteStrings: []string{
				"{Ifindex: 3 Dst: 100.112.0.1/32 Src: <nil> Gw: <nil> Flags: [] Table: 3}",
				"{Ifindex: 0 Dst: 0.0.0.0/0 Src: <nil> Gw: 100.112.0.1 Flags: [] Table: 3}",
			},
		},
	} {
		obtainedRules, obtainedRoutes := ciliumNodeENIRulesAndRoutes(node, macToNetlinkInterfaceIndex, tc.options)
		c.Assert(ruleStrings(obtainedRules), checker.DeepEquals, tc.expectedRuleStrings)
		c.Assert(routeStrings(obtainedRoutes), checker.DeepEquals, tc.expectedRouteStrings)
	}
}

func newInt(i int) *int { return &i }

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
