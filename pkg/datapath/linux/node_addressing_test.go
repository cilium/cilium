// Copyright 2018-2020 Authors of Cilium
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

package linux

import (
	"net"

	"gopkg.in/check.v1"
)

func (s *linuxTestSuite) TestMapSubnetAddresses(c *check.C) {
	tests := []struct {
		name        string
		subnets     []net.IPNet
		expectedIPs []net.IP
	}{
		{
			name: "one ipv4 ip",
			subnets: []net.IPNet{
				{
					IP:   net.IPv4(127, 0, 0, 1),
					Mask: net.IPv4Mask(255, 255, 255, 255),
				},
			},
			expectedIPs: []net.IP{
				net.IPv4(127, 0, 0, 1),
			},
		},
		{
			name: "one ipv4 subnet",
			subnets: []net.IPNet{
				{
					IP:   net.IPv4(127, 0, 0, 1),
					Mask: net.IPv4Mask(255, 255, 255, 254),
				},
			},
			expectedIPs: []net.IP{
				net.IPv4(127, 0, 0, 0),
				net.IPv4(127, 0, 0, 1),
			},
		},
		{
			name: "two ipv4 subnets",
			subnets: []net.IPNet{
				{
					IP:   net.IPv4(127, 0, 0, 2),
					Mask: net.IPv4Mask(255, 255, 255, 254),
				},
				{
					IP:   net.IPv4(127, 0, 0, 4),
					Mask: net.IPv4Mask(255, 255, 255, 254),
				},
			},
			expectedIPs: []net.IP{
				net.IPv4(127, 0, 0, 2),
				net.IPv4(127, 0, 0, 3),
				net.IPv4(127, 0, 0, 4),
				net.IPv4(127, 0, 0, 5),
			},
		},
		{
			name: "one ipv6",
			subnets: []net.IPNet{
				{
					IP:   net.IPv6zero,
					Mask: net.IPMask{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
				},
			},
			expectedIPs: []net.IP{
				net.IPv6zero,
			},
		},
		{
			name: "one ipv6 subnet",
			subnets: []net.IPNet{
				{
					IP:   net.IPv6loopback,
					Mask: net.IPMask{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe},
				},
			},
			expectedIPs: []net.IP{
				net.IPv6zero,
				net.IPv6loopback,
			},
		},
		{
			name: "two ipv6 subnets",
			subnets: []net.IPNet{
				{
					IP:   net.IPv6loopback,
					Mask: net.IPMask{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe},
				},
				{
					IP:   net.IPv6linklocalallnodes,
					Mask: net.IPMask{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe},
				},
			},
			expectedIPs: []net.IP{
				net.IPv6zero,
				net.IPv6loopback,
				{0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
				net.IPv6linklocalallnodes,
			},
		},
	}

	for _, tt := range tests {
		c.Logf("running %q", tt.name)
		var got []net.IP
		err := mapSubnetAddresses(tt.subnets, func(ip net.IP) error {
			got = append(got, ip)
			return nil
		})
		c.Assert(err, check.IsNil)
		le := len(tt.expectedIPs)
		c.Assert(le, check.Equals, len(got))
		for i := 0; i < le; i++ {
			c.Assert(tt.expectedIPs[i].Equal(got[i]), check.Equals, true)
		}
	}
}
