// Copyright 2018-2019 Authors of Cilium
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

	"github.com/cilium/cilium/pkg/checker"
	"github.com/cilium/cilium/pkg/cidr"
	"github.com/cilium/cilium/pkg/datapath"
	"github.com/cilium/cilium/pkg/datapath/fake"
	"github.com/cilium/cilium/pkg/mtu"

	"gopkg.in/check.v1"
)

var (
	nh = linuxNodeHandler{
		nodeConfig: datapath.LocalNodeConfiguration{
			MtuConfig: mtu.NewConfiguration(0, false, false, 100, net.IP("1.1.1.1")),
		},
		nodeAddressing: fake.NewNodeAddressing(),
		datapathConfig: DatapathConfiguration{
			HostDevice: "host_device",
		},
	}
	cr1 = cidr.MustParseCIDR("10.1.0.0/16")
)

func (s *linuxTestSuite) TestTunnelCIDRUpdateRequired(c *check.C) {
	c1 := cidr.MustParseCIDR("10.1.0.0/16")
	c2 := cidr.MustParseCIDR("10.2.0.0/16")
	ip1 := net.ParseIP("1.1.1.1")
	ip2 := net.ParseIP("2.2.2.2")

	c.Assert(cidrNodeMappingUpdateRequired(nil, nil, ip1, ip1, 0, 0), check.Equals, false) // disabled -> disabled
	c.Assert(cidrNodeMappingUpdateRequired(nil, c1, ip1, ip1, 0, 0), check.Equals, true)   // disabled -> c1
	c.Assert(cidrNodeMappingUpdateRequired(c1, c1, ip1, ip1, 0, 0), check.Equals, false)   // c1 -> c1
	c.Assert(cidrNodeMappingUpdateRequired(c1, c1, ip1, ip2, 0, 0), check.Equals, true)    // c1 -> c1 (changed host IP)
	c.Assert(cidrNodeMappingUpdateRequired(c1, c2, ip2, ip2, 0, 0), check.Equals, true)    // c1 -> c2
	c.Assert(cidrNodeMappingUpdateRequired(c2, nil, ip2, ip2, 0, 0), check.Equals, false)  // c2 -> disabled
	c.Assert(cidrNodeMappingUpdateRequired(c1, c1, ip1, ip1, 0, 1), check.Equals, true)    // key upgrade 0 -> 1
	c.Assert(cidrNodeMappingUpdateRequired(c1, c1, ip1, ip1, 1, 0), check.Equals, true)    // key downgrade 1 -> 0

	c1 = cidr.MustParseCIDR("f00d::a0a:0:0:0/96")
	c2 = cidr.MustParseCIDR("f00d::b0b:0:0:0/96")
	ip1 = net.ParseIP("cafe::1")
	ip2 = net.ParseIP("cafe::2")

	c.Assert(cidrNodeMappingUpdateRequired(nil, nil, ip1, ip1, 0, 0), check.Equals, false) // disabled -> disabled
	c.Assert(cidrNodeMappingUpdateRequired(nil, c1, ip1, ip1, 0, 0), check.Equals, true)   // disabled -> c1
	c.Assert(cidrNodeMappingUpdateRequired(c1, c1, ip1, ip1, 0, 0), check.Equals, false)   // c1 -> c1
	c.Assert(cidrNodeMappingUpdateRequired(c1, c1, ip1, ip2, 0, 0), check.Equals, true)    // c1 -> c1 (changed host IP)
	c.Assert(cidrNodeMappingUpdateRequired(c1, c2, ip2, ip2, 0, 0), check.Equals, true)    // c1 -> c2
	c.Assert(cidrNodeMappingUpdateRequired(c2, nil, ip2, ip2, 0, 0), check.Equals, false)  // c2 -> disabled
	c.Assert(cidrNodeMappingUpdateRequired(c1, c1, ip1, ip1, 0, 1), check.Equals, true)    // key upgrade 0 -> 1
	c.Assert(cidrNodeMappingUpdateRequired(c1, c1, ip1, ip1, 1, 0), check.Equals, true)    // key downgrade 1 -> 0
}

func (s *linuxTestSuite) TestCreateNodeRoute(c *check.C) {
	dpConfig := DatapathConfiguration{
		HostDevice: "host_device",
	}

	fakeNodeAddressing := fake.NewNodeAddressing()

	nodeHandler := NewNodeHandler(dpConfig, fakeNodeAddressing, nil)

	c1 := cidr.MustParseCIDR("10.10.0.0/16")
	generatedRoute, err := nodeHandler.(*linuxNodeHandler).createNodeRouteSpec(c1, false)
	c.Assert(err, check.IsNil)
	c.Assert(generatedRoute.Prefix, checker.DeepEquals, *c1.IPNet)
	c.Assert(generatedRoute.Device, check.Equals, dpConfig.HostDevice)
	c.Assert(*generatedRoute.Nexthop, checker.DeepEquals, fakeNodeAddressing.IPv4().Router())
	c.Assert(generatedRoute.Local, checker.DeepEquals, fakeNodeAddressing.IPv4().Router())

	c1 = cidr.MustParseCIDR("beef:beef::/48")
	generatedRoute, err = nodeHandler.(*linuxNodeHandler).createNodeRouteSpec(c1, false)
	c.Assert(err, check.IsNil)
	c.Assert(generatedRoute.Prefix, checker.DeepEquals, *c1.IPNet)
	c.Assert(generatedRoute.Device, check.Equals, dpConfig.HostDevice)
	c.Assert(*generatedRoute.Nexthop, checker.DeepEquals, fakeNodeAddressing.IPv6().Router())
	c.Assert(generatedRoute.Local, checker.DeepEquals, fakeNodeAddressing.IPv6().PrimaryExternal())
}

func (s *linuxTestSuite) TestCreateNodeRouteSpecMtu(c *check.C) {
	generatedRoute, err := nh.createNodeRouteSpec(cr1, false)

	c.Assert(err, check.IsNil)
	c.Assert(generatedRoute.MTU, check.Not(check.Equals), 0)

	generatedRoute, err = nh.createNodeRouteSpec(cr1, true)

	c.Assert(err, check.IsNil)
	c.Assert(generatedRoute.MTU, check.Equals, 0)
}
