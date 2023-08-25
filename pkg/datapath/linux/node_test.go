// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package linux

import (
	"net"
	"testing"

	check "github.com/cilium/checkmate"
	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"github.com/cilium/cilium/pkg/checker"
	"github.com/cilium/cilium/pkg/cidr"
	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/datapath/fake"
	"github.com/cilium/cilium/pkg/datapath/linux/linux_defaults"
	"github.com/cilium/cilium/pkg/datapath/linux/route"
	datapath "github.com/cilium/cilium/pkg/datapath/types"
	"github.com/cilium/cilium/pkg/mtu"
	"github.com/cilium/cilium/pkg/netns"
	"github.com/cilium/cilium/pkg/testutils"
)

var (
	nh = linuxNodeHandler{
		nodeConfig: datapath.LocalNodeConfiguration{
			MtuConfig: mtu.NewConfiguration(0, false, false, false, false, 100, net.IP("1.1.1.1")),
		},
		nodeAddressing: fake.NewNodeAddressing(),
		datapathConfig: DatapathConfiguration{
			HostDevice: "host_device",
		},
	}
	cr1 = cidr.MustParseCIDR("10.1.0.0/16")
)

func (s *linuxTestSuite) TestTunnelCIDRUpdateRequired(c *check.C) {
	nilPrefixCluster := cmtypes.PrefixCluster{}
	c1 := cmtypes.PrefixClusterFromCIDR(cidr.MustParseCIDR("10.1.0.0/16"))
	c2 := cmtypes.PrefixClusterFromCIDR(cidr.MustParseCIDR("10.2.0.0/16"))
	ip1 := net.ParseIP("1.1.1.1")
	ip2 := net.ParseIP("2.2.2.2")

	c.Assert(cidrNodeMappingUpdateRequired(nilPrefixCluster, nilPrefixCluster, ip1, ip1, 0, 0), check.Equals, false) // disabled -> disabled
	c.Assert(cidrNodeMappingUpdateRequired(nilPrefixCluster, c1, ip1, ip1, 0, 0), check.Equals, true)                // disabled -> c1
	c.Assert(cidrNodeMappingUpdateRequired(c1, c1, ip1, ip1, 0, 0), check.Equals, false)                             // c1 -> c1
	c.Assert(cidrNodeMappingUpdateRequired(c1, c1, ip1, ip2, 0, 0), check.Equals, true)                              // c1 -> c1 (changed host IP)
	c.Assert(cidrNodeMappingUpdateRequired(c1, c2, ip2, ip2, 0, 0), check.Equals, true)                              // c1 -> c2
	c.Assert(cidrNodeMappingUpdateRequired(c2, nilPrefixCluster, ip2, ip2, 0, 0), check.Equals, false)               // c2 -> disabled
	c.Assert(cidrNodeMappingUpdateRequired(c1, c1, ip1, ip1, 0, 1), check.Equals, true)                              // key upgrade 0 -> 1
	c.Assert(cidrNodeMappingUpdateRequired(c1, c1, ip1, ip1, 1, 0), check.Equals, true)                              // key downgrade 1 -> 0

	c1 = cmtypes.PrefixClusterFromCIDR(cidr.MustParseCIDR("f00d::a0a:0:0:0/96"))
	c2 = cmtypes.PrefixClusterFromCIDR(cidr.MustParseCIDR("f00d::b0b:0:0:0/96"))
	ip1 = net.ParseIP("cafe::1")
	ip2 = net.ParseIP("cafe::2")

	c.Assert(cidrNodeMappingUpdateRequired(nilPrefixCluster, nilPrefixCluster, ip1, ip1, 0, 0), check.Equals, false) // disabled -> disabled
	c.Assert(cidrNodeMappingUpdateRequired(nilPrefixCluster, c1, ip1, ip1, 0, 0), check.Equals, true)                // disabled -> c1
	c.Assert(cidrNodeMappingUpdateRequired(c1, c1, ip1, ip1, 0, 0), check.Equals, false)                             // c1 -> c1
	c.Assert(cidrNodeMappingUpdateRequired(c1, c1, ip1, ip2, 0, 0), check.Equals, true)                              // c1 -> c1 (changed host IP)
	c.Assert(cidrNodeMappingUpdateRequired(c1, c2, ip2, ip2, 0, 0), check.Equals, true)                              // c1 -> c2
	c.Assert(cidrNodeMappingUpdateRequired(c2, nilPrefixCluster, ip2, ip2, 0, 0), check.Equals, false)               // c2 -> disabled
	c.Assert(cidrNodeMappingUpdateRequired(c1, c1, ip1, ip1, 0, 1), check.Equals, true)                              // key upgrade 0 -> 1
	c.Assert(cidrNodeMappingUpdateRequired(c1, c1, ip1, ip1, 1, 0), check.Equals, true)                              // key downgrade 1 -> 0
}

func (s *linuxTestSuite) TestCreateNodeRoute(c *check.C) {
	dpConfig := DatapathConfiguration{
		HostDevice: "host_device",
	}

	fakeNodeAddressing := fake.NewNodeAddressing()

	nodeHandler := NewNodeHandler(dpConfig, fakeNodeAddressing, nil)

	c1 := cidr.MustParseCIDR("10.10.0.0/16")
	generatedRoute, err := nodeHandler.createNodeRouteSpec(c1, false)
	c.Assert(err, check.IsNil)
	c.Assert(generatedRoute.Prefix, checker.DeepEquals, *c1.IPNet)
	c.Assert(generatedRoute.Device, check.Equals, dpConfig.HostDevice)
	c.Assert(*generatedRoute.Nexthop, checker.DeepEquals, fakeNodeAddressing.IPv4().Router())
	c.Assert(generatedRoute.Local, checker.DeepEquals, fakeNodeAddressing.IPv4().Router())

	c1 = cidr.MustParseCIDR("beef:beef::/48")
	generatedRoute, err = nodeHandler.createNodeRouteSpec(c1, false)
	c.Assert(err, check.IsNil)
	c.Assert(generatedRoute.Prefix, checker.DeepEquals, *c1.IPNet)
	c.Assert(generatedRoute.Device, check.Equals, dpConfig.HostDevice)
	c.Assert(generatedRoute.Nexthop, check.IsNil)
	c.Assert(generatedRoute.Local, checker.DeepEquals, fakeNodeAddressing.IPv6().Router())
}

func (s *linuxTestSuite) TestCreateNodeRouteSpecMtu(c *check.C) {
	generatedRoute, err := nh.createNodeRouteSpec(cr1, false)

	c.Assert(err, check.IsNil)
	c.Assert(generatedRoute.MTU, check.Not(check.Equals), 0)

	generatedRoute, err = nh.createNodeRouteSpec(cr1, true)

	c.Assert(err, check.IsNil)
	c.Assert(generatedRoute.MTU, check.Equals, 0)
}

func (s *linuxTestSuite) TestStoreLoadNeighLinks(c *check.C) {
	tmpDir := c.MkDir()
	devExpected := []string{"dev1"}
	err := storeNeighLink(tmpDir, devExpected)
	c.Assert(err, check.IsNil)

	devsActual, err := loadNeighLink(tmpDir)
	c.Assert(err, check.IsNil)
	c.Assert(devExpected, checker.DeepEquals, devsActual)
}

func TestLocalRule(t *testing.T) {
	testutils.PrivilegedTest(t)

	nn := "local-rules"
	tns, err := netns.ReplaceNetNSWithName(nn)
	assert.NoError(t, err)
	t.Cleanup(func() {
		tns.Close()
		netns.RemoveNetNSWithName(nn)
	})

	test := func(t *testing.T) {
		require.NoError(t, NodeEnsureLocalRoutingRule())

		// Expect at least one rule in the netns, with the first entry at pref 100
		// pointing at table 255.
		rules, err := route.ListRules(netlink.FAMILY_V4, nil)
		assert.NoError(t, err)
		assert.GreaterOrEqual(t, len(rules), 1)
		assert.Equal(t, rules[0].Priority, linux_defaults.RulePriorityLocalLookup)
		assert.Equal(t, rules[0].Table, unix.RT_TABLE_LOCAL)

		rules, err = route.ListRules(netlink.FAMILY_V6, nil)
		assert.NoError(t, err)
		assert.GreaterOrEqual(t, len(rules), 1)
		assert.Equal(t, rules[0].Priority, linux_defaults.RulePriorityLocalLookup)
		assert.Equal(t, rules[0].Table, unix.RT_TABLE_LOCAL)
	}

	tns.Do(func(_ ns.NetNS) error {
		// Install rules the first time.
		test(t)

		// Ensure idempotency.
		test(t)

		return nil
	})
}
