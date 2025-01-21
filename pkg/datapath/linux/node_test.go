// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package linux

import (
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"github.com/cilium/cilium/pkg/cidr"
	fakeTypes "github.com/cilium/cilium/pkg/datapath/fake/types"
	"github.com/cilium/cilium/pkg/datapath/linux/linux_defaults"
	"github.com/cilium/cilium/pkg/datapath/linux/route"
	datapath "github.com/cilium/cilium/pkg/datapath/types"
	"github.com/cilium/cilium/pkg/mtu"
	"github.com/cilium/cilium/pkg/testutils"
	"github.com/cilium/cilium/pkg/testutils/netns"
)

var (
	fakeNodeAddressing = fakeTypes.NewNodeAddressing()

	nodeConfig = datapath.LocalNodeConfiguration{
		NodeIPv4:            fakeNodeAddressing.IPv4().PrimaryExternal(),
		NodeIPv6:            fakeNodeAddressing.IPv6().PrimaryExternal(),
		CiliumInternalIPv4:  fakeNodeAddressing.IPv4().Router(),
		CiliumInternalIPv6:  fakeNodeAddressing.IPv6().Router(),
		DeviceMTU:           calcMtu.DeviceMTU,
		RouteMTU:            calcMtu.RouteMTU,
		RoutePostEncryptMTU: calcMtu.RoutePostEncryptMTU,
	}
	mtuConfig = mtu.NewConfiguration(0, false, false, false, false)
	calcMtu   = mtuConfig.Calculate(100)
	nh        = linuxNodeHandler{
		nodeConfig: nodeConfig,
		datapathConfig: DatapathConfiguration{
			HostDevice: "host_device",
		},
	}
	cr1 = cidr.MustParseCIDR("10.1.0.0/16")
)

func TestCreateNodeRoute(t *testing.T) {
	dpConfig := DatapathConfiguration{
		HostDevice: "host_device",
	}
	log := hivetest.Logger(t)

	nodeHandler := newNodeHandler(log, dpConfig, nil, new(mockEnqueuer))
	nodeHandler.NodeConfigurationChanged(nodeConfig)

	c1 := cidr.MustParseCIDR("10.10.0.0/16")
	generatedRoute, err := nodeHandler.createNodeRouteSpec(c1, false)
	require.NoError(t, err)
	require.Equal(t, *c1.IPNet, generatedRoute.Prefix)
	require.Equal(t, dpConfig.HostDevice, generatedRoute.Device)
	require.Equal(t, fakeNodeAddressing.IPv4().Router(), *generatedRoute.Nexthop)
	require.Equal(t, fakeNodeAddressing.IPv4().Router(), generatedRoute.Local)

	c1 = cidr.MustParseCIDR("beef:beef::/48")
	generatedRoute, err = nodeHandler.createNodeRouteSpec(c1, false)
	require.NoError(t, err)
	require.Equal(t, *c1.IPNet, generatedRoute.Prefix)
	require.Equal(t, dpConfig.HostDevice, generatedRoute.Device)
	require.Nil(t, generatedRoute.Nexthop)
	require.Equal(t, fakeNodeAddressing.IPv6().Router(), generatedRoute.Local)
}

func TestCreateNodeRouteSpecMtu(t *testing.T) {
	generatedRoute, err := nh.createNodeRouteSpec(cr1, false)

	require.NoError(t, err)
	require.NotEqual(t, 0, generatedRoute.MTU)

	generatedRoute, err = nh.createNodeRouteSpec(cr1, true)

	require.NoError(t, err)
	require.Equal(t, 0, generatedRoute.MTU)
}

func TestStoreLoadNeighLinks(t *testing.T) {
	tmpDir := t.TempDir()
	devExpected := []string{"dev1"}
	err := storeNeighLink(tmpDir, devExpected)
	require.NoError(t, err)

	devsActual, err := loadNeighLink(tmpDir)
	require.NoError(t, err)
	require.Equal(t, devExpected, devsActual)
}

func TestLocalRule(t *testing.T) {
	testutils.PrivilegedTest(t)

	ns := netns.NewNetNS(t)

	test := func(t *testing.T) {
		require.NoError(t, NodeEnsureLocalRoutingRule())

		// Expect at least one rule in the netns, with the first entry at pref 100
		// pointing at table 255.
		rules, err := route.ListRules(netlink.FAMILY_V4, nil)
		assert.NoError(t, err)
		assert.GreaterOrEqual(t, len(rules), 1)
		assert.Equal(t, linux_defaults.RulePriorityLocalLookup, rules[0].Priority)
		assert.Equal(t, unix.RT_TABLE_LOCAL, rules[0].Table)

		rules, err = route.ListRules(netlink.FAMILY_V6, nil)
		assert.NoError(t, err)
		assert.GreaterOrEqual(t, len(rules), 1)
		assert.Equal(t, linux_defaults.RulePriorityLocalLookup, rules[0].Priority)
		assert.Equal(t, unix.RT_TABLE_LOCAL, rules[0].Table)
	}

	ns.Do(func() error {
		// Install rules the first time.
		test(t)

		// Ensure idempotency.
		test(t)

		return nil
	})
}
