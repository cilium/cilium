// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build linux

package linux

import (
	"context"
	"fmt"
	"net"
	"sort"
	"testing"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/testutils"
	"github.com/cilium/cilium/pkg/testutils/netns"
)

type DevicesSuite struct {
	prevConfigDirectRoutingDevice     string
	prevConfigIPv6MCastDevice         string
	prevConfigEnableIPv4              bool
	prevConfigEnableIPv6              bool
	prevConfigEnableHostLegacyRouting bool
	prevConfigEnableNodePort          bool
	prevConfigNodePortAcceleration    string
	prevConfigRoutingMode             string
	prevConfigEnableIPv6NDP           bool
}

func setUpDevicesSuite(tb testing.TB) *DevicesSuite {
	testutils.PrivilegedTest(tb)

	var err error

	s := &DevicesSuite{}
	s.prevConfigDirectRoutingDevice = option.Config.DirectRoutingDevice
	s.prevConfigEnableIPv4 = option.Config.EnableIPv4
	s.prevConfigEnableIPv6 = option.Config.EnableIPv6
	s.prevConfigEnableNodePort = option.Config.EnableNodePort
	s.prevConfigNodePortAcceleration = option.Config.NodePortAcceleration
	s.prevConfigRoutingMode = option.Config.RoutingMode
	s.prevConfigEnableIPv6NDP = option.Config.EnableIPv6NDP
	s.prevConfigIPv6MCastDevice = option.Config.IPv6MCastDevice
	require.Nil(tb, err)

	tb.Cleanup(func() {
		option.Config.DirectRoutingDevice = s.prevConfigDirectRoutingDevice
		option.Config.EnableIPv4 = s.prevConfigEnableIPv4
		option.Config.EnableIPv6 = s.prevConfigEnableIPv6
		option.Config.EnableNodePort = s.prevConfigEnableNodePort
		option.Config.EnableHostLegacyRouting = s.prevConfigEnableHostLegacyRouting
		option.Config.NodePortAcceleration = s.prevConfigNodePortAcceleration
		option.Config.RoutingMode = s.prevConfigRoutingMode
		option.Config.EnableIPv6NDP = s.prevConfigEnableIPv6NDP
		option.Config.IPv6MCastDevice = s.prevConfigIPv6MCastDevice
	})

	return s
}

func nodeSetIP(ip net.IP) {
	node.UpdateLocalNodeInTest(func(n *node.LocalNode) {
		n.SetNodeInternalIP(ip)
	})
}

func TestDetect(t *testing.T) {
	s := setUpDevicesSuite(t)
	s.withFixture(t, func() {
		option.Config.DirectRoutingDevice = ""
		option.Config.EnableNodePort = true
		option.Config.NodePortAcceleration = option.NodePortAccelerationDisabled
		option.Config.EnableHostLegacyRouting = true
		option.Config.EnableNodePort = false

		// 1. No devices, nothing to detect.
		dm, err := newDeviceManagerForTests(t)
		require.Nil(t, err)

		devices, err := dm.Detect(false)
		require.Nil(t, err)
		require.EqualValues(t, []string{}, devices)
		dm.Stop(t)

		// 2. Nodeport, detection is performed:
		option.Config.EnableNodePort = true
		require.Nil(t, createDummy("dummy0", "192.168.0.1/24", false))
		nodeSetIP(net.ParseIP("192.168.0.1"))

		dm, err = newDeviceManagerForTests(t)
		require.Nil(t, err)
		devices, err = dm.Detect(true)
		require.Nil(t, err)
		require.EqualValues(t, []string{"dummy0"}, devices)
		require.Equal(t, "dummy0", option.Config.DirectRoutingDevice)
		option.Config.DirectRoutingDevice = ""
		dm.Stop(t)

		// Manually specified devices, no detection is performed
		option.Config.EnableNodePort = true
		nodeSetIP(net.ParseIP("192.168.0.1"))
		require.Nil(t, createDummy("dummy1", "192.168.1.1/24", false))

		dm, err = newDeviceManagerForTests(t, "dummy0")
		require.Nil(t, err)
		devices, err = dm.Detect(true)
		require.Nil(t, err)
		require.EqualValues(t, []string{"dummy0"}, devices)
		require.Equal(t, "dummy0", option.Config.DirectRoutingDevice)
		option.Config.DirectRoutingDevice = ""

		// Direct routing mode, should find all devices and set direct
		// routing device to the one with k8s node ip.
		require.Nil(t, createDummy("dummy2", "192.168.2.1/24", false))
		require.Nil(t, createDummy("dummy3", "192.168.3.1/24", false))
		require.Nil(t, delRoutes("dummy3")) // Delete routes so it won't be detected
		nodeSetIP(net.ParseIP("192.168.1.1"))
		option.Config.EnableIPv4 = true
		option.Config.EnableIPv6 = false
		option.Config.RoutingMode = option.RoutingModeNative
		dm, err = newDeviceManagerForTests(t)
		require.Nil(t, err)
		devices, err = dm.Detect(true)
		require.Nil(t, err)
		require.EqualValues(t, []string{"dummy0", "dummy1", "dummy2"}, devices)
		require.Equal(t, "dummy1", option.Config.DirectRoutingDevice)
		option.Config.DirectRoutingDevice = ""
		dm.Stop(t)

		// Tunnel routing mode with XDP, should find all devices and set direct
		// routing device to the one with k8s node ip.
		nodeSetIP(net.ParseIP("192.168.1.1"))
		option.Config.EnableIPv4 = true
		option.Config.EnableIPv6 = false
		option.Config.RoutingMode = option.RoutingModeTunnel
		option.Config.EnableNodePort = true
		option.Config.NodePortAcceleration = option.NodePortAccelerationNative

		dm, err = newDeviceManagerForTests(t)
		require.Nil(t, err)
		devices, err = dm.Detect(true)
		require.Nil(t, err)
		require.EqualValues(t, []string{"dummy0", "dummy1", "dummy2"}, devices)
		require.Equal(t, "dummy1", option.Config.DirectRoutingDevice)

		option.Config.DirectRoutingDevice = ""
		option.Config.NodePortAcceleration = option.NodePortAccelerationDisabled
		option.Config.RoutingMode = option.RoutingModeNative
		dm.Stop(t)

		// Use IPv6 node IP and enable IPv6NDP and check that multicast device is detected.
		option.Config.EnableIPv6 = true
		option.Config.EnableIPv6NDP = true
		require.Nil(t, createDummy("dummy_v6", "2001:db8::face/64", true))
		nodeSetIP(nil)
		nodeSetIP(net.ParseIP("2001:db8::face"))
		dm, err = newDeviceManagerForTests(t)
		require.Nil(t, err)
		devices, err = dm.Detect(true)
		require.Nil(t, err)
		require.EqualValues(t, []string{"dummy0", "dummy1", "dummy2", "dummy_v6"}, devices)
		require.Equal(t, "dummy_v6", option.Config.DirectRoutingDevice)
		require.EqualValues(t, "dummy_v6", option.Config.IPv6MCastDevice)
		option.Config.DirectRoutingDevice = ""
		dm.Stop(t)

		// Only consider veth devices if they have a default route.
		require.Nil(t, createVeth("veth0", "192.168.4.1/24", false))
		dm, err = newDeviceManagerForTests(t)
		require.Nil(t, err)
		devices, err = dm.Detect(true)
		require.Nil(t, err)
		require.EqualValues(t, []string{"dummy0", "dummy1", "dummy2", "dummy_v6"}, devices)
		dm.Stop(t)

		require.Nil(t, addRoute(addRouteParams{iface: "veth0", gw: "192.168.4.254", table: unix.RT_TABLE_MAIN}))
		dm, err = newDeviceManagerForTests(t)
		require.Nil(t, err)
		devices, err = dm.Detect(true)
		require.Nil(t, err)
		require.EqualValues(t, []string{"dummy0", "dummy1", "dummy2", "dummy_v6", "veth0"}, devices)
		dm.Stop(t)

		// Detect devices that only have routes in non-main tables
		require.Nil(t, addRoute(addRouteParams{iface: "dummy3", dst: "192.168.3.1/24", scope: unix.RT_SCOPE_LINK, table: 11}))
		dm, err = newDeviceManagerForTests(t)
		require.Nil(t, err)
		devices, err = dm.Detect(true)
		require.Nil(t, err)
		require.EqualValues(t, []string{"dummy0", "dummy1", "dummy2", "dummy3", "dummy_v6", "veth0"}, devices)
		dm.Stop(t)

		// Skip bridge devices, and devices added to the bridge
		require.Nil(t, createBridge("br0", "192.168.5.1/24", false))
		dm, err = newDeviceManagerForTests(t)
		require.Nil(t, err)
		devices, err = dm.Detect(true)
		require.Nil(t, err)
		require.EqualValues(t, []string{"dummy0", "dummy1", "dummy2", "dummy3", "dummy_v6", "veth0"}, devices)
		dm.Stop(t)

		require.Nil(t, setMaster("dummy3", "br0"))
		dm, err = newDeviceManagerForTests(t)
		require.Nil(t, err)
		devices, err = dm.Detect(true)
		require.Nil(t, err)
		require.EqualValues(t, []string{"dummy0", "dummy1", "dummy2", "dummy_v6", "veth0"}, devices)
		dm.Stop(t)

		// Don't skip bond devices, but do skip bond slaves.
		require.Nil(t, createBond("bond0", "192.168.6.1/24", false))
		require.Nil(t, setBondMaster("dummy2", "bond0"))
		dm, err = newDeviceManagerForTests(t)
		require.Nil(t, err)
		devices, err = dm.Detect(true)
		require.Nil(t, err)
		sort.Strings(devices)
		require.EqualValues(t, []string{"bond0", "dummy0", "dummy1", "dummy_v6", "veth0"}, devices)
		dm.Stop(t)
	})
}

func TestExpandDirectRoutingDevice(t *testing.T) {
	s := setUpDevicesSuite(t)
	s.withFixture(t, func() {
		option.Config.EnableNodePort = true
		option.Config.RoutingMode = option.RoutingModeNative

		require.Nil(t, createDummy("dummy0", "192.168.0.1/24", false))
		require.Nil(t, createDummy("dummy1", "192.168.1.2/24", false))
		require.Nil(t, createDummy("unmatched", "192.168.4.5/24", false))
		nodeSetIP(net.ParseIP("192.168.0.1"))

		// 1. Check expansion works and non-matching prefixes are ignored
		option.Config.DirectRoutingDevice = "dummy+"
		dm, err := newDeviceManagerForTests(t)
		require.Nil(t, err)
		_, err = dm.Detect(true)
		require.Nil(t, err)
		require.Equal(t, "dummy0", option.Config.DirectRoutingDevice)
		dm.Stop(t)

		// 2. Check that expansion fails if directRoutingDevice is specified but yields empty expansion
		option.Config.DirectRoutingDevice = "none+"
		dm, err = newDeviceManagerForTests(t)
		require.Nil(t, err)
		_, err = dm.Detect(true)
		require.Error(t, err)
		require.Equal(t, "", option.Config.DirectRoutingDevice)
		dm.Stop(t)
	})
}

func (s *DevicesSuite) withFixture(t *testing.T, test func()) {
	logging.SetLogLevelToDebug()

	ns := netns.NewNetNS(t)

	ns.Do(func() error {
		node.WithTestLocalNodeStore(test)
		return nil
	})
}

func createLink(linkTemplate netlink.Link, iface, ipAddr string, flagMulticast bool) error {
	var flags net.Flags
	if flagMulticast {
		flags = net.FlagMulticast
	}
	*linkTemplate.Attrs() = netlink.LinkAttrs{
		Name:  iface,
		Flags: flags,
	}

	if err := netlink.LinkAdd(linkTemplate); err != nil {
		return err
	}

	if ipAddr != "" {
		if err := addAddr(iface, ipAddr); err != nil {
			return err
		}
	}

	link, err := netlink.LinkByName(iface)
	if err != nil {
		return err
	}

	if err := netlink.LinkSetUp(link); err != nil {
		return err
	}

	return nil
}

func deleteLink(name string) error {
	link, err := netlink.LinkByName(name)
	if err != nil {
		return err
	}
	return netlink.LinkDel(link)
}

func createDummy(iface, ipAddr string, flagMulticast bool) error {
	return createLink(&netlink.Dummy{}, iface, ipAddr, flagMulticast)
}

func createVeth(iface, ipAddr string, flagMulticast bool) error {
	return createLink(&netlink.Veth{PeerName: iface + "_"}, iface, ipAddr, flagMulticast)
}

func createBridge(iface, ipAddr string, flagMulticast bool) error {
	return createLink(&netlink.Bridge{}, iface, ipAddr, flagMulticast)
}

func createBond(iface, ipAddr string, flagMulticast bool) error {
	bond := netlink.NewLinkBond(netlink.LinkAttrs{})
	bond.Mode = netlink.BOND_MODE_BALANCE_RR
	return createLink(bond, iface, ipAddr, flagMulticast)
}

func setLinkUp(iface string) error {
	link, err := netlink.LinkByName(iface)
	if err != nil {
		return err
	}
	return netlink.LinkSetUp(link)
}

func setMaster(iface string, master string) error {
	masterLink, err := netlink.LinkByName(master)
	if err != nil {
		return err
	}
	link, err := netlink.LinkByName(iface)
	if err != nil {
		return err
	}
	return netlink.LinkSetMaster(link, masterLink)
}

func setBondMaster(iface string, master string) error {
	masterLink, err := netlink.LinkByName(master)
	if err != nil {
		return err
	}
	link, err := netlink.LinkByName(iface)
	if err != nil {
		return err
	}
	netlink.LinkSetDown(link)
	defer netlink.LinkSetUp(link)
	return netlink.LinkSetBondSlave(link, masterLink.(*netlink.Bond))
}
func addAddr(iface string, cidr string) error {
	return addAddrScoped(iface, cidr, netlink.SCOPE_SITE, 0)
}

func addAddrScoped(iface string, cidr string, scope netlink.Scope, flags int) error {
	ip, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return fmt.Errorf("ParseCIDR: %w", err)
	}
	ipnet.IP = ip
	link, err := netlink.LinkByName(iface)
	if err != nil {
		return fmt.Errorf("LinkByName: %w", err)
	}

	if err := netlink.AddrAdd(link, &netlink.Addr{IPNet: ipnet, Scope: int(scope), Flags: flags}); err != nil {
		return fmt.Errorf("AddrAdd: %w", err)
	}
	return nil
}

type addRouteParams struct {
	iface string
	gw    string
	src   string
	dst   string
	table int
	scope netlink.Scope
}

func addRoute(p addRouteParams) error {
	link, err := netlink.LinkByName(p.iface)
	if err != nil {
		return err
	}

	var dst *net.IPNet
	if p.dst != "" {
		_, dst, err = net.ParseCIDR(p.dst)
		if err != nil {
			return err
		}
	}

	var src net.IP
	if p.src != "" {
		src = net.ParseIP(p.src)
	}

	if p.table == 0 {
		p.table = unix.RT_TABLE_MAIN
	}

	route := &netlink.Route{
		LinkIndex: link.Attrs().Index,
		Dst:       dst,
		Src:       src,
		Gw:        net.ParseIP(p.gw),
		Table:     p.table,
		Scope:     p.scope,
	}
	if err := netlink.RouteAdd(route); err != nil {
		return err
	}

	return nil
}

func delRoute(p addRouteParams) error {
	link, err := netlink.LinkByName(p.iface)
	if err != nil {
		return err
	}

	var dst *net.IPNet
	if p.dst != "" {
		_, dst, err = net.ParseCIDR(p.dst)
		if err != nil {
			return err
		}
	}

	var src net.IP
	if p.src != "" {
		src = net.ParseIP(p.src)
	}

	if p.table == 0 {
		p.table = unix.RT_TABLE_MAIN
	}

	route := &netlink.Route{
		LinkIndex: link.Attrs().Index,
		Dst:       dst,
		Src:       src,
		Gw:        net.ParseIP(p.gw),
		Table:     p.table,
		Scope:     p.scope,
	}
	if err := netlink.RouteDel(route); err != nil {
		return err
	}

	return nil
}

func delRoutes(iface string) error {
	link, err := netlink.LinkByName(iface)
	if err != nil {
		return err
	}

	filter := netlink.Route{
		Table:     unix.RT_TABLE_UNSPEC,
		LinkIndex: link.Attrs().Index,
	}
	mask := netlink.RT_FILTER_TABLE | netlink.RT_FILTER_OIF

	routes, err := netlink.RouteListFiltered(netlink.FAMILY_ALL, &filter, mask)
	if err != nil {
		return err
	}

	for _, r := range routes {
		if err := netlink.RouteDel(&r); err != nil {
			return err
		}
	}

	return nil
}

func newDeviceManagerForTests(t testing.TB, devs ...string) (dm *DeviceManager, err error) {
	h := hive.New(
		DevicesControllerCell,
		cell.Provide(func() (*netlinkFuncs, error) { return makeNetlinkFuncs() }),
		cell.Invoke(func(dm_ *DeviceManager) {
			dm = dm_
		}))
	hive.AddConfigOverride(h, func(c *DevicesConfig) {
		c.Devices = devs
	})
	err = h.Start(hivetest.Logger(t), context.TODO())
	dm.hive = h
	return
}

func (dm *DeviceManager) Stop(t testing.TB) {
	if dm.hive != nil {
		dm.hive.Stop(hivetest.Logger(t), context.TODO())
	}
}
