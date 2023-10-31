// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build linux

package linux

import (
	"context"
	"fmt"
	"net"
	"runtime"
	"slices"
	"sort"
	"time"

	. "github.com/cilium/checkmate"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"

	"github.com/cilium/cilium/pkg/checker"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/statedb"
	"github.com/cilium/cilium/pkg/testutils"
)

type DevicesSuite struct {
	currentNetNS                      netns.NsHandle
	prevConfigDevices                 []string
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

var _ = Suite(&DevicesSuite{})

func (s *DevicesSuite) SetUpSuite(c *C) {
	testutils.PrivilegedTest(c)

	var err error

	s.prevConfigDevices = option.Config.GetDevices()
	s.prevConfigDirectRoutingDevice = option.Config.DirectRoutingDevice
	s.prevConfigEnableIPv4 = option.Config.EnableIPv4
	s.prevConfigEnableIPv6 = option.Config.EnableIPv6
	s.prevConfigEnableNodePort = option.Config.EnableNodePort
	s.prevConfigNodePortAcceleration = option.Config.NodePortAcceleration
	s.prevConfigRoutingMode = option.Config.RoutingMode
	s.prevConfigEnableIPv6NDP = option.Config.EnableIPv6NDP
	s.prevConfigIPv6MCastDevice = option.Config.IPv6MCastDevice
	s.currentNetNS, err = netns.Get()
	c.Assert(err, IsNil)
}

func nodeSetIP(ip net.IP) {
	node.UpdateLocalNodeInTest(func(n *node.LocalNode) {
		n.SetNodeInternalIP(ip)
	})
}

func (s *DevicesSuite) TearDownTest(c *C) {
	option.Config.SetDevices(s.prevConfigDevices)
	option.Config.DirectRoutingDevice = s.prevConfigDirectRoutingDevice
	option.Config.EnableIPv4 = s.prevConfigEnableIPv4
	option.Config.EnableIPv6 = s.prevConfigEnableIPv6
	option.Config.EnableNodePort = s.prevConfigEnableNodePort
	option.Config.EnableHostLegacyRouting = s.prevConfigEnableHostLegacyRouting
	option.Config.NodePortAcceleration = s.prevConfigNodePortAcceleration
	option.Config.RoutingMode = s.prevConfigRoutingMode
	option.Config.EnableIPv6NDP = s.prevConfigEnableIPv6NDP
	option.Config.IPv6MCastDevice = s.prevConfigIPv6MCastDevice
}

func (s *DevicesSuite) TestDetect(c *C) {
	s.withFixture(c, func() {
		option.Config.SetDevices([]string{})
		option.Config.DirectRoutingDevice = ""
		option.Config.EnableNodePort = true
		option.Config.NodePortAcceleration = option.NodePortAccelerationDisabled
		option.Config.EnableHostLegacyRouting = true
		option.Config.EnableNodePort = false

		// 1. No devices, nothing to detect.
		dm, err := newDeviceManagerForTests()
		c.Assert(err, IsNil)

		devices, err := dm.Detect(false)
		c.Assert(err, IsNil)
		c.Assert(devices, checker.DeepEquals, []string(nil))
		dm.Stop()

		// 2. Nodeport, detection is performed:
		option.Config.EnableNodePort = true
		c.Assert(createDummy("dummy0", "192.168.0.1/24", false), IsNil)
		nodeSetIP(net.ParseIP("192.168.0.1"))

		dm, err = newDeviceManagerForTests()
		c.Assert(err, IsNil)
		devices, err = dm.Detect(true)
		c.Assert(err, IsNil)
		c.Assert(devices, checker.DeepEquals, []string{"dummy0"})
		c.Assert(option.Config.GetDevices(), checker.DeepEquals, devices)
		c.Assert(option.Config.DirectRoutingDevice, Equals, "dummy0")
		option.Config.DirectRoutingDevice = ""
		dm.Stop()

		// Manually specified devices, no detection is performed
		option.Config.EnableNodePort = true
		nodeSetIP(net.ParseIP("192.168.0.1"))
		c.Assert(createDummy("dummy1", "192.168.1.1/24", false), IsNil)
		option.Config.SetDevices([]string{"dummy0"})

		dm, err = newDeviceManagerForTests()
		c.Assert(err, IsNil)
		devices, err = dm.Detect(true)
		c.Assert(err, IsNil)
		c.Assert(devices, checker.DeepEquals, []string{"dummy0"})
		c.Assert(option.Config.GetDevices(), checker.DeepEquals, devices)
		c.Assert(option.Config.DirectRoutingDevice, Equals, "dummy0")
		option.Config.SetDevices([]string{})
		option.Config.DirectRoutingDevice = ""

		// Direct routing mode, should find all devices and set direct
		// routing device to the one with k8s node ip.
		c.Assert(createDummy("dummy2", "192.168.2.1/24", false), IsNil)
		c.Assert(createDummy("dummy3", "192.168.3.1/24", false), IsNil)
		c.Assert(delRoutes("dummy3"), IsNil) // Delete routes so it won't be detected
		nodeSetIP(net.ParseIP("192.168.1.1"))
		option.Config.EnableIPv4 = true
		option.Config.EnableIPv6 = false
		option.Config.RoutingMode = option.RoutingModeNative
		dm, err = newDeviceManagerForTests()
		c.Assert(err, IsNil)
		devices, err = dm.Detect(true)
		c.Assert(err, IsNil)
		c.Assert(devices, checker.DeepEquals, []string{"dummy0", "dummy1", "dummy2"})
		c.Assert(option.Config.GetDevices(), checker.DeepEquals, devices)
		c.Assert(option.Config.DirectRoutingDevice, Equals, "dummy1")
		option.Config.DirectRoutingDevice = ""
		option.Config.SetDevices([]string{})
		dm.Stop()

		// Tunnel routing mode with XDP, should find all devices and set direct
		// routing device to the one with k8s node ip.
		nodeSetIP(net.ParseIP("192.168.1.1"))
		option.Config.EnableIPv4 = true
		option.Config.EnableIPv6 = false
		option.Config.RoutingMode = option.RoutingModeTunnel
		option.Config.EnableNodePort = true
		option.Config.NodePortAcceleration = option.NodePortAccelerationNative

		dm, err = newDeviceManagerForTests()
		c.Assert(err, IsNil)
		devices, err = dm.Detect(true)
		c.Assert(err, IsNil)
		c.Assert(devices, checker.DeepEquals, []string{"dummy0", "dummy1", "dummy2"})
		c.Assert(option.Config.GetDevices(), checker.DeepEquals, devices)
		c.Assert(option.Config.DirectRoutingDevice, Equals, "dummy1")

		option.Config.DirectRoutingDevice = ""
		option.Config.SetDevices([]string{})
		option.Config.NodePortAcceleration = option.NodePortAccelerationDisabled
		option.Config.RoutingMode = option.RoutingModeNative
		dm.Stop()

		// Use IPv6 node IP and enable IPv6NDP and check that multicast device is detected.
		option.Config.EnableIPv6 = true
		option.Config.EnableIPv6NDP = true
		c.Assert(createDummy("dummy_v6", "2001:db8::face/64", true), IsNil)
		nodeSetIP(nil)
		nodeSetIP(net.ParseIP("2001:db8::face"))
		dm, err = newDeviceManagerForTests()
		c.Assert(err, IsNil)
		devices, err = dm.Detect(true)
		c.Assert(err, IsNil)
		c.Assert(devices, checker.DeepEquals, []string{"dummy0", "dummy1", "dummy2", "dummy_v6"})
		c.Assert(option.Config.GetDevices(), checker.DeepEquals, devices)
		c.Assert(option.Config.DirectRoutingDevice, checker.Equals, "dummy_v6")
		c.Assert(option.Config.IPv6MCastDevice, checker.DeepEquals, "dummy_v6")
		option.Config.DirectRoutingDevice = ""
		option.Config.SetDevices([]string{})
		dm.Stop()

		// Only consider veth devices if they have a default route.
		c.Assert(createVeth("veth0", "192.168.4.1/24", false), IsNil)
		dm, err = newDeviceManagerForTests()
		c.Assert(err, IsNil)
		devices, err = dm.Detect(true)
		c.Assert(err, IsNil)
		c.Assert(devices, checker.DeepEquals, []string{"dummy0", "dummy1", "dummy2", "dummy_v6"})
		c.Assert(option.Config.GetDevices(), checker.DeepEquals, devices)
		option.Config.SetDevices([]string{})
		dm.Stop()

		c.Assert(addRoute(addRouteParams{iface: "veth0", gw: "192.168.4.254", table: unix.RT_TABLE_MAIN}), IsNil)
		dm, err = newDeviceManagerForTests()
		c.Assert(err, IsNil)
		devices, err = dm.Detect(true)
		c.Assert(err, IsNil)
		c.Assert(devices, checker.DeepEquals, []string{"dummy0", "dummy1", "dummy2", "dummy_v6", "veth0"})
		c.Assert(option.Config.GetDevices(), checker.DeepEquals, devices)
		option.Config.SetDevices([]string{})
		dm.Stop()

		// Detect devices that only have routes in non-main tables
		c.Assert(addRoute(addRouteParams{iface: "dummy3", dst: "192.168.3.1/24", scope: unix.RT_SCOPE_LINK, table: 11}), IsNil)
		dm, err = newDeviceManagerForTests()
		c.Assert(err, IsNil)
		devices, err = dm.Detect(true)
		c.Assert(err, IsNil)
		c.Assert(devices, checker.DeepEquals, []string{"dummy0", "dummy1", "dummy2", "dummy3", "dummy_v6", "veth0"})
		c.Assert(option.Config.GetDevices(), checker.DeepEquals, devices)
		option.Config.SetDevices([]string{})
		dm.Stop()

		// Skip bridge devices, and devices added to the bridge
		c.Assert(createBridge("br0", "192.168.5.1/24", false), IsNil)
		dm, err = newDeviceManagerForTests()
		c.Assert(err, IsNil)
		devices, err = dm.Detect(true)
		c.Assert(err, IsNil)
		c.Assert(devices, checker.DeepEquals, []string{"dummy0", "dummy1", "dummy2", "dummy3", "dummy_v6", "veth0"})
		c.Assert(option.Config.GetDevices(), checker.DeepEquals, devices)
		option.Config.SetDevices([]string{})
		dm.Stop()

		c.Assert(setMaster("dummy3", "br0"), IsNil)
		dm, err = newDeviceManagerForTests()
		c.Assert(err, IsNil)
		devices, err = dm.Detect(true)
		c.Assert(err, IsNil)
		c.Assert(devices, checker.DeepEquals, []string{"dummy0", "dummy1", "dummy2", "dummy_v6", "veth0"})
		c.Assert(option.Config.GetDevices(), checker.DeepEquals, devices)
		option.Config.SetDevices([]string{})
		dm.Stop()

		// Don't skip bond devices, but do skip bond slaves.
		c.Assert(createBond("bond0", "192.168.6.1/24", false), IsNil)
		c.Assert(setBondMaster("dummy2", "bond0"), IsNil)
		dm, err = newDeviceManagerForTests()
		c.Assert(err, IsNil)
		devices, err = dm.Detect(true)
		c.Assert(err, IsNil)
		sort.Strings(devices)
		c.Assert(devices, checker.DeepEquals, []string{"bond0", "dummy0", "dummy1", "dummy_v6", "veth0"})
		option.Config.SetDevices([]string{})
		dm.Stop()
	})
}

func (s *DevicesSuite) TestExpandDevices(c *C) {
	s.withFixture(c, func() {
		c.Assert(createDummy("dummy0", "192.168.0.1/24", false), IsNil)
		c.Assert(createDummy("dummy1", "192.168.1.2/24", false), IsNil)
		c.Assert(createDummy("other0", "192.168.2.3/24", false), IsNil)
		c.Assert(createDummy("other1", "192.168.3.4/24", false), IsNil)
		c.Assert(createDummy("unmatched", "192.168.4.5/24", false), IsNil)

		// 1. Check expansion works and non-matching prefixes are ignored
		option.Config.SetDevices([]string{"dummy+", "missing+", "other0+" /* duplicates: */, "dum+", "other0", "other1"})
		option.Config.DirectRoutingDevice = "dummy0"
		dm, err := newDeviceManagerForTests()
		c.Assert(err, IsNil)
		devs, err := dm.Detect(true)
		c.Assert(err, IsNil)
		c.Assert(devs, checker.DeepEquals, []string{"dummy0", "dummy1", "other0", "other1"})
		dm.Stop()

		// 2. Check that expansion fails if devices are specified but yields empty expansion
		option.Config.SetDevices([]string{"none+"})
		dm, err = newDeviceManagerForTests()
		c.Assert(err, IsNil)
		_, err = dm.Detect(true)
		c.Assert(err, NotNil)
		dm.Stop()
	})
}

func (s *DevicesSuite) TestExpandDirectRoutingDevice(c *C) {
	s.withFixture(c, func() {
		option.Config.EnableNodePort = true
		option.Config.RoutingMode = option.RoutingModeNative

		c.Assert(createDummy("dummy0", "192.168.0.1/24", false), IsNil)
		c.Assert(createDummy("dummy1", "192.168.1.2/24", false), IsNil)
		c.Assert(createDummy("unmatched", "192.168.4.5/24", false), IsNil)
		nodeSetIP(net.ParseIP("192.168.0.1"))

		// 1. Check expansion works and non-matching prefixes are ignored
		option.Config.DirectRoutingDevice = "dummy+"
		dm, err := newDeviceManagerForTests()
		c.Assert(err, IsNil)
		_, err = dm.Detect(true)
		c.Assert(err, IsNil)
		c.Assert(option.Config.DirectRoutingDevice, Equals, "dummy0")
		dm.Stop()

		// 2. Check that expansion fails if directRoutingDevice is specified but yields empty expansion
		option.Config.DirectRoutingDevice = "none+"
		dm, err = newDeviceManagerForTests()
		c.Assert(err, IsNil)
		_, err = dm.Detect(true)
		c.Assert(err, NotNil)
		c.Assert(option.Config.DirectRoutingDevice, Equals, "")
		dm.Stop()
	})
}

func (s *DevicesSuite) TestListenForNewDevices(c *C) {
	s.withFixture(c, func() {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		timeout := time.After(10 * time.Second)

		option.Config.SetDevices([]string{})
		option.Config.EnableNodePort = true
		c.Assert(createDummy("dummy0", "192.168.1.2/24", false), IsNil)

		dm, err := newDeviceManagerForTests()
		c.Assert(err, IsNil)
		defer dm.Stop()

		initialDevices, err := dm.Detect(false)
		c.Assert(err, IsNil)
		c.Assert(initialDevices, checker.DeepEquals, []string{"dummy0"})

		devicesChan, err := dm.Listen(ctx)
		c.Assert(err, IsNil)

		// Create the IPv4 & IPv6 devices that should be detected.
		c.Assert(createDummy("dummy1", "2001:db8::face/64", true), IsNil)

		// Create another device without an IP address or routes. This should be ignored.
		c.Assert(createDummy("dummy2", "", false), IsNil)

		// Create a veth device with default route that should be detected. veth devices are used in test
		// setups.
		c.Assert(createVeth("veth0", "192.168.2.2/24", false), IsNil)
		c.Assert(addRoute(addRouteParams{iface: "veth0", gw: "192.168.2.254", table: unix.RT_TABLE_MAIN}), IsNil)

		// Create few devices with excluded prefixes
		c.Assert(createDummy("lxc123", "", false), IsNil)
		c.Assert(createDummy("cilium_foo", "", false), IsNil)

		// Wait for the devices to be updated. Depending on how quickly the devices are created
		// this may span multiple callbacks.
		passed := false
		for !passed {
			var devices []string
			select {
			case <-timeout:
				c.Fatalf("Test timed out, last devices seen: %v", devices)
			case devices = <-devicesChan:
				if slices.Equal(devices, initialDevices) {
					c.Fatalf("Expected Listen() to not emit the initial devices")
				}
				passed, _ = checker.DeepEqual(devices, []string{"dummy0", "dummy1", "veth0"})
			}
		}

		// Test that deletion of devices is detected.
		link, err := netlink.LinkByName("dummy0")
		c.Assert(err, IsNil)
		err = netlink.LinkDel(link)
		c.Assert(err, IsNil)

		for !passed {
			var devices []string
			select {
			case <-timeout:
				c.Fatalf("Test timed out, last devices seen: %v", devices)
			case devices = <-devicesChan:
				passed, _ = checker.DeepEqual(devices, []string{"dummy1", "veth0"})
			}
		}
	})
}

func (s *DevicesSuite) TestListenForNewDevicesFiltered(c *C) {
	s.withFixture(c, func() {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		timeout := time.After(5 * time.Second)

		option.Config.SetDevices([]string{"dummy+"})
		dm, err := newDeviceManagerForTests()
		c.Assert(err, IsNil)
		defer dm.Stop()

		devicesChan, err := dm.Listen(ctx)
		c.Assert(err, IsNil)

		// Create the IPv4 & IPv6 devices that should be detected.
		c.Assert(createDummy("dummy0", "192.168.1.2/24", false), IsNil)
		c.Assert(createDummy("dummy1", "2001:db8::face/64", true), IsNil)

		// Create a device with non-matching name.
		c.Assert(createDummy("other0", "192.168.2.2/24", false), IsNil)

		// Wait for the devices to be updated. Depending on how quickly the devices are created
		// this may span multiple callbacks.
		passed := false
		for !passed {
			select {
			case <-timeout:
				c.Fatal("Test timed out")
			case devices := <-devicesChan:
				passed, _ = checker.DeepEqual(devices, []string{"dummy0", "dummy1"})
			}
		}
	})
}

func (s *DevicesSuite) TestListenAfterDelete(c *C) {
	s.withFixture(c, func() {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		timeout := time.After(time.Second * 5)

		option.Config.SetDevices([]string{"dummy+"})
		option.Config.DirectRoutingDevice = "dummy0"
		c.Assert(createDummy("dummy0", "192.168.1.2/24", false), IsNil)
		c.Assert(createDummy("dummy1", "2001:db8::face/64", true), IsNil)

		// Detect the devices
		dm, err := newDeviceManagerForTests()
		c.Assert(err, IsNil)
		defer dm.Stop()
		devices, err := dm.Detect(true)
		c.Assert(err, IsNil)
		c.Assert(devices, checker.DeepEquals, []string{"dummy0", "dummy1"})

		// Delete one of the devices before listening
		link, err := netlink.LinkByName("dummy1")
		c.Assert(err, IsNil)
		err = netlink.LinkDel(link)
		c.Assert(err, IsNil)

		// Now start listening to device changes. We expect the dummy1 to
		// be deleted.
		devicesChan, err := dm.Listen(ctx)
		c.Assert(err, IsNil)

		passed := false
		for !passed {
			var devices []string
			select {
			case <-timeout:
				c.Fatalf("Test timed out, last seen devices: %v", devices)
			case devices := <-devicesChan:
				passed, _ = checker.DeepEqual(devices, []string{"dummy0"})
			}
		}
	})
}

func (s *DevicesSuite) withFixture(c *C, test func()) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	logging.SetLogLevelToDebug()

	testNetNS, err := netns.New() // creates netns, and sets it to current
	c.Assert(err, IsNil)
	defer func() { c.Assert(testNetNS.Close(), IsNil) }()
	defer func() { c.Assert(netns.Set(s.currentNetNS), IsNil) }()

	node.WithTestLocalNodeStore(test)
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

func newDeviceManagerForTests() (dm *DeviceManager, err error) {
	ns, _ := netns.Get()
	h := hive.New(
		statedb.Cell,
		DevicesControllerCell,
		cell.Provide(func() DevicesConfig {
			return DevicesConfig{Devices: option.Config.GetDevices()}
		}),
		cell.Provide(func() (*netlinkFuncs, error) { return makeNetlinkFuncs(ns) }),
		cell.Invoke(func(dm_ *DeviceManager) {
			dm = dm_
		}))
	err = h.Start(context.TODO())
	dm.hive = h
	return
}
