// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build linux

package linux

import (
	"context"
	"net"
	"runtime"
	"time"

	. "github.com/cilium/checkmate"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"

	"github.com/cilium/cilium/pkg/checker"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/testutils"
)

type DevicesSuite struct {
	currentNetNS                   netns.NsHandle
	prevConfigDevices              []string
	prevConfigDirectRoutingDevice  string
	prevConfigIPv6MCastDevice      string
	prevConfigEnableIPv4           bool
	prevConfigEnableIPv6           bool
	prevConfigEnableNodePort       bool
	prevConfigNodePortAcceleration string
	prevConfigRoutingMode          string
	prevConfigEnableIPv6NDP        bool
	prevK8sNodeIP                  net.IP
	prevK8sNodeIPv6                net.IP
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
	s.prevK8sNodeIP = node.GetIPv4()
	s.prevK8sNodeIPv6 = node.GetIPv6()
	s.currentNetNS, err = netns.Get()
	c.Assert(err, IsNil)
}

func (s *DevicesSuite) TearDownTest(c *C) {
	option.Config.SetDevices(s.prevConfigDevices)
	option.Config.DirectRoutingDevice = s.prevConfigDirectRoutingDevice
	option.Config.EnableIPv4 = s.prevConfigEnableIPv4
	option.Config.EnableIPv6 = s.prevConfigEnableIPv6
	option.Config.EnableNodePort = s.prevConfigEnableNodePort
	option.Config.NodePortAcceleration = s.prevConfigNodePortAcceleration
	option.Config.RoutingMode = s.prevConfigRoutingMode
	option.Config.EnableIPv6NDP = s.prevConfigEnableIPv6NDP
	option.Config.IPv6MCastDevice = s.prevConfigIPv6MCastDevice
	node.SetIPv4(s.prevK8sNodeIP)
	node.SetIPv6(s.prevK8sNodeIPv6)
}

func (s *DevicesSuite) TestDetect(c *C) {
	s.withFreshNetNS(c, func() {
		dm, err := NewDeviceManager()
		c.Assert(err, IsNil)

		option.Config.SetDevices([]string{})
		option.Config.DirectRoutingDevice = ""
		option.Config.NodePortAcceleration = option.NodePortAccelerationDisabled

		// No devices, nothing to detect.
		devices, err := dm.Detect(false)
		c.Assert(err, IsNil)
		c.Assert(devices, checker.DeepEquals, []string{})

		// Node IP not set, can still detect. Direct routing device shouldn't be detected.
		option.Config.EnableNodePort = true
		c.Assert(createDummy("dummy0", "192.168.0.1/24", false), IsNil)
		node.SetIPv4(nil)

		devices, err = dm.Detect(true)
		c.Assert(err, IsNil)
		c.Assert(devices, checker.DeepEquals, []string{"dummy0"})
		c.Assert(option.Config.GetDevices(), checker.DeepEquals, devices)
		c.Assert(option.Config.DirectRoutingDevice, Equals, "")

		// Manually specified devices, no detection is performed
		option.Config.EnableNodePort = true
		node.SetIPv4(net.ParseIP("192.168.0.1"))
		c.Assert(createDummy("dummy1", "192.168.1.1/24", false), IsNil)
		option.Config.SetDevices([]string{"dummy0"})

		devices, err = dm.Detect(true)
		c.Assert(err, IsNil)
		c.Assert(devices, checker.DeepEquals, []string{"dummy0"})
		c.Assert(option.Config.GetDevices(), checker.DeepEquals, devices)
		c.Assert(option.Config.DirectRoutingDevice, Equals, "")
		option.Config.SetDevices([]string{})

		// Direct routing mode, should find all devices and set direct
		// routing device to the one with k8s node ip.
		c.Assert(createDummy("dummy2", "192.168.2.1/24", false), IsNil)
		c.Assert(createDummy("dummy3", "192.168.3.1/24", false), IsNil)
		c.Assert(delRoutes("dummy3"), IsNil) // Delete routes so it won't be detected
		node.SetIPv4(net.ParseIP("192.168.1.1"))
		option.Config.EnableIPv4 = true
		option.Config.EnableIPv6 = false
		option.Config.RoutingMode = option.RoutingModeNative
		devices, err = dm.Detect(true)
		c.Assert(err, IsNil)
		c.Assert(devices, checker.DeepEquals, []string{"dummy0", "dummy1", "dummy2"})
		c.Assert(option.Config.GetDevices(), checker.DeepEquals, devices)
		c.Assert(option.Config.DirectRoutingDevice, Equals, "dummy1")
		option.Config.DirectRoutingDevice = ""
		option.Config.SetDevices([]string{})

		// Tunnel routing mode with XDP, should find all devices and set direct
		// routing device to the one with k8s node ip.
		node.SetIPv4(net.ParseIP("192.168.1.1"))
		option.Config.EnableIPv4 = true
		option.Config.EnableIPv6 = false
		option.Config.RoutingMode = option.RoutingModeTunnel
		option.Config.EnableNodePort = true
		option.Config.NodePortAcceleration = option.NodePortAccelerationNative

		devices, err = dm.Detect(true)
		c.Assert(err, IsNil)
		c.Assert(devices, checker.DeepEquals, []string{"dummy0", "dummy1", "dummy2"})
		c.Assert(option.Config.GetDevices(), checker.DeepEquals, devices)
		c.Assert(option.Config.DirectRoutingDevice, Equals, "dummy1")

		option.Config.DirectRoutingDevice = ""
		option.Config.SetDevices([]string{})
		option.Config.NodePortAcceleration = option.NodePortAccelerationDisabled
		option.Config.RoutingMode = option.RoutingModeNative

		// Use IPv6 node IP and enable IPv6NDP and check that multicast device is detected.
		// Use an excluded device name to verify that device with NodeIP is still picked.
		option.Config.EnableIPv6 = true
		option.Config.EnableIPv6NDP = true
		c.Assert(createDummy("cilium_foo", "2001:db8::face/64", true), IsNil)
		node.SetIPv4(nil)
		node.SetIPv6(net.ParseIP("2001:db8::face"))
		devices, err = dm.Detect(true)
		c.Assert(err, IsNil)
		c.Assert(devices, checker.DeepEquals, []string{"cilium_foo", "dummy0", "dummy1", "dummy2"})
		c.Assert(option.Config.GetDevices(), checker.DeepEquals, devices)
		c.Assert(option.Config.DirectRoutingDevice, checker.Equals, "cilium_foo")
		c.Assert(option.Config.IPv6MCastDevice, checker.DeepEquals, "cilium_foo")
		option.Config.DirectRoutingDevice = ""
		option.Config.SetDevices([]string{})

		// Only consider veth devices if they have a default route.
		c.Assert(createVeth("veth0", "192.168.4.1/24", false), IsNil)
		devices, err = dm.Detect(true)
		c.Assert(err, IsNil)
		c.Assert(devices, checker.DeepEquals, []string{"cilium_foo", "dummy0", "dummy1", "dummy2"})
		c.Assert(option.Config.GetDevices(), checker.DeepEquals, devices)
		option.Config.SetDevices([]string{})

		c.Assert(addRoute(addRouteParams{iface: "veth0", gw: "192.168.4.254", table: unix.RT_TABLE_MAIN}), IsNil)
		devices, err = dm.Detect(true)
		c.Assert(err, IsNil)
		c.Assert(devices, checker.DeepEquals, []string{"cilium_foo", "dummy0", "dummy1", "dummy2", "veth0"})
		c.Assert(option.Config.GetDevices(), checker.DeepEquals, devices)
		option.Config.SetDevices([]string{})

		// Detect devices that only have routes in non-main tables
		c.Assert(addRoute(addRouteParams{iface: "dummy3", dst: "192.168.3.1/24", scope: unix.RT_SCOPE_LINK, table: 11}), IsNil)
		devices, err = dm.Detect(true)
		c.Assert(err, IsNil)
		c.Assert(devices, checker.DeepEquals, []string{"cilium_foo", "dummy0", "dummy1", "dummy2", "dummy3", "veth0"})
		c.Assert(option.Config.GetDevices(), checker.DeepEquals, devices)
		option.Config.SetDevices([]string{})

		// Skip bridge devices, and devices added to the bridge
		c.Assert(createBridge("br0", "192.168.5.1/24", false), IsNil)
		devices, err = dm.Detect(true)
		c.Assert(err, IsNil)
		c.Assert(devices, checker.DeepEquals, []string{"cilium_foo", "dummy0", "dummy1", "dummy2", "dummy3", "veth0"})
		c.Assert(option.Config.GetDevices(), checker.DeepEquals, devices)
		option.Config.SetDevices([]string{})

		c.Assert(setMaster("dummy3", "br0"), IsNil)
		devices, err = dm.Detect(true)
		c.Assert(err, IsNil)
		c.Assert(devices, checker.DeepEquals, []string{"cilium_foo", "dummy0", "dummy1", "dummy2", "veth0"})
		c.Assert(option.Config.GetDevices(), checker.DeepEquals, devices)
		option.Config.SetDevices([]string{})

		// Don't skip bond devices, but do skip bond slaves.
		c.Assert(createBond("bond0", "192.168.6.1/24", false), IsNil)
		c.Assert(setBondMaster("dummy2", "bond0"), IsNil)
		devices, err = dm.Detect(true)
		c.Assert(err, IsNil)
		c.Assert(devices, checker.DeepEquals, []string{"bond0", "cilium_foo", "dummy0", "dummy1", "veth0"})
		option.Config.SetDevices([]string{})
	})
}

func (s *DevicesSuite) TestExpandDevices(c *C) {
	s.withFreshNetNS(c, func() {
		c.Assert(createDummy("dummy0", "192.168.0.1/24", false), IsNil)
		c.Assert(createDummy("dummy1", "192.168.1.2/24", false), IsNil)
		c.Assert(createDummy("other0", "192.168.2.3/24", false), IsNil)
		c.Assert(createDummy("other1", "192.168.3.4/24", false), IsNil)
		c.Assert(createDummy("unmatched", "192.168.4.5/24", false), IsNil)

		dm, err := NewDeviceManager()
		c.Assert(err, IsNil)

		// 1. Check expansion works and non-matching prefixes are ignored
		option.Config.SetDevices([]string{"dummy+", "missing+", "other0+" /* duplicates: */, "dum+", "other0", "other1"})
		c.Assert(dm.expandDevices(), IsNil)
		c.Assert(option.Config.GetDevices(), checker.DeepEquals, []string{"dummy0", "dummy1", "other0", "other1"})

		// 2. Check that expansion fails if devices are specified but yields empty expansion
		option.Config.SetDevices([]string{"none+"})
		c.Assert(dm.expandDevices(), NotNil)
	})
}

func (s *DevicesSuite) TestExpandDirectRoutingDevice(c *C) {
	s.withFreshNetNS(c, func() {
		c.Assert(createDummy("dummy0", "192.168.0.1/24", false), IsNil)
		c.Assert(createDummy("dummy1", "192.168.1.2/24", false), IsNil)
		c.Assert(createDummy("unmatched", "192.168.4.5/24", false), IsNil)

		dm, err := NewDeviceManager()
		c.Assert(err, IsNil)

		// 1. Check expansion works and non-matching prefixes are ignored
		option.Config.DirectRoutingDevice = "dummy+"
		c.Assert(dm.expandDirectRoutingDevice(), IsNil)
		c.Assert(option.Config.DirectRoutingDevice, Equals, "dummy0")

		// 2. Check that expansion fails if directRoutingDevice is specified but yields empty expansion
		option.Config.DirectRoutingDevice = "none+"
		c.Assert(dm.expandDirectRoutingDevice(), NotNil)
	})
}

func (s *DevicesSuite) TestListenForNewDevices(c *C) {
	s.withFreshNetNS(c, func() {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		timeout := time.After(time.Second)

		option.Config.SetDevices([]string{})
		dm, err := NewDeviceManager()
		c.Assert(err, IsNil)

		devicesChan, err := dm.Listen(ctx)
		c.Assert(err, IsNil)

		// Create the IPv4 & IPv6 devices that should be detected.
		c.Assert(createDummy("dummy0", "192.168.1.2/24", false), IsNil)
		c.Assert(createDummy("dummy1", "2001:db8::face/64", true), IsNil)

		// Create another device without an IP address or routes. This should be ignored.
		c.Assert(createDummy("dummy2", "", false), IsNil)

		// Create a veth device which should be detected. veth devices are used in test
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
			select {
			case <-timeout:
				c.Fatal("Test timed out")
			case devices := <-devicesChan:
				passed, _ = checker.DeepEqual(devices, []string{"dummy0", "dummy1", "veth0"})
			}
		}

		// Test that deletion of devices is detected.
		link, err := netlink.LinkByName("dummy0")
		c.Assert(err, IsNil)
		err = netlink.LinkDel(link)
		c.Assert(err, IsNil)

		for !passed {
			select {
			case <-timeout:
				c.Fatal("Test timed out")
			case devices := <-devicesChan:
				passed, _ = checker.DeepEqual(devices, []string{"dummy1"})
			}
		}
	})
}

func (s *DevicesSuite) TestListenForNewDevicesFiltered(c *C) {
	s.withFreshNetNS(c, func() {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		timeout := time.After(time.Second)

		option.Config.SetDevices([]string{"dummy+"})
		dm, err := NewDeviceManager()
		c.Assert(err, IsNil)

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
	s.withFreshNetNS(c, func() {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		timeout := time.After(time.Second)

		option.Config.SetDevices([]string{"dummy+"})
		dm, err := NewDeviceManager()
		c.Assert(err, IsNil)

		c.Assert(createDummy("dummy0", "192.168.1.2/24", false), IsNil)
		c.Assert(createDummy("dummy1", "2001:db8::face/64", true), IsNil)

		// Detect the devices
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
			select {
			case <-timeout:
				c.Fatal("Test timed out")
			case devices := <-devicesChan:
				passed, _ = checker.DeepEqual(devices, []string{"dummy0"})
			}
		}
	})
}

func (s *DevicesSuite) withFreshNetNS(c *C, test func()) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	testNetNS, err := netns.New() // creates netns, and sets it to current
	c.Assert(err, IsNil)
	defer func() { c.Assert(testNetNS.Close(), IsNil) }()
	defer func() { c.Assert(netns.Set(s.currentNetNS), IsNil) }()

	test()
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
	return netlink.LinkSetBondSlave(link, masterLink.(*netlink.Bond))
}

func addAddr(iface string, cidr string) error {
	ip, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return err
	}
	ipnet.IP = ip

	link, err := netlink.LinkByName(iface)
	if err != nil {
		return err
	}

	if err := netlink.AddrAdd(link, &netlink.Addr{IPNet: ipnet}); err != nil {
		return err
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
		if r.Table == unix.RT_TABLE_LOCAL {
			continue
		}
		if err := netlink.RouteDel(&r); err != nil {
			return err
		}
	}

	return nil
}
