// SPDX-License-Identifier: Apache-2.0
// Copyright 2021 Authors of Cilium

//go:build linux && privileged_tests
// +build linux,privileged_tests

package cmd

import (
	"context"
	"net"
	"runtime"
	"time"

	"github.com/cilium/cilium/pkg/checker"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/option"

	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
	. "gopkg.in/check.v1"
)

type DevicesSuite struct {
	currentNetNS                  netns.NsHandle
	prevConfigDevices             []string
	prevConfigDirectRoutingDevice string
	prevConfigEnableIPv4          bool
	prevConfigEnableIPv6          bool
	prevK8sNodeIP                 net.IP
}

var _ = Suite(&DevicesSuite{})

func (s *DevicesSuite) SetUpSuite(c *C) {
	var err error

	s.prevConfigDevices = option.Config.Devices
	s.prevConfigDirectRoutingDevice = option.Config.DirectRoutingDevice
	s.prevConfigEnableIPv4 = option.Config.EnableIPv4
	s.prevConfigEnableIPv6 = option.Config.EnableIPv6
	s.prevK8sNodeIP = node.GetK8sNodeIP()

	s.currentNetNS, err = netns.Get()
	c.Assert(err, IsNil)
}

func (s *DevicesSuite) TearDownTest(c *C) {
	option.Config.Devices = s.prevConfigDevices
	option.Config.DirectRoutingDevice = s.prevConfigDirectRoutingDevice
	option.Config.EnableIPv4 = s.prevConfigEnableIPv4
	option.Config.EnableIPv6 = s.prevConfigEnableIPv6
	node.SetK8sNodeIP(s.prevK8sNodeIP)
}

func (s *DevicesSuite) TestDetect(c *C) {
	s.withFreshNetNS(c, func() {
		node.SetK8sNodeIP(net.ParseIP("192.168.0.1"))
		option.Config.EnableNodePort = true // TODO restore

		dm := NewDeviceManager()

		// 1. No devices = impossible to detect
		c.Assert(dm.Detect(), NotNil)

		// 2. Manually specified devices, no detection is performed
		c.Assert(createDummy("dummy0", "192.168.0.1/24", false), IsNil)
		c.Assert(createDummy("dummy1", "192.168.1.2/24", false), IsNil)
		option.Config.Devices = []string{"dummy0"}
		c.Assert(dm.Detect(), IsNil)
		option.Config.Devices = []string{}
		option.Config.DirectRoutingDevice = ""

		// 3. Direct routing mode, should find all devices and set direct
		// routing device to the one with k8s node ip.
		c.Assert(createDummy("dummy2", "192.168.2.3/24", false), IsNil)
		node.SetK8sNodeIP(net.ParseIP("192.168.1.2"))
		option.Config.EnableIPv4 = true
		option.Config.EnableIPv6 = false
		option.Config.Tunnel = option.TunnelDisabled // TODO restore
		c.Assert(dm.Detect(), IsNil)
		c.Assert(option.Config.Devices, checker.DeepEquals, []string{"dummy0", "dummy1", "dummy2"})
		c.Assert(option.Config.DirectRoutingDevice, Equals, "dummy1")
		option.Config.Devices = []string{}
		option.Config.DirectRoutingDevice = ""

		// 4. With IPv6 node address on dummy3, set cilium_foo interface to node IP,
		// only dummy3 should be detected matching node IP (no IPv6 default route present)
		option.Config.EnableIPv6 = true
		c.Assert(createDummy("dummy3", "2001:db8::face/64", true), IsNil)
		c.Assert(createDummy("cilium_foo", "2001:db8::face/128", true), IsNil)
		node.SetK8sNodeIP(net.ParseIP("2001:db8::face"))
		option.Config.EnableIPv6NDP = true // TODO restore
		c.Assert(dm.Detect(), IsNil)
		c.Assert(option.Config.Devices, checker.DeepEquals, []string{"dummy0", "dummy1", "dummy2", "dummy3"})
		c.Assert(option.Config.DirectRoutingDevice, checker.Equals, "dummy3")
		c.Assert(option.Config.IPv6MCastDevice, checker.DeepEquals, "dummy3")

		// TODO(JM): Test failure to detect direct-routing/ipv6mcast
		// TODO(JM): Test that devices without routes are not detected.
	})
}

func (s *DevicesSuite) TestExpandDevices(c *C) {
	s.withFreshNetNS(c, func() {
		c.Assert(createDummy("dummy0", "192.168.0.1/24", false), IsNil)
		c.Assert(createDummy("dummy1", "192.168.1.2/24", false), IsNil)
		c.Assert(createDummy("other0", "192.168.2.3/24", false), IsNil)
		c.Assert(createDummy("other1", "192.168.3.4/24", false), IsNil)
		c.Assert(createDummy("unmatched", "192.168.4.5/24", false), IsNil)

		option.Config.Devices = []string{"dummy+", "missing+", "other0+" /* duplicates: */, "dum+", "other0", "other1"}
		expandDevices()
		c.Assert(option.Config.Devices, checker.DeepEquals, []string{"dummy0", "dummy1", "other0", "other1"})
	})
}

func (s *DevicesSuite) TestListenForNewDevices(c *C) {
	s.withFreshNetNS(c, func() {
		option.Config.Devices = []string{}
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		updated := make(chan struct{})
		timeout := time.After(time.Second)

		netns, err := netns.Get()
		c.Assert(err, IsNil)

		dm := NewDeviceManager()

		err = dm.Listen(ctx, &netns, func() { updated <- struct{}{} })
		c.Assert(err, IsNil)

		c.Assert(option.Config.Devices, checker.DeepEquals, []string{})

		// Create the IPv4 & IPv6 devices that should be detected.
		c.Assert(createDummy("dummy0", "192.168.1.2/24", false), IsNil)
		c.Assert(createDummy("dummy1", "2001:db8::face/64", true), IsNil)

		// Create another device without an IP address or routes. This should be ignored.
		c.Assert(createDummy("dummy2", "", false), IsNil)

		// Create a veth device which should be detected. veth devices are used in test
		// setups.
		c.Assert(createVeth("eth0", "192.168.2.2/24", false), IsNil)

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
			case <-updated:
				passed, _ = checker.DeepEqual(option.Config.Devices, []string{"dummy0", "dummy1", "eth0"})
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
			case <-updated:
				passed, _ = checker.DeepEqual(option.Config.Devices, []string{"dummy1"})
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

	link, err := netlink.LinkByName(iface)
	if err != nil {
		return err
	}

	if ipAddr != "" {
		ip, ipnet, err := net.ParseCIDR(ipAddr)
		if err != nil {
			return err
		}
		ipnet.IP = ip

		if err := netlink.AddrAdd(link, &netlink.Addr{IPNet: ipnet}); err != nil {
			return err
		}
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

func addDefaultRoute(iface string, ipAddr string) error {
	link, err := netlink.LinkByName(iface)
	if err != nil {
		return err
	}

	route := &netlink.Route{
		LinkIndex: link.Attrs().Index,
		Dst:       nil,
		Gw:        net.ParseIP(ipAddr),
	}
	if err := netlink.RouteAdd(route); err != nil {
		return err
	}

	return nil
}
