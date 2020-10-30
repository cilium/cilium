// Copyright 2020 Authors of Cilium
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

// +build linux,privileged_tests

package cmd

import (
	"net"
	"runtime"
	"sort"

	"github.com/cilium/cilium/pkg/checker"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/option"

	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
	. "gopkg.in/check.v1"
)

type KubeProxySuite struct {
	currentNetNS                  netns.NsHandle
	testNetNS                     netns.NsHandle
	prevConfigDevices             []string
	prevConfigDirectRoutingDevice string
	prevConfigEnableIPv4          bool
	prevConfigEnableIPv6          bool
	prevK8sNodeIP                 net.IP
}

var _ = Suite(&KubeProxySuite{})

func (s *KubeProxySuite) SetUpSuite(c *C) {
	var err error

	s.prevConfigDevices = option.Config.Devices
	s.prevConfigDirectRoutingDevice = option.Config.DirectRoutingDevice
	s.prevConfigEnableIPv4 = option.Config.EnableIPv4
	s.prevConfigEnableIPv6 = option.Config.EnableIPv6
	s.prevK8sNodeIP = node.GetK8sNodeIP()

	s.currentNetNS, err = netns.Get()
	c.Assert(err, IsNil)
	s.testNetNS, err = netns.New()
	c.Assert(err, IsNil)
}

func (s *KubeProxySuite) TearDownTest(c *C) {
	option.Config.Devices = s.prevConfigDevices
	option.Config.DirectRoutingDevice = s.prevConfigDirectRoutingDevice
	option.Config.EnableIPv4 = s.prevConfigEnableIPv4
	option.Config.EnableIPv6 = s.prevConfigEnableIPv6
	node.SetK8sNodeIP(s.prevK8sNodeIP)

	c.Assert(s.testNetNS.Close(), IsNil)
}

func (s *KubeProxySuite) TestDetectDevices(c *C) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	c.Assert(netns.Set(s.testNetNS), IsNil)
	defer func() { c.Assert(netns.Set(s.currentNetNS), IsNil) }()

	// 1. No devices = impossible to detect
	c.Assert(detectDevices(true, true), NotNil)

	// 2. No devices, but no detection is required
	c.Assert(detectDevices(false, false), IsNil)

	// 3. Direct routing mode, should find dummy0 for both opts
	c.Assert(createDummy("dummy0", "192.168.0.1/24"), IsNil)
	c.Assert(createDummy("dummy1", "192.168.1.2/24"), IsNil)
	c.Assert(createDummy("dummy2", "192.168.2.3/24"), IsNil)
	option.Config.EnableIPv4 = true
	option.Config.EnableIPv6 = false
	option.Config.Tunnel = option.TunnelDisabled
	node.SetK8sNodeIP(net.ParseIP("192.168.0.1"))
	c.Assert(detectDevices(true, true), IsNil)
	c.Assert(option.Config.Devices, checker.DeepEquals, []string{"dummy0"})
	c.Assert(option.Config.DirectRoutingDevice, Equals, "dummy0")

	// 4. dummy1 should be detected too
	c.Assert(addDefaultRoute("dummy1", "192.168.1.1"), IsNil)
	c.Assert(detectDevices(true, true), IsNil)
	sort.Strings(option.Config.Devices)
	c.Assert(option.Config.Devices, checker.DeepEquals, []string{"dummy0", "dummy1"})
	c.Assert(option.Config.DirectRoutingDevice, Equals, "dummy0")

	// 5. Enable IPv6, dummy1 should not be detected, as no default route for
	// ipv6 is found
	option.Config.EnableIPv6 = true
	c.Assert(detectDevices(true, true), IsNil)
	c.Assert(option.Config.Devices, checker.DeepEquals, []string{"dummy0"})
	c.Assert(option.Config.DirectRoutingDevice, Equals, "dummy0")

	// 6. Set random NodeIP, only dummy1 should be detected
	option.Config.EnableIPv6 = false
	node.SetK8sNodeIP(net.ParseIP("192.168.34.1"))
	c.Assert(detectDevices(true, true), IsNil)
	c.Assert(option.Config.Devices, checker.DeepEquals, []string{"dummy1"})
	c.Assert(option.Config.DirectRoutingDevice, Equals, "dummy1")
}

func createDummy(iface, ipAddr string) error {
	dummy := &netlink.Dummy{
		LinkAttrs: netlink.LinkAttrs{
			Name: iface,
		},
	}
	if err := netlink.LinkAdd(dummy); err != nil {
		return err
	}

	link, err := netlink.LinkByName(iface)
	if err != nil {
		return err
	}

	ip, ipnet, err := net.ParseCIDR(ipAddr)
	if err != nil {
		return err
	}
	ipnet.IP = ip

	if err := netlink.AddrAdd(link, &netlink.Addr{IPNet: ipnet}); err != nil {
		return err
	}

	if err := netlink.LinkSetUp(link); err != nil {
		return err
	}

	return nil
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
