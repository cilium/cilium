// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build linux

package loader

import (
	"fmt"

	. "github.com/cilium/checkmate"
	"github.com/vishvananda/netlink"

	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/sysctl"
	"github.com/cilium/cilium/pkg/testutils"
)

type NetlinkTestSuite struct {
	prevConfigEnableIPv4 bool
	prevConfigEnableIPv6 bool
}

var _ = Suite(&NetlinkTestSuite{})

func (s *NetlinkTestSuite) SetUpSuite(c *C) {
	testutils.PrivilegedTest(c)

	s.prevConfigEnableIPv4 = option.Config.EnableIPv4
	s.prevConfigEnableIPv6 = option.Config.EnableIPv6

	option.Config.EnableIPv4 = true
	option.Config.EnableIPv6 = true
}

func (s *NetlinkTestSuite) TearDownSuite(c *C) {
	option.Config.EnableIPv4 = s.prevConfigEnableIPv4
	option.Config.EnableIPv6 = s.prevConfigEnableIPv6
}

func (s *NetlinkTestSuite) TestSetupDev(c *C) {
	ifName := "dummy9"

	dummy := &netlink.Dummy{
		LinkAttrs: netlink.LinkAttrs{
			Name: ifName,
		},
	}
	err := netlink.LinkAdd(dummy)
	c.Assert(err, IsNil)

	err = setupDev(dummy)
	c.Assert(err, IsNil)

	enabledSettings := []string{
		fmt.Sprintf("net.ipv6.conf.%s.forwarding", ifName),
		fmt.Sprintf("net.ipv4.conf.%s.forwarding", ifName),
		fmt.Sprintf("net.ipv4.conf.%s.accept_local", ifName),
	}
	disabledSettings := []string{
		fmt.Sprintf("net.ipv4.conf.%s.rp_filter", ifName),
		fmt.Sprintf("net.ipv4.conf.%s.send_redirects", ifName),
	}
	for _, setting := range enabledSettings {
		s, err := sysctl.Read(setting)
		c.Assert(err, IsNil)
		c.Assert(s, Equals, "1")
	}
	for _, setting := range disabledSettings {
		s, err := sysctl.Read(setting)
		c.Assert(err, IsNil)
		c.Assert(s, Equals, "0")
	}

	err = netlink.LinkDel(dummy)
	c.Assert(err, IsNil)
}
