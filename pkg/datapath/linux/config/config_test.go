// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"strings"
	"testing"

	. "github.com/cilium/checkmate"
	"github.com/vishvananda/netlink"

	"github.com/cilium/ebpf/rlimit"

	"github.com/cilium/cilium/pkg/datapath/loader"
	datapath "github.com/cilium/cilium/pkg/datapath/types"
	"github.com/cilium/cilium/pkg/maps/ctmap"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/testutils"
)

type ConfigSuite struct{}

func Test(t *testing.T) {
	TestingT(t)
}

var (
	_ = Suite(&ConfigSuite{})

	dummyNodeCfg  = datapath.LocalNodeConfiguration{}
	dummyDevCfg   = testutils.NewTestEndpoint()
	dummyEPCfg    = testutils.NewTestEndpoint()
	ipv4DummyAddr = netip.MustParseAddr("192.0.2.3")
	ipv6DummyAddr = netip.MustParseAddr("2001:db08:0bad:cafe:600d:bee2:0bad:cafe")
)

func (s *ConfigSuite) SetUpSuite(c *C) {
	testutils.PrivilegedTest(c)

	ctmap.InitMapInfo(option.CTMapEntriesGlobalTCPDefault, option.CTMapEntriesGlobalAnyDefault, true, true, true)
}

func (s *ConfigSuite) SetUpTest(c *C) {
	err := rlimit.RemoveMemlock()
	c.Assert(err, IsNil)
	node.InitDefaultPrefix("")
	node.SetInternalIPv4Router(ipv4DummyAddr.AsSlice())
	node.SetIPv4Loopback(ipv4DummyAddr.AsSlice())
}

func (s *ConfigSuite) TearDownTest(c *C) {
	node.SetInternalIPv4Router(nil)
	node.SetIPv4Loopback(nil)
}

type badWriter struct{}

func (b *badWriter) Write(p []byte) (int, error) {
	return 0, errors.New("bad write :(")
}

type writeFn func(io.Writer, datapath.ConfigWriter) error

func writeConfig(c *C, header string, write writeFn) {
	tests := []struct {
		description string
		output      io.Writer
		expResult   Checker
	}{
		{
			description: "successful write to an in-memory buffer",
			output:      &bytes.Buffer{},
			expResult:   IsNil,
		},
		{
			description: "write to a failing writer",
			output:      &badWriter{},
			expResult:   NotNil,
		},
	}
	for _, test := range tests {
		c.Logf("  Testing %s configuration: %s", header, test.description)
		cfg := &HeaderfileWriter{}
		c.Assert(write(test.output, cfg), test.expResult)
	}
}

func (s *ConfigSuite) TestWriteNodeConfig(c *C) {
	writeConfig(c, "node", func(w io.Writer, dp datapath.ConfigWriter) error {
		return dp.WriteNodeConfig(w, &dummyNodeCfg)
	})
}

func (s *ConfigSuite) TestWriteNetdevConfig(c *C) {
	writeConfig(c, "netdev", func(w io.Writer, dp datapath.ConfigWriter) error {
		return dp.WriteNetdevConfig(w, &dummyDevCfg)
	})
}

func (s *ConfigSuite) TestWriteEndpointConfig(c *C) {
	writeConfig(c, "endpoint", func(w io.Writer, dp datapath.ConfigWriter) error {
		return dp.WriteEndpointConfig(w, &dummyEPCfg)
	})

	// Create copy of config option so that it can be restored at the end of
	// this test. In the future, we'd like to parallelize running unit tests.
	// As it stands, this test would not be ready to parallelize until we
	// remove our dependency on globals (e.g. option.Config).
	oldEnableIPv6 := option.Config.EnableIPv6
	defer func() {
		option.Config.EnableIPv6 = oldEnableIPv6
	}()

	testRun := func(t *testutils.TestEndpoint) ([]byte, map[string]uint64, map[string]string) {
		cfg := &HeaderfileWriter{}
		varSub, stringSub := loader.ELFSubstitutions(t)

		var buf bytes.Buffer
		cfg.writeStaticData(&buf, t)

		return buf.Bytes(), varSub, stringSub
	}

	lxcIPs := []string{"LXC_IP_1", "LXC_IP_2"}

	tests := []struct {
		description string
		template    testutils.TestEndpoint // Represents template bpf prog
		endpoint    testutils.TestEndpoint // Represents normal endpoint bpf prog
		preTestRun  func(t *testutils.TestEndpoint, e *testutils.TestEndpoint)
		templateExp bool
		endpointExp bool
	}{
		{
			description: "IPv6 is disabled, endpoint does not have an IPv6 addr",
			template:    testutils.NewTestEndpoint(),
			endpoint:    testutils.NewTestEndpoint(),
			preTestRun: func(t *testutils.TestEndpoint, e *testutils.TestEndpoint) {
				option.Config.EnableIPv6 = false
				t.IPv6 = ipv6DummyAddr // Template bpf prog always has dummy IPv6
				e.IPv6 = netip.Addr{}  // This endpoint does not have an IPv6 addr
			},
			templateExp: true,
			endpointExp: false,
		},
		{
			description: "IPv6 is disabled, endpoint does have an IPv6 addr",
			template:    testutils.NewTestEndpoint(),
			endpoint:    testutils.NewTestEndpoint(),
			preTestRun: func(t *testutils.TestEndpoint, e *testutils.TestEndpoint) {
				option.Config.EnableIPv6 = false
				t.IPv6 = ipv6DummyAddr // Template bpf prog always has dummy IPv6
				e.IPv6 = ipv6DummyAddr // This endpoint does have an IPv6 addr
			},
			templateExp: true,
			endpointExp: true,
		},
		{
			description: "IPv6 is enabled",
			template:    testutils.NewTestEndpoint(),
			endpoint:    testutils.NewTestEndpoint(),
			preTestRun: func(t *testutils.TestEndpoint, e *testutils.TestEndpoint) {
				option.Config.EnableIPv6 = true
				t.IPv6 = ipv6DummyAddr
				e.IPv6 = ipv6DummyAddr
			},
			templateExp: true,
			endpointExp: true,
		},
		{
			description: "IPv6 is enabled, endpoint does not have IPv6 address",
			template:    testutils.NewTestEndpoint(),
			endpoint:    testutils.NewTestEndpoint(),
			preTestRun: func(t *testutils.TestEndpoint, e *testutils.TestEndpoint) {
				option.Config.EnableIPv6 = true
				t.IPv6 = ipv6DummyAddr
				e.IPv6 = netip.Addr{}
			},
			templateExp: true,
			endpointExp: false,
		},
	}
	for _, test := range tests {
		c.Logf("Testing %s", test.description)
		test.preTestRun(&test.template, &test.endpoint)

		b, vsub, _ := testRun(&test.template)
		c.Assert(bytes.Contains(b, []byte("DEFINE_IPV6")), Equals, test.templateExp)
		assertKeysInsideMap(c, vsub, lxcIPs, test.templateExp)

		b, vsub, _ = testRun(&test.endpoint)
		c.Assert(bytes.Contains(b, []byte("DEFINE_IPV6")), Equals, test.endpointExp)
		assertKeysInsideMap(c, vsub, lxcIPs, test.endpointExp)
	}
}

func (s *ConfigSuite) TestWriteStaticData(c *C) {
	cfg := &HeaderfileWriter{}
	ep := &dummyEPCfg

	varSub, stringSub := loader.ELFSubstitutions(ep)

	var buf bytes.Buffer
	cfg.writeStaticData(&buf, ep)
	b := buf.Bytes()
	for k := range varSub {
		for _, suffix := range []string{"_1", "_2"} {
			// Variables with these suffixes are implemented via
			// multiple 64-bit values. The header define doesn't
			// include these numbers though, so strip them.
			if strings.HasSuffix(k, suffix) {
				k = strings.TrimSuffix(k, suffix)
				break
			}
		}
		c.Assert(bytes.Contains(b, []byte(k)), Equals, true)
	}
	for _, v := range stringSub {
		c.Logf("Ensuring config has %s", v)
		if strings.HasPrefix(v, "1/0x") {
			// Skip tail call map name replacement
			continue
		}
		c.Assert(bytes.Contains(b, []byte(v)), Equals, true)
	}
}

func assertKeysInsideMap(c *C, m map[string]uint64, keys []string, want bool) {
	for _, v := range keys {
		_, ok := m[v]
		c.Assert(ok, Equals, want)
	}
}

func createMainLink(name string, c *C) *netlink.Dummy {
	link := &netlink.Dummy{
		LinkAttrs: netlink.LinkAttrs{
			Name: name,
		},
	}
	err := netlink.LinkAdd(link)
	c.Assert(err, IsNil)

	return link
}

func createVlanLink(vlanId int, mainLink *netlink.Dummy, c *C) *netlink.Vlan {
	link := &netlink.Vlan{
		LinkAttrs: netlink.LinkAttrs{
			Name:        fmt.Sprintf("%s.%d", mainLink.Name, vlanId),
			ParentIndex: mainLink.Index,
		},
		VlanProtocol: netlink.VLAN_PROTOCOL_8021Q,
		VlanId:       vlanId,
	}
	err := netlink.LinkAdd(link)
	c.Assert(err, IsNil)

	return link
}

func (s *ConfigSuite) TestVLANBypassConfig(c *C) {
	oldDevices := option.Config.GetDevices()
	defer func() {
		option.Config.SetDevices(oldDevices)
	}()

	main1 := createMainLink("dummy0", c)
	defer func() {
		netlink.LinkDel(main1)
	}()

	for i := 4000; i < 4003; i++ {
		vlan := createVlanLink(i, main1, c)
		defer func() {
			netlink.LinkDel(vlan)
		}()
	}

	main2 := createMainLink("dummy1", c)
	defer func() {
		netlink.LinkDel(main2)
	}()

	for i := 4003; i < 4006; i++ {
		vlan := createVlanLink(i, main2, c)
		defer func() {
			netlink.LinkDel(vlan)
		}()
	}

	option.Config.SetDevices([]string{"dummy0", "dummy0.4000", "dummy0.4001", "dummy1", "dummy1.4003"})
	option.Config.VLANBPFBypass = []int{4004}
	m, err := vlanFilterMacros()
	c.Assert(err, Equals, nil)
	c.Assert(m, Equals, fmt.Sprintf(`switch (ifindex) { \
case %d: \
switch (vlan_id) { \
case 4000: \
case 4001: \
return true; \
} \
break; \
case %d: \
switch (vlan_id) { \
case 4003: \
case 4004: \
return true; \
} \
break; \
} \
return false;`, main1.Index, main2.Index))

	option.Config.VLANBPFBypass = []int{4002, 4004, 4005}
	_, err = vlanFilterMacros()
	c.Assert(err, NotNil)

	option.Config.VLANBPFBypass = []int{0}
	m, err = vlanFilterMacros()
	c.Assert(err, IsNil)
	c.Assert(m, Equals, "return true")
}
