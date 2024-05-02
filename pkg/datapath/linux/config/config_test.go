// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package config

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"strings"
	"testing"

	"github.com/cilium/ebpf/rlimit"
	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/hivetest"
	"github.com/spf13/afero"
	"github.com/stretchr/testify/require"
	"github.com/vishvananda/netlink"

	"github.com/cilium/cilium/pkg/cidr"
	fakeTypes "github.com/cilium/cilium/pkg/datapath/fake/types"
	dpdef "github.com/cilium/cilium/pkg/datapath/linux/config/defines"
	"github.com/cilium/cilium/pkg/datapath/linux/sysctl"
	"github.com/cilium/cilium/pkg/datapath/loader"
	"github.com/cilium/cilium/pkg/datapath/tables"
	datapath "github.com/cilium/cilium/pkg/datapath/types"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/maps/nodemap"
	"github.com/cilium/cilium/pkg/maps/nodemap/fake"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/testutils"
)

var (
	dummyNodeCfg = datapath.LocalNodeConfiguration{
		NodeIPv4:           ipv4DummyAddr.AsSlice(),
		NodeIPv6:           ipv6DummyAddr.AsSlice(),
		CiliumInternalIPv4: ipv4DummyAddr.AsSlice(),
		CiliumInternalIPv6: ipv6DummyAddr.AsSlice(),
		AllocCIDRIPv4:      cidr.MustParseCIDR("10.147.0.0/16"),
		LoopbackIPv4:       ipv4DummyAddr.AsSlice(),
		Devices:            []*tables.Device{},
		NodeAddresses:      []tables.NodeAddress{},
		HostEndpointID:     1,
	}
	dummyDevCfg   = testutils.NewTestEndpoint()
	dummyEPCfg    = testutils.NewTestEndpoint()
	ipv4DummyAddr = netip.MustParseAddr("192.0.2.3")
	ipv6DummyAddr = netip.MustParseAddr("2001:db08:0bad:cafe:600d:bee2:0bad:cafe")
)

func setupConfigSuite(tb testing.TB) {
	testutils.PrivilegedTest(tb)

	tb.Helper()

	require.NoError(tb, rlimit.RemoveMemlock(), "Failed to remove memory limits")

	option.Config.EnableHostLegacyRouting = true // Disable obtaining direct routing device.
}

type badWriter struct{}

func (b *badWriter) Write(p []byte) (int, error) {
	return 0, errors.New("bad write :(")
}

type writeFn func(io.Writer, datapath.ConfigWriter) error

func writeConfig(t *testing.T, header string, write writeFn) {
	tests := []struct {
		description string
		output      io.Writer
		wantErr     bool
	}{
		{
			description: "successful write to an in-memory buffer",
			output:      &bytes.Buffer{},
			wantErr:     false,
		},
		{
			description: "write to a failing writer",
			output:      &badWriter{},
			wantErr:     true,
		},
	}
	for _, test := range tests {
		var writer datapath.ConfigWriter
		t.Logf("  Testing %s configuration: %s", header, test.description)
		h := hive.New(
			provideNodemap,
			tables.DirectRoutingDeviceCell,
			cell.Provide(
				fakeTypes.NewNodeAddressing,
				func() sysctl.Sysctl { return sysctl.NewDirectSysctl(afero.NewOsFs(), "/proc") },
				NewHeaderfileWriter,
			),
			cell.Invoke(func(writer_ datapath.ConfigWriter) {
				writer = writer_
			}),
		)

		tlog := hivetest.Logger(t)
		require.NoError(t, h.Start(tlog, context.TODO()))
		t.Cleanup(func() { require.Nil(t, h.Stop(tlog, context.TODO())) })
		err := write(test.output, writer)
		require.True(t, test.wantErr == (err != nil), "wantErr=%v, err=%s", test.wantErr, err)
	}
}

func TestWriteNodeConfig(t *testing.T) {
	setupConfigSuite(t)
	writeConfig(t, "node", func(w io.Writer, dp datapath.ConfigWriter) error {
		return dp.WriteNodeConfig(w, &dummyNodeCfg)
	})
}

func TestWriteNetdevConfig(t *testing.T) {
	writeConfig(t, "netdev", func(w io.Writer, dp datapath.ConfigWriter) error {
		return dp.WriteNetdevConfig(w, dummyDevCfg.GetOptions())
	})
}

func TestWriteEndpointConfig(t *testing.T) {
	writeConfig(t, "endpoint", func(w io.Writer, dp datapath.ConfigWriter) error {
		return dp.WriteEndpointConfig(w, &dummyNodeCfg, &dummyEPCfg)
	})

	// Create copy of config option so that it can be restored at the end of
	// this test. In the future, we'd like to parallelize running unit tests.
	// As it stands, this test would not be ready to parallelize until we
	// remove our dependency on globals (e.g. option.Config).
	oldEnableIPv6 := option.Config.EnableIPv6
	defer func() {
		option.Config.EnableIPv6 = oldEnableIPv6
	}()

	testRun := func(te *testutils.TestEndpoint) ([]byte, map[string]uint64) {
		cfg := &HeaderfileWriter{}
		varSub := loader.ELFVariableSubstitutions(te)

		var buf bytes.Buffer
		cfg.writeStaticData(nil, &buf, te)

		return buf.Bytes(), varSub
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
		t.Logf("Testing %s", test.description)
		test.preTestRun(&test.template, &test.endpoint)

		b, vsub := testRun(&test.template)
		require.Equal(t, test.templateExp, bytes.Contains(b, []byte("DEFINE_IPV6")))
		assertKeysInsideMap(t, vsub, lxcIPs, test.templateExp)

		b, vsub = testRun(&test.endpoint)
		require.Equal(t, test.endpointExp, bytes.Contains(b, []byte("DEFINE_IPV6")))
		assertKeysInsideMap(t, vsub, lxcIPs, test.endpointExp)
	}
}

func TestWriteStaticData(t *testing.T) {
	cfg := &HeaderfileWriter{}
	ep := &dummyEPCfg

	varSub := loader.ELFVariableSubstitutions(ep)
	mapSub := loader.ELFMapSubstitutions(ep)

	var buf bytes.Buffer
	cfg.writeStaticData(nil, &buf, ep)
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
		require.Equal(t, true, bytes.Contains(b, []byte(k)))
	}
	for _, v := range mapSub {
		t.Logf("Ensuring config has %s", v)
		require.Equal(t, true, bytes.Contains(b, []byte(v)))
	}
}

func assertKeysInsideMap(t *testing.T, m map[string]uint64, keys []string, want bool) {
	for _, v := range keys {
		_, ok := m[v]
		require.Equal(t, want, ok)
	}
}

func createMainLink(name string, t *testing.T) *netlink.Dummy {
	link := &netlink.Dummy{
		LinkAttrs: netlink.LinkAttrs{
			Name: name,
		},
	}
	err := netlink.LinkAdd(link)
	require.NoError(t, err)

	return link
}

func createVlanLink(vlanId int, mainLink *netlink.Dummy, t *testing.T) *netlink.Vlan {
	link := &netlink.Vlan{
		LinkAttrs: netlink.LinkAttrs{
			Name:        fmt.Sprintf("%s.%d", mainLink.Name, vlanId),
			ParentIndex: mainLink.Index,
		},
		VlanProtocol: netlink.VLAN_PROTOCOL_8021Q,
		VlanId:       vlanId,
	}
	err := netlink.LinkAdd(link)
	require.Nil(t, err)

	return link
}

func TestVLANBypassConfig(t *testing.T) {
	setupConfigSuite(t)

	var devs []*tables.Device

	main1 := createMainLink("dummy0", t)
	devs = append(devs, &tables.Device{Name: main1.Name, Index: main1.Index})
	defer func() {
		netlink.LinkDel(main1)
	}()

	// Define set of vlans which we want to allow.
	allow := map[int]bool{
		4000: true,
		4001: true,
		4003: true,
	}

	for i := 4000; i < 4003; i++ {
		vlan := createVlanLink(i, main1, t)
		if allow[i] {
			devs = append(devs, &tables.Device{Index: vlan.Index, Name: vlan.Name})
		}
		defer func() {
			netlink.LinkDel(vlan)
		}()
	}

	main2 := createMainLink("dummy1", t)
	devs = append(devs, &tables.Device{Name: main2.Name, Index: main2.Index})
	defer func() {
		netlink.LinkDel(main2)
	}()

	for i := 4003; i < 4006; i++ {
		vlan := createVlanLink(i, main2, t)
		if allow[i] {
			devs = append(devs, &tables.Device{Index: vlan.Index, Name: vlan.Name})
		}
		defer func() {
			netlink.LinkDel(vlan)
		}()
	}

	option.Config.VLANBPFBypass = []int{4004}
	m, err := vlanFilterMacros(devs)
	require.Equal(t, nil, err)
	require.Equal(t, fmt.Sprintf(`switch (ifindex) { \
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
return false;`, main1.Index, main2.Index), m)

	option.Config.VLANBPFBypass = []int{4002, 4004, 4005}
	_, err = vlanFilterMacros(devs)
	require.Error(t, err)

	option.Config.VLANBPFBypass = []int{0}
	m, err = vlanFilterMacros(devs)
	require.Nil(t, err)
	require.Equal(t, "return true", m)
}

func TestWriteNodeConfigExtraDefines(t *testing.T) {
	testutils.PrivilegedTest(t)
	setupConfigSuite(t)

	var (
		na datapath.NodeAddressing
	)
	h := hive.New(
		cell.Provide(
			fakeTypes.NewNodeAddressing,
		),
		cell.Invoke(func(
			nodeaddressing datapath.NodeAddressing,
		) {
			na = nodeaddressing
		}),
	)

	tlog := hivetest.Logger(t)
	require.NoError(t, h.Start(tlog, context.TODO()))
	t.Cleanup(func() { h.Stop(tlog, context.TODO()) })

	var buffer bytes.Buffer

	// Assert that configurations are propagated when all generated extra defines are valid
	cfg, err := NewHeaderfileWriter(WriterParams{
		NodeAddressing:   na,
		NodeExtraDefines: nil,
		NodeExtraDefineFns: []dpdef.Fn{
			func() (dpdef.Map, error) { return dpdef.Map{"FOO": "0x1", "BAR": "0x2"}, nil },
			func() (dpdef.Map, error) { return dpdef.Map{"BAZ": "0x3"}, nil },
		},
		Sysctl:  sysctl.NewDirectSysctl(afero.NewOsFs(), "/proc"),
		NodeMap: fake.NewFakeNodeMapV2(),
	})
	require.NoError(t, err)

	buffer.Reset()
	require.NoError(t, cfg.WriteNodeConfig(&buffer, &dummyNodeCfg))

	output := buffer.String()
	require.Contains(t, output, "define FOO 0x1\n")
	require.Contains(t, output, "define BAR 0x2\n")
	require.Contains(t, output, "define BAZ 0x3\n")

	// Assert that an error is returned when one extra define function returns an error
	cfg, err = NewHeaderfileWriter(WriterParams{
		NodeAddressing:   fakeTypes.NewNodeAddressing(),
		NodeExtraDefines: nil,
		NodeExtraDefineFns: []dpdef.Fn{
			func() (dpdef.Map, error) { return nil, errors.New("failing on purpose") },
		},
		Sysctl:  sysctl.NewDirectSysctl(afero.NewOsFs(), "/proc"),
		NodeMap: fake.NewFakeNodeMapV2(),
	})
	require.NoError(t, err)

	buffer.Reset()
	require.Error(t, cfg.WriteNodeConfig(&buffer, &dummyNodeCfg))

	// Assert that an error is returned when one extra define would overwrite an already existing entry
	cfg, err = NewHeaderfileWriter(WriterParams{
		NodeAddressing:   fakeTypes.NewNodeAddressing(),
		NodeExtraDefines: nil,
		NodeExtraDefineFns: []dpdef.Fn{
			func() (dpdef.Map, error) { return dpdef.Map{"FOO": "0x1", "BAR": "0x2"}, nil },
			func() (dpdef.Map, error) { return dpdef.Map{"FOO": "0x3"}, nil },
		},
		Sysctl:  sysctl.NewDirectSysctl(afero.NewOsFs(), "/proc"),
		NodeMap: fake.NewFakeNodeMapV2(),
	})
	require.NoError(t, err)

	buffer.Reset()
	require.Error(t, cfg.WriteNodeConfig(&buffer, &dummyNodeCfg))
}

func TestNewHeaderfileWriter(t *testing.T) {
	testutils.PrivilegedTest(t)
	setupConfigSuite(t)

	a := dpdef.Map{"A": "1"}
	var buffer bytes.Buffer

	_, err := NewHeaderfileWriter(WriterParams{
		NodeAddressing:     fakeTypes.NewNodeAddressing(),
		NodeExtraDefines:   []dpdef.Map{a, a},
		NodeExtraDefineFns: nil,
		Sysctl:             sysctl.NewDirectSysctl(afero.NewOsFs(), "/proc"),
		NodeMap:            fake.NewFakeNodeMapV2(),
	})

	require.Error(t, err, "duplicate keys should be rejected")

	cfg, err := NewHeaderfileWriter(WriterParams{
		NodeAddressing:     fakeTypes.NewNodeAddressing(),
		NodeExtraDefines:   []dpdef.Map{a},
		NodeExtraDefineFns: nil,
		Sysctl:             sysctl.NewDirectSysctl(afero.NewOsFs(), "/proc"),
		NodeMap:            fake.NewFakeNodeMapV2(),
	})
	require.NoError(t, err)
	require.NoError(t, cfg.WriteNodeConfig(&buffer, &dummyNodeCfg))
	require.Contains(t, buffer.String(), "define A 1\n")
}

var provideNodemap = cell.Provide(func() nodemap.MapV2 {
	return fake.NewFakeNodeMapV2()
})
