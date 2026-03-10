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
	"testing"
	"time"

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
	"github.com/cilium/cilium/pkg/datapath/tables"
	datapath "github.com/cilium/cilium/pkg/datapath/types"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/kpr"
	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/maglev"
	"github.com/cilium/cilium/pkg/maps/nodemap"
	"github.com/cilium/cilium/pkg/maps/nodemap/fake"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/testutils"
	"github.com/cilium/cilium/pkg/testutils/netns"
)

var (
	dummyNodeCfg = datapath.LocalNodeConfiguration{
		NodeIPv4:            ipv4DummyAddr,
		NodeIPv6:            ipv6DummyAddr,
		CiliumInternalIPv4:  ipv4DummyAddr,
		CiliumInternalIPv6:  ipv6DummyAddr,
		AllocCIDRIPv4:       cidr.MustParseCIDR("10.147.0.0/16"),
		ServiceLoopbackIPv4: ipv4DummyAddr,
		ServiceLoopbackIPv6: ipv6DummyAddr,
		Devices:             []*tables.Device{},
		NodeAddresses:       []tables.NodeAddress{},
		HostEndpointID:      1,
		MaglevConfig:        maglev.DefaultConfig,
	}
	dummyDevCfg   testutils.TestEndpoint
	ipv4DummyAddr = netip.MustParseAddr("192.0.2.3")
	ipv6DummyAddr = netip.MustParseAddr("2001:db08:0bad:cafe:600d:bee2:0bad:cafe")
)

func setupConfigSuite(tb testing.TB) {
	testutils.PrivilegedTest(tb)

	dummyDevCfg = testutils.NewTestEndpoint(tb)

	tb.Helper()

	require.NoError(tb, rlimit.RemoveMemlock(), "Failed to remove memory limits")

	option.Config.UnsafeDaemonConfigOption.EnableHostLegacyRouting = true // Disable obtaining direct routing device.
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
			maglev.Cell,
			cell.Provide(func() loadbalancer.Config { return loadbalancer.DefaultConfig }),
			cell.Provide(
				fakeTypes.NewNodeAddressing,
				func() sysctl.Sysctl { return sysctl.NewDirectSysctl(afero.NewOsFs(), "/proc") },
				NewHeaderfileWriter,
				func() datapath.IPsecConfig { return fakeTypes.IPsecConfig{} },
			),
			kpr.Cell,
			cell.Invoke(func(writer_ datapath.ConfigWriter) {
				writer = writer_
			}),
		)

		tlog := hivetest.Logger(t)
		require.NoError(t, h.Start(tlog, context.TODO()))
		t.Cleanup(func() { require.NoError(t, h.Stop(tlog, context.TODO())) })
		err := write(test.output, writer)
		require.Equal(t, test.wantErr, (err != nil), "wantErr=%v, err=%s", test.wantErr, err)
	}
}

func setupCiliumDummyDevices(t *testing.T, ns *netns.NetNS) {
	t.Helper()
	require.NoError(t, ns.Do(func() error {
		ciliumNet := &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: "cilium_net"}}
		if err := netlink.LinkAdd(ciliumNet); err != nil {
			return err
		}
		if err := netlink.LinkSetUp(ciliumNet); err != nil {
			return err
		}
		ciliumHost := &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: "cilium_host"}}
		if err := netlink.LinkAdd(ciliumHost); err != nil {
			return err
		}
		if err := netlink.LinkSetUp(ciliumHost); err != nil {
			return err
		}
		return nil
	}))

	t.Cleanup(func() {
		_ = ns.Do(func() error {
			err1 := netlink.LinkDel(&netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: "cilium_net"}})
			err2 := netlink.LinkDel(&netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: "cilium_host"}})
			if err1 != nil && err2 != nil {
				return fmt.Errorf("failed to delete cilium_net and cilium_host: %w", errors.Join(err1, err2))
			}
			if err1 != nil {
				return fmt.Errorf("failed to delete cilium_net: %w", err1)
			}
			if err2 != nil {
				return fmt.Errorf("failed to delete cilium_host: %w", err2)
			}
			return nil
		})
	})
}

func TestPrivilegedWriteNodeConfig(t *testing.T) {
	testutils.PrivilegedTest(t)
	ns := netns.NewNetNS(t)
	setupCiliumDummyDevices(t, ns)
	err := ns.Do(func() error {
		setupConfigSuite(t)
		writeConfig(t, "node", func(w io.Writer, dp datapath.ConfigWriter) error {
			return dp.WriteNodeConfig(w, &dummyNodeCfg)
		})
		return nil
	})
	require.NoError(t, err)
}

func TestPrivilegedWriteNetdevConfig(t *testing.T) {
	setupConfigSuite(t)
	writeConfig(t, "netdev", func(w io.Writer, dp datapath.ConfigWriter) error {
		return dp.WriteNetdevConfig(w, dummyDevCfg.GetOptions())
	})
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
	require.NoError(t, err)

	return link
}

func TestPrivilegedVLANBypassConfig(t *testing.T) {
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
	require.NoError(t, err)
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
	require.NoError(t, err)
	require.Equal(t, "return true", m)
}

func TestPrivilegedWriteNodeConfigExtraDefines(t *testing.T) {
	testutils.PrivilegedTest(t)
	ns := netns.NewNetNS(t)
	setupCiliumDummyDevices(t, ns)
	err := ns.Do(func() error {
		setupConfigSuite(t)

		var (
			na datapath.NodeAddressing
		)
		h := hive.New(
			cell.Provide(
				fakeTypes.NewNodeAddressing,
			),
			maglev.Cell,
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
		return nil
	})
	require.NoError(t, err)
}

func TestPreferredIPv6Address(t *testing.T) {
	testCases := []struct {
		name    string
		devices []tables.DeviceAddress
		want    netip.Addr
	}{
		{
			name: "link_local_only",
			devices: []tables.DeviceAddress{
				{
					Addr: netip.MustParseAddr("fe80::4001:aff:fe35:a805"),
				},
			},
			want: netip.MustParseAddr("fe80::4001:aff:fe35:a805"),
		},
		{
			name: "global_only",
			devices: []tables.DeviceAddress{
				{
					Addr: netip.MustParseAddr("2600:1900:4001:2a1:0:2::"),
				},
			},
			want: netip.MustParseAddr("2600:1900:4001:2a1:0:2::"),
		},
		{
			name: "local_first",
			devices: []tables.DeviceAddress{
				{
					Addr: netip.MustParseAddr("fe80::4001:aff:fe35:a805"),
				},
				{
					Addr: netip.MustParseAddr("2600:1900:4001:2a1:0:2::"),
				},
			},
			want: netip.MustParseAddr("2600:1900:4001:2a1:0:2::"),
		},
		{
			name: "global_first",
			devices: []tables.DeviceAddress{
				{
					Addr: netip.MustParseAddr("2600:1900:4001:2a1:0:2::"),
				},
				{
					Addr: netip.MustParseAddr("fe80::4001:aff:fe35:a805"),
				},
			},
			want: netip.MustParseAddr("2600:1900:4001:2a1:0:2::"),
		},
		{
			name: "select_first_global",
			devices: []tables.DeviceAddress{
				{
					Addr: netip.MustParseAddr("2600:1900:4001:2a1:0:2::"),
				},
				{
					Addr: netip.MustParseAddr("2600:1900:4001:2a1:0:3::"),
				},
			},
			want: netip.MustParseAddr("2600:1900:4001:2a1:0:2::"),
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			if got := preferredIPv6Address(tc.devices); got != tc.want {
				t.Errorf("preferredIPv6Address() mismatch, got %s want %s", got, tc.want)
			}
		})
	}
}

func TestPrivilegedNewHeaderfileWriter(t *testing.T) {
	testutils.PrivilegedTest(t)
	ns := netns.NewNetNS(t)
	setupCiliumDummyDevices(t, ns)
	err := ns.Do(func() error {
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
		return nil
	})
	require.NoError(t, err)
}

var provideNodemap = cell.Provide(func() nodemap.MapV2 {
	return fake.NewFakeNodeMapV2()
})

// writeNodeConfigToBuffer creates a HeaderfileWriter and writes the node
// configuration to a buffer. This helper is used by the datapath config
// defines tests below.
func writeNodeConfigToBuffer(t *testing.T, nodeCfg *datapath.LocalNodeConfiguration) string {
	t.Helper()
	cfg, err := NewHeaderfileWriter(WriterParams{
		NodeAddressing:     fakeTypes.NewNodeAddressing(),
		NodeExtraDefines:   nil,
		NodeExtraDefineFns: nil,
		Sysctl:             sysctl.NewDirectSysctl(afero.NewOsFs(), "/proc"),
		NodeMap:            fake.NewFakeNodeMapV2(),
	})
	require.NoError(t, err)

	var buffer bytes.Buffer
	require.NoError(t, cfg.WriteNodeConfig(&buffer, nodeCfg))
	return buffer.String()
}

// TestPrivilegedWriteNodeConfigMonitorAggregation verifies that the monitor
// aggregation configuration options (MonitorAggregationInterval and
// MonitorAggregationFlags) are correctly propagated to BPF defines
// (CT_REPORT_INTERVAL and CT_REPORT_FLAGS).
// This covers the MonitorAggregation scenarios previously tested by
// K8sDatapathConfig.
func TestPrivilegedWriteNodeConfigMonitorAggregation(t *testing.T) {
	testutils.PrivilegedTest(t)
	ns := netns.NewNetNS(t)
	setupCiliumDummyDevices(t, ns)
	err := ns.Do(func() error {
		setupConfigSuite(t)

		origInterval := option.Config.MonitorAggregationInterval
		origFlags := option.Config.MonitorAggregationFlags
		t.Cleanup(func() {
			option.Config.MonitorAggregationInterval = origInterval
			option.Config.MonitorAggregationFlags = origFlags
		})

		t.Run("medium aggregation with SYN flag", func(t *testing.T) {
			// bpf.monitorAggregation=medium, bpf.monitorInterval=60s,
			// bpf.monitorFlags=syn (TCP SYN = 0x02)
			option.Config.MonitorAggregationInterval = 60 * time.Second
			option.Config.MonitorAggregationFlags = 0x02 // SYN flag

			output := writeNodeConfigToBuffer(t, &dummyNodeCfg)
			require.Contains(t, output, "define CT_REPORT_INTERVAL 60\n",
				"Expected 60s monitor aggregation interval")
			require.Contains(t, output, "define CT_REPORT_FLAGS 0x0002\n",
				"Expected SYN flag (0x0002) in monitor aggregation flags")
		})

		t.Run("medium aggregation with PSH flag", func(t *testing.T) {
			// bpf.monitorAggregation=medium, bpf.monitorInterval=60s,
			// bpf.monitorFlags=psh (TCP PSH = 0x08)
			option.Config.MonitorAggregationInterval = 60 * time.Second
			option.Config.MonitorAggregationFlags = 0x08 // PSH flag

			output := writeNodeConfigToBuffer(t, &dummyNodeCfg)
			require.Contains(t, output, "define CT_REPORT_INTERVAL 60\n",
				"Expected 60s monitor aggregation interval")
			require.Contains(t, output, "define CT_REPORT_FLAGS 0x0008\n",
				"Expected PSH flag (0x0008) in monitor aggregation flags")
		})

		t.Run("no aggregation", func(t *testing.T) {
			// monitorAggregation=none => interval=0, flags=0
			option.Config.MonitorAggregationInterval = 0
			option.Config.MonitorAggregationFlags = 0

			output := writeNodeConfigToBuffer(t, &dummyNodeCfg)
			require.Contains(t, output, "define CT_REPORT_INTERVAL 0\n",
				"Expected 0 interval with no aggregation")
			require.Contains(t, output, "define CT_REPORT_FLAGS 0x0000\n",
				"Expected 0x0000 flags with no aggregation")
		})

		return nil
	})
	require.NoError(t, err)
}

// TestPrivilegedWriteNodeConfigHostFirewall verifies that with host firewall
// enabled, the ENABLE_HOST_FIREWALL BPF define is present, and without it,
// it is absent.
// This covers the Host firewall scenarios previously tested by
// K8sDatapathConfig.
func TestPrivilegedWriteNodeConfigHostFirewall(t *testing.T) {
	testutils.PrivilegedTest(t)
	ns := netns.NewNetNS(t)
	setupCiliumDummyDevices(t, ns)
	err := ns.Do(func() error {
		setupConfigSuite(t)

		origHostFirewall := option.Config.EnableHostFirewall
		t.Cleanup(func() {
			option.Config.EnableHostFirewall = origHostFirewall
		})

		t.Run("host firewall enabled", func(t *testing.T) {
			option.Config.EnableHostFirewall = true
			output := writeNodeConfigToBuffer(t, &dummyNodeCfg)
			require.Contains(t, output, "define ENABLE_HOST_FIREWALL 1\n",
				"Expected ENABLE_HOST_FIREWALL define when host firewall is enabled")
		})

		t.Run("host firewall disabled", func(t *testing.T) {
			option.Config.EnableHostFirewall = false
			output := writeNodeConfigToBuffer(t, &dummyNodeCfg)
			require.NotContains(t, output, "ENABLE_HOST_FIREWALL",
				"Expected no ENABLE_HOST_FIREWALL define when host firewall is disabled")
		})

		return nil
	})
	require.NoError(t, err)
}

// TestPrivilegedWriteNodeConfigIPv4Only verifies that when IPv4 is enabled
// and IPv6 is disabled, only ENABLE_IPV4 is present (not ENABLE_IPV6).
// This covers the IPv4Only scenario previously tested by K8sDatapathConfig.
func TestPrivilegedWriteNodeConfigIPv4Only(t *testing.T) {
	testutils.PrivilegedTest(t)
	ns := netns.NewNetNS(t)
	setupCiliumDummyDevices(t, ns)
	err := ns.Do(func() error {
		setupConfigSuite(t)

		origIPv4 := option.Config.EnableIPv4
		origIPv6 := option.Config.EnableIPv6
		t.Cleanup(func() {
			option.Config.EnableIPv4 = origIPv4
			option.Config.EnableIPv6 = origIPv6
		})

		t.Run("IPv4 only", func(t *testing.T) {
			option.Config.EnableIPv4 = true
			option.Config.EnableIPv6 = false
			output := writeNodeConfigToBuffer(t, &dummyNodeCfg)
			require.Contains(t, output, "define ENABLE_IPV4 1\n",
				"Expected ENABLE_IPV4 define when IPv4 is enabled")
			require.NotContains(t, output, "define ENABLE_IPV6",
				"Expected no ENABLE_IPV6 define when IPv6 is disabled")
		})

		t.Run("dual stack", func(t *testing.T) {
			option.Config.EnableIPv4 = true
			option.Config.EnableIPv6 = true
			output := writeNodeConfigToBuffer(t, &dummyNodeCfg)
			require.Contains(t, output, "define ENABLE_IPV4 1\n",
				"Expected ENABLE_IPV4 define for dual stack")
			require.Contains(t, output, "define ENABLE_IPV6 1\n",
				"Expected ENABLE_IPV6 define for dual stack")
		})

		return nil
	})
	require.NoError(t, err)
}

// TestPrivilegedWriteNodeConfigBPFMasquerade verifies that when BPF masquerade
// is enabled, the correct ENABLE_MASQUERADE_IPV4, ENABLE_IP_MASQ_AGENT_IPV4,
// and SNAT exclusion CIDR defines are generated.
// This covers the BPF masquerading with ip-masq-agent scenarios previously
// tested by K8sDatapathConfig.
func TestPrivilegedWriteNodeConfigBPFMasquerade(t *testing.T) {
	testutils.PrivilegedTest(t)
	ns := netns.NewNetNS(t)
	setupCiliumDummyDevices(t, ns)
	err := ns.Do(func() error {
		setupConfigSuite(t)

		origBPFMasq := option.Config.EnableBPFMasquerade
		origIPv4Masq := option.Config.EnableIPv4Masquerade
		origIPv6Masq := option.Config.EnableIPv6Masquerade
		origIPMasqAgent := option.Config.EnableIPMasqAgent
		origNativeRoutingCIDR := option.Config.IPv4NativeRoutingCIDR
		t.Cleanup(func() {
			option.Config.EnableBPFMasquerade = origBPFMasq
			option.Config.EnableIPv4Masquerade = origIPv4Masq
			option.Config.EnableIPv6Masquerade = origIPv6Masq
			option.Config.EnableIPMasqAgent = origIPMasqAgent
			option.Config.IPv4NativeRoutingCIDR = origNativeRoutingCIDR
		})

		t.Run("BPF masquerade with ip-masq-agent", func(t *testing.T) {
			option.Config.EnableBPFMasquerade = true
			option.Config.EnableIPv4Masquerade = true
			option.Config.EnableIPv6Masquerade = false
			option.Config.EnableIPMasqAgent = true
			option.Config.IPv4NativeRoutingCIDR = cidr.MustParseCIDR("10.0.0.0/8")

			output := writeNodeConfigToBuffer(t, &dummyNodeCfg)
			require.Contains(t, output, "define ENABLE_MASQUERADE_IPV4 1\n",
				"Expected ENABLE_MASQUERADE_IPV4 define with BPF masquerade")
			require.Contains(t, output, "define ENABLE_IP_MASQ_AGENT_IPV4 1\n",
				"Expected ENABLE_IP_MASQ_AGENT_IPV4 define with ip-masq-agent enabled")
			require.Contains(t, output, "define ENABLE_NODEPORT 1\n",
				"Expected ENABLE_NODEPORT define with BPF masquerade")
		})

		t.Run("BPF masquerade without ip-masq-agent", func(t *testing.T) {
			option.Config.EnableBPFMasquerade = true
			option.Config.EnableIPv4Masquerade = true
			option.Config.EnableIPv6Masquerade = false
			option.Config.EnableIPMasqAgent = false

			nodeCfg := dummyNodeCfg
			nodeCfg.NativeRoutingCIDRIPv4 = cidr.MustParseCIDR("10.0.0.0/8")

			output := writeNodeConfigToBuffer(t, &nodeCfg)
			require.Contains(t, output, "define ENABLE_MASQUERADE_IPV4 1\n",
				"Expected ENABLE_MASQUERADE_IPV4 define with BPF masquerade")
			require.NotContains(t, output, "ENABLE_IP_MASQ_AGENT",
				"Expected no ENABLE_IP_MASQ_AGENT define without ip-masq-agent")
		})

		t.Run("BPF masquerade disabled", func(t *testing.T) {
			option.Config.EnableBPFMasquerade = false
			option.Config.EnableIPv4Masquerade = true
			option.Config.EnableIPMasqAgent = false

			output := writeNodeConfigToBuffer(t, &dummyNodeCfg)
			require.NotContains(t, output, "ENABLE_MASQUERADE_IPV4",
				"Expected no ENABLE_MASQUERADE_IPV4 define without BPF masquerade")
		})

		return nil
	})
	require.NoError(t, err)
}
