// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package orchestrator

import (
	"context"
	"net/netip"
	"testing"

	"github.com/cilium/statedb"
	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/goleak"

	fakeconnector "github.com/cilium/cilium/pkg/datapath/connector/fake"
	fakeipsec "github.com/cilium/cilium/pkg/datapath/linux/ipsec/fake"
	"github.com/cilium/cilium/pkg/datapath/linux/sysctl"
	"github.com/cilium/cilium/pkg/datapath/tables"
	"github.com/cilium/cilium/pkg/datapath/tunnel"
	"github.com/cilium/cilium/pkg/datapath/xdp"
	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/kpr"
	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/maglev"
	"github.com/cilium/cilium/pkg/mtu"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/svcrouteconfig"
	"github.com/cilium/cilium/pkg/testutils"
	wgfake "github.com/cilium/cilium/pkg/wireguard/fake"
)

func TestDirectRoutingDeviceHasAddr(t *testing.T) {
	// Save and restore global config.
	savedIPv4 := option.Config.EnableIPv4
	savedIPv6 := option.Config.EnableIPv6
	t.Cleanup(func() {
		option.Config.EnableIPv4 = savedIPv4
		option.Config.EnableIPv6 = savedIPv6
	})
	option.Config.EnableIPv4 = true
	option.Config.EnableIPv6 = true

	tests := []struct {
		name  string
		addrs []tables.DeviceAddress
		want  bool
	}{
		{
			name: "both addresses",
			addrs: []tables.DeviceAddress{
				{Addr: netip.MustParseAddr("192.0.2.1")},
				{Addr: netip.MustParseAddr("2001:db8::1")},
			},
			want: true,
		},
		{
			name: "only IPv4",
			addrs: []tables.DeviceAddress{
				{Addr: netip.MustParseAddr("192.0.2.1")},
			},
			want: true,
		},
		{
			name: "only IPv6",
			addrs: []tables.DeviceAddress{
				{Addr: netip.MustParseAddr("2001:db8::1")},
			},
			want: true,
		},
		{
			name:  "no addresses",
			addrs: nil,
			want:  false,
		},
		{
			name: "only unspecified IPv4",
			addrs: []tables.DeviceAddress{
				{Addr: netip.MustParseAddr("0.0.0.0")},
			},
			want: false,
		},
		{
			name: "only unspecified IPv6",
			addrs: []tables.DeviceAddress{
				{Addr: netip.MustParseAddr("::")},
			},
			want: false,
		},
		{
			name: "both unspecified",
			addrs: []tables.DeviceAddress{
				{Addr: netip.MustParseAddr("0.0.0.0")},
				{Addr: netip.MustParseAddr("::")},
			},
			want: false,
		},
		{
			name: "valid IPv4 and unspecified IPv6",
			addrs: []tables.DeviceAddress{
				{Addr: netip.MustParseAddr("192.0.2.1")},
				{Addr: netip.MustParseAddr("::")},
			},
			want: true,
		},
		{
			name: "unspecified IPv4 and valid IPv6",
			addrs: []tables.DeviceAddress{
				{Addr: netip.MustParseAddr("0.0.0.0")},
				{Addr: netip.MustParseAddr("2001:db8::1")},
			},
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dev := &tables.Device{Name: "eth0", Index: 2, Addrs: tt.addrs}
			assert.Equal(t, tt.want, directRoutingDeviceHasAddr(dev))
		})
	}
}

// TestNewLocalNodeConfigNoGoroutineLeak is a regression test for
// https://github.com/cilium/cilium/issues/46254: the watch channel returned by
// newLocalNodeConfig is backed by a common.MergeChannels goroutine that must be
// reclaimed when the caller cancels the context, even if no input ever fires.
func TestNewLocalNodeConfigNoGoroutineLeak(t *testing.T) {
	// Save and restore the global config touched below.
	savedHostLegacy := option.Config.UnsafeDaemonConfigOption.EnableHostLegacyRouting
	savedV4Range := option.Config.IPv4ServiceRange
	savedV6Range := option.Config.IPv6ServiceRange
	t.Cleanup(func() {
		option.Config.UnsafeDaemonConfigOption.EnableHostLegacyRouting = savedHostLegacy
		option.Config.IPv4ServiceRange = savedV4Range
		option.Config.IPv6ServiceRange = savedV6Range
	})
	// KPR + BPF host routing + Wireguard disabled => DirectRoutingDeviceRequired
	// is false, so newLocalNodeConfig skips the direct routing device branch.
	option.Config.UnsafeDaemonConfigOption.EnableHostLegacyRouting = true
	option.Config.IPv4ServiceRange = AutoCIDR
	option.Config.IPv6ServiceRange = AutoCIDR

	db := statedb.New()
	devices, err := tables.NewDeviceTable(db)
	require.NoError(t, err)
	nodeAddrs, err := tables.NewNodeAddressTable(db)
	require.NoError(t, err)
	mtuTable, err := mtu.NewMTUTable(db)
	require.NoError(t, err)

	// Seed cilium_host and cilium_net so newLocalNodeConfig reaches the success
	// path that builds the merged watch channel.
	wtxn := db.WriteTxn(devices)
	for i, name := range []string{defaults.HostDevice, defaults.SecondHostDevice} {
		_, _, err = devices.Insert(wtxn, &tables.Device{
			Index:        i + 1,
			Name:         name,
			HardwareAddr: tables.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, byte(i + 1)},
		})
		require.NoError(t, err)
	}
	wtxn.Commit()

	// In-memory sysctl with the ephemeral port range getEphemeralPortRangeMin reads.
	memFS := afero.NewMemMapFs()
	require.NoError(t, memFS.MkdirAll("/proc/sys/net/ipv4", 0755))
	require.NoError(t, afero.WriteFile(memFS,
		"/proc/sys/net/ipv4/ip_local_port_range", []byte("32768\t60999"), 0644))
	sysctlReader := sysctl.NewDirectSysctl(memFS, "/proc")

	wgAgent := wgfake.NewTestAgent(wgfake.Config{EnableWireguard: false})

	call := func(ctx context.Context) error {
		_, _, err := newLocalNodeConfig(
			ctx,
			option.Config,
			node.LocalNode{Local: &node.LocalNodeInfo{}},
			sysctlReader,
			tunnel.Config{},
			db.ReadTxn(),
			tables.DirectRoutingDevice{},
			devices,
			nodeAddrs,
			"",
			xdp.Config{},
			loadbalancer.Config{},
			kpr.KPRConfig{},
			svcrouteconfig.RoutesConfig{},
			maglev.Config{},
			mtuTable,
			wgAgent,
			fakeipsec.Config{},
			fakeconnector.NewVeth(),
			nil,
		)
		return err
	}

	// Baseline goroutines after setup so statedb's etc. are not counted.
	defer testutils.GoleakVerifyNone(t, goleak.IgnoreCurrent())

	// Emulate the reconciler loop: create a watch, abandon it (as when the loop
	// wakes via another event source), then cancel the per-iteration context.
	// Without the fix the merge goroutines block forever in reflect.Select.
	for range 1000 {
		watchCtx, cancelWatch := context.WithCancel(context.Background())
		require.NoError(t, call(watchCtx))
		cancelWatch()
	}
}
