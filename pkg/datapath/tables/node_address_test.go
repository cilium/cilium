// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package tables

import (
	"context"
	"math/rand"
	"net"
	"net/netip"
	"slices"
	"sort"
	"strings"
	"testing"

	"github.com/spf13/pflag"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"

	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/cilium/cilium/pkg/hive/job"
	"github.com/cilium/cilium/pkg/ip"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/statedb"
)

func TestNodeAddressConfig(t *testing.T) {
	var cfg NodeAddressConfig
	newHive := func() *hive.Hive {
		return hive.New(
			cell.Config(NodeAddressConfig{}),
			cell.Invoke(func(c NodeAddressConfig) { cfg = c }),
		)
	}
	testCases := [][]string{
		nil,                         // Empty
		{"1.2.3.0/24"},              // IPv4
		{"1.2.0.0/16", "fe80::/64"}, // IPv4 & IPv6
	}

	for _, testCase := range testCases {
		flags := pflag.NewFlagSet("", pflag.ContinueOnError)
		h := newHive()
		h.RegisterFlags(flags)
		flags.Set("nodeport-addresses", strings.Join(testCase, ","))
		if assert.NoError(t, h.Start(context.TODO()), "Start") {
			assert.NoError(t, h.Stop(context.TODO()), "Stop")
			require.Len(t, cfg.NodePortAddresses, len(testCase))
			for i := range testCase {
				assert.Equal(t, testCase[i], cfg.NodePortAddresses[i].String())
			}
		}
	}
}

var ciliumHostIP = net.ParseIP("9.9.9.9")
var ciliumHostIPLinkScoped = net.ParseIP("9.9.9.8")

var nodeAddressTests = []struct {
	name         string
	addrs        []DeviceAddress // Addresses to add to the "test" device
	wantAddrs    []net.IP
	wantPrimary  []net.IP
	wantNodePort []net.IP
}{
	{
		name: "ipv4 simple",
		addrs: []DeviceAddress{
			{
				Addr:  netip.MustParseAddr("10.0.0.1"),
				Scope: unix.RT_SCOPE_SITE,
			},
		},
		wantAddrs: []net.IP{
			ciliumHostIP,
			ciliumHostIPLinkScoped,
			net.ParseIP("10.0.0.1"),
		},
		wantPrimary: []net.IP{
			ciliumHostIP,
			net.ParseIP("10.0.0.1"),
		},
		wantNodePort: []net.IP{
			net.ParseIP("10.0.0.1"),
		},
	},
	{
		name: "ipv6 simple",
		addrs: []DeviceAddress{
			{
				Addr:  netip.MustParseAddr("2001:db8::1"),
				Scope: unix.RT_SCOPE_SITE,
			},
		},
		wantAddrs: []net.IP{
			ciliumHostIP,
			ciliumHostIPLinkScoped,
			net.ParseIP("2001:db8::1"),
		},
		wantPrimary: []net.IP{
			ciliumHostIP,
			net.ParseIP("2001:db8::1"),
		},
		wantNodePort: []net.IP{
			net.ParseIP("2001:db8::1"),
		},
	},
	{
		name: "v4/v6 mix",
		addrs: []DeviceAddress{
			{
				Addr:  netip.MustParseAddr("10.0.0.1"),
				Scope: unix.RT_SCOPE_SITE,
			},
			{
				Addr:  netip.MustParseAddr("2001:db8::1"),
				Scope: unix.RT_SCOPE_UNIVERSE,
			},
		},

		wantAddrs: []net.IP{
			ciliumHostIP,
			ciliumHostIPLinkScoped,
			net.ParseIP("2001:db8::1"),
			net.ParseIP("10.0.0.1"),
		},
		wantPrimary: []net.IP{
			ciliumHostIP,
			net.ParseIP("2001:db8::1"),
			net.ParseIP("10.0.0.1"),
		},
		wantNodePort: []net.IP{
			net.ParseIP("10.0.0.1"),
			net.ParseIP("2001:db8::1"),
		},
	},
	{

		name: "skip-out-of-scope-addrs",
		addrs: []DeviceAddress{
			{
				Addr:  netip.MustParseAddr("10.0.1.1"),
				Scope: unix.RT_SCOPE_UNIVERSE,
			},
			{
				Addr:  netip.MustParseAddr("10.0.2.2"),
				Scope: unix.RT_SCOPE_LINK,
			},
			{
				Addr:      netip.MustParseAddr("10.0.3.3"),
				Secondary: true,
				Scope:     unix.RT_SCOPE_HOST,
			},
		},

		// The default AddressMaxScope is set to LINK-1, so addresses with
		// scope LINK or above are ignored (except for cilium_host addresses)
		wantAddrs: []net.IP{
			ciliumHostIP,
			ciliumHostIPLinkScoped,
			net.ParseIP("10.0.1.1"),
		},

		wantPrimary: []net.IP{
			ciliumHostIP,
			net.ParseIP("10.0.1.1"),
		},

		wantNodePort: []net.IP{
			net.ParseIP("10.0.1.1"),
		},
	},

	{
		name: "multiple",
		addrs: []DeviceAddress{
			{
				Addr:  netip.MustParseAddr("10.0.0.1"),
				Scope: unix.RT_SCOPE_UNIVERSE,
			},
			{
				Addr:      netip.MustParseAddr("10.0.0.2"),
				Scope:     unix.RT_SCOPE_UNIVERSE,
				Secondary: true,
			},
			{
				Addr:  netip.MustParseAddr("1.1.1.1"),
				Scope: unix.RT_SCOPE_UNIVERSE,
			},
		},

		wantAddrs: []net.IP{
			ciliumHostIP,
			ciliumHostIPLinkScoped,
			net.ParseIP("10.0.0.1"),
			net.ParseIP("10.0.0.2"),
			net.ParseIP("1.1.1.1"),
		},

		wantPrimary: []net.IP{
			ciliumHostIP,
			net.ParseIP("1.1.1.1"),
		},

		wantNodePort: []net.IP{
			net.ParseIP("10.0.0.1"),
		},
	},
	{
		name: "ipv6 multiple",
		addrs: []DeviceAddress{
			{ // Second public address
				Addr:  netip.MustParseAddr("2600:beef::2"),
				Scope: unix.RT_SCOPE_SITE,
			},
			{ // First public address
				Addr:  netip.MustParseAddr("2600:beef::3"),
				Scope: unix.RT_SCOPE_UNIVERSE,
			},

			{ // First private address (preferred for NodePort)
				Addr:  netip.MustParseAddr("2001:db8::1"),
				Scope: unix.RT_SCOPE_UNIVERSE,
			},
		},

		wantAddrs: []net.IP{
			ciliumHostIP,
			ciliumHostIPLinkScoped,
			net.ParseIP("2001:db8::1"),
			net.ParseIP("2600:beef::2"),
			net.ParseIP("2600:beef::3"),
		},

		wantPrimary: []net.IP{
			ciliumHostIP,
			net.ParseIP("2600:beef::3"),
		},

		wantNodePort: []net.IP{
			net.ParseIP("2001:db8::1"),
		},
	},
}

func TestNodeAddress(t *testing.T) {
	t.Parallel()

	// Use a shared fixture so that we're dealing with an evolving set of addresses
	// for the device.
	db, devices, nodeAddrs := fixture(t, defaults.AddressScopeMax, nil)

	_, watch := nodeAddrs.All(db.ReadTxn())
	txn := db.WriteTxn(devices)
	devices.Insert(txn, &Device{
		Index: 2,
		Name:  "cilium_host",
		Flags: net.FlagUp,
		Addrs: []DeviceAddress{
			{Addr: ip.MustAddrFromIP(ciliumHostIP), Scope: unix.RT_SCOPE_UNIVERSE},
			{Addr: ip.MustAddrFromIP(ciliumHostIPLinkScoped), Scope: unix.RT_SCOPE_LINK},
		},
		Selected: false,
	})
	devices.Insert(txn, &Device{
		Index: 1,
		Name:  "lo",
		Flags: net.FlagUp | net.FlagLoopback,
		Addrs: []DeviceAddress{
			{Addr: netip.MustParseAddr("127.0.0.1"), Scope: unix.RT_SCOPE_HOST},
			{Addr: netip.MustParseAddr("::1"), Scope: unix.RT_SCOPE_HOST},
		},
		Selected: false,
	})
	txn.Commit()

	// Wait for cilium_host addresses to be processed.
	<-watch
	iter, _ := nodeAddrs.All(db.ReadTxn())
	addrs := statedb.Collect(statedb.Map(iter, func(n NodeAddress) string { return n.String() }))
	assert.Equal(t, addrs,
		[]string{"::1 (*)", "9.9.9.8 (cilium_host)", "9.9.9.9 (cilium_host)", "127.0.0.1 (*)"},
		"unexpected initial node addresses")

	for _, tt := range nodeAddressTests {
		t.Run(tt.name, func(t *testing.T) {

			txn := db.WriteTxn(devices)
			_, watch := nodeAddrs.All(txn)

			shuffleSlice(tt.addrs) // For extra bit of randomness
			devices.Insert(txn,
				&Device{
					Index:    3,
					Name:     "test",
					Selected: true,
					Flags:    net.FlagUp,
					Addrs:    tt.addrs,
				})

			txn.Commit()
			<-watch // wait for propagation

			iter, _ := nodeAddrs.All(db.ReadTxn())
			addrs := statedb.Collect(iter)
			local := []string{}
			nodePort := []string{}
			primary := []string{}
			for _, addr := range addrs {
				if addr.DeviceName == WildcardDeviceName {
					continue
				}
				local = append(local, addr.Addr.String())
				if addr.NodePort {
					nodePort = append(nodePort, addr.Addr.String())
				}
				if addr.Primary {
					primary = append(primary, addr.Addr.String())
				}
			}
			assert.ElementsMatch(t, local, ipStrings(tt.wantAddrs), "Addresses do not match")
			assert.ElementsMatch(t, nodePort, ipStrings(tt.wantNodePort), "NodePort addresses do not match")
			assert.ElementsMatch(t, primary, ipStrings(tt.wantPrimary), "Primary addresses do not match")
			assertOnePrimaryPerDevice(t, addrs)

		})
	}

	// Delete the devices and check that node addresses is cleaned up.
	_, watch = nodeAddrs.All(db.ReadTxn())
	txn = db.WriteTxn(devices)
	devices.Delete(txn, &Device{Index: 1})
	devices.Delete(txn, &Device{Index: 2})
	devices.Delete(txn, &Device{Index: 3})
	txn.Commit()
	<-watch // wait for propagation

	assert.Equal(t, nodeAddrs.NumObjects(db.ReadTxn()), 0, "expected no NodeAddresses after device deletion")

}

// TestNodeAddressHostDevice checks that the for cilium_host the link scope'd
// addresses are always picked regardless of the max scope.
// More context in commit 080857bdedca67d58ec39f8f96c5f38b22f6dc0b.
func TestNodeAddressHostDevice(t *testing.T) {
	t.Parallel()

	db, devices, nodeAddrs := fixture(t, unix.RT_SCOPE_SITE, nil)

	txn := db.WriteTxn(devices)
	_, watch := nodeAddrs.All(txn)

	devices.Insert(txn, &Device{
		Index: 1,
		Name:  "cilium_host",
		Flags: net.FlagUp,
		Addrs: []DeviceAddress{
			// <SITE
			{Addr: ip.MustAddrFromIP(ciliumHostIP), Scope: unix.RT_SCOPE_UNIVERSE},
			// >SITE, but included
			{Addr: ip.MustAddrFromIP(ciliumHostIPLinkScoped), Scope: unix.RT_SCOPE_LINK},
			// >SITE, skipped
			{Addr: netip.MustParseAddr("10.0.0.1"), Scope: unix.RT_SCOPE_HOST},
		},
		Selected: false,
	})

	txn.Commit()
	<-watch // wait for propagation

	iter, _ := nodeAddrs.All(db.ReadTxn())
	addrs := statedb.Collect(iter)

	if assert.Len(t, addrs, 2) {
		// The addresses are sorted by IP, so we see the link-scoped address first.
		assert.Equal(t, addrs[0].Addr.String(), ciliumHostIPLinkScoped.String())
		assert.False(t, addrs[0].Primary)

		assert.Equal(t, addrs[1].Addr.String(), ciliumHostIP.String())
		assert.True(t, addrs[1].Primary)
	}
}

var nodeAddressWhitelistTests = []struct {
	name         string
	cidrs        string          // --nodeport-addresses
	addrs        []DeviceAddress // Addresses to add to the "test" device
	wantLocal    []net.IP        // e.g. LocalAddresses()
	wantNodePort []net.IP        // e.g. LoadBalancerNodeAddresses()
	wantFallback []net.IP        // Fallback addresses, e.g. addresses of "*" device
}{
	{
		name:  "ipv4",
		cidrs: "10.0.0.0/8",
		addrs: []DeviceAddress{
			{
				Addr:  netip.MustParseAddr("10.0.0.1"),
				Scope: unix.RT_SCOPE_SITE,
			},
			{
				Addr:  netip.MustParseAddr("11.0.0.1"),
				Scope: unix.RT_SCOPE_SITE,
			},
		},
		wantLocal: []net.IP{
			ciliumHostIP,
			ciliumHostIPLinkScoped,
			net.ParseIP("10.0.0.1"),
			net.ParseIP("11.0.0.1"),
		},
		wantNodePort: []net.IP{
			net.ParseIP("10.0.0.1"),
		},
		wantFallback: []net.IP{
			net.ParseIP("11.0.0.1"), // public over private
		},
	},
	{
		name:  "ipv6",
		cidrs: "2001::/16",
		addrs: []DeviceAddress{
			{
				Addr:  netip.MustParseAddr("2001:db8::1"),
				Scope: unix.RT_SCOPE_SITE,
			},
			{
				Addr:  netip.MustParseAddr("2600:beef::2"),
				Scope: unix.RT_SCOPE_SITE,
			},
		},
		wantLocal: []net.IP{
			ciliumHostIP,
			ciliumHostIPLinkScoped,
			net.ParseIP("2001:db8::1"),
			net.ParseIP("2600:beef::2"),
		},
		wantNodePort: []net.IP{
			net.ParseIP("2001:db8::1"),
		},
		wantFallback: []net.IP{
			net.ParseIP("2600:beef::2"),
		},
	},
	{
		name:  "v4-v6 mix",
		cidrs: "2001::/16,10.0.0.0/8",
		addrs: []DeviceAddress{
			{
				Addr:  netip.MustParseAddr("10.0.0.1"),
				Scope: unix.RT_SCOPE_SITE,
			},
			{
				Addr:  netip.MustParseAddr("11.0.0.1"),
				Scope: unix.RT_SCOPE_UNIVERSE,
			},
			{
				Addr:  netip.MustParseAddr("2001:db8::1"),
				Scope: unix.RT_SCOPE_UNIVERSE,
			},
			{
				Addr:  netip.MustParseAddr("2600:beef::2"),
				Scope: unix.RT_SCOPE_SITE,
			},
		},

		wantLocal: []net.IP{
			ciliumHostIP,
			ciliumHostIPLinkScoped,
			net.ParseIP("10.0.0.1"),
			net.ParseIP("11.0.0.1"),
			net.ParseIP("2001:db8::1"),
			net.ParseIP("2600:beef::2"),
		},
		wantNodePort: []net.IP{
			net.ParseIP("10.0.0.1"),
			net.ParseIP("2001:db8::1"),
		},
		wantFallback: []net.IP{
			net.ParseIP("11.0.0.1"), // public over private
			net.ParseIP("2600:beef::2"),
		},
	},
}

func TestNodeAddressWhitelist(t *testing.T) {
	t.Parallel()

	for _, tt := range nodeAddressWhitelistTests {
		t.Run(tt.name, func(t *testing.T) {
			db, devices, nodeAddrs := fixture(t, defaults.AddressScopeMax,
				func(h *hive.Hive) {
					h.Viper().Set("nodeport-addresses", tt.cidrs)
				})

			txn := db.WriteTxn(devices)
			_, watch := nodeAddrs.All(txn)

			devices.Insert(txn, &Device{
				Index: 1,
				Name:  "cilium_host",
				Flags: net.FlagUp,
				Addrs: []DeviceAddress{
					{Addr: ip.MustAddrFromIP(ciliumHostIP), Scope: unix.RT_SCOPE_UNIVERSE},
					{Addr: ip.MustAddrFromIP(ciliumHostIPLinkScoped), Scope: unix.RT_SCOPE_LINK},
				},
				Selected: false,
			})

			shuffleSlice(tt.addrs) // For extra bit of randomness
			devices.Insert(txn,
				&Device{
					Index:    2,
					Name:     "test",
					Selected: true,
					Flags:    net.FlagUp,
					Addrs:    tt.addrs,
				})

			txn.Commit()
			<-watch // wait for propagation

			iter, _ := nodeAddrs.All(db.ReadTxn())
			local := []string{}
			nodePort := []string{}
			fallback := []string{}
			for addr, _, ok := iter.Next(); ok; addr, _, ok = iter.Next() {
				if addr.DeviceName == WildcardDeviceName {
					fallback = append(fallback, addr.Addr.String())
					continue
				}
				local = append(local, addr.Addr.String())
				if addr.NodePort {
					nodePort = append(nodePort, addr.Addr.String())
				}
			}
			assert.ElementsMatch(t, local, ipStrings(tt.wantLocal), "LocalAddresses do not match")
			assert.ElementsMatch(t, nodePort, ipStrings(tt.wantNodePort), "LoadBalancerNodeAddresses do not match")
			assert.ElementsMatch(t, fallback, ipStrings(tt.wantFallback), "fallback addresses do not match")
		})
	}

}

func fixture(t *testing.T, addressScopeMax int, beforeStart func(*hive.Hive)) (*statedb.DB, statedb.RWTable[*Device], statedb.Table[NodeAddress]) {
	var (
		db        *statedb.DB
		devices   statedb.RWTable[*Device]
		nodeAddrs statedb.Table[NodeAddress]
	)
	h := hive.New(
		job.Cell,
		statedb.Cell,
		NodeAddressCell,
		cell.Provide(
			NewDeviceTable,
			statedb.RWTable[*Device].ToTable,
		),
		cell.Invoke(func(db_ *statedb.DB, d statedb.RWTable[*Device], na statedb.Table[NodeAddress]) {
			db = db_
			devices = d
			nodeAddrs = na
			db.RegisterTable(d)
		}),

		// option.DaemonConfig needed for AddressMaxScope. This flag will move into NodeAddressConfig
		// in a follow-up PR.
		cell.Provide(func() *option.DaemonConfig {
			return &option.DaemonConfig{
				AddressScopeMax: addressScopeMax,
			}
		}),
	)
	if beforeStart != nil {
		beforeStart(h)
	}
	require.NoError(t, h.Start(context.TODO()), "Start")
	t.Cleanup(func() {
		assert.NoError(t, h.Stop(context.TODO()), "Stop")
	})
	return db, devices, nodeAddrs
}

// ipStrings converts net.IP to a string. Used to assert equalence without having to deal
// with e.g. IPv4-mapped IPv6 presentation etc.
func ipStrings(ips []net.IP) (ss []string) {
	for i := range ips {
		ss = append(ss, ips[i].String())
	}
	sort.Strings(ss)
	return
}

func shuffleSlice[T any](xs []T) []T {
	rand.Shuffle(
		len(xs),
		func(i, j int) {
			xs[i], xs[j] = xs[j], xs[i]
		})
	return xs
}

func assertOnePrimaryPerDevice(t *testing.T, addrs []NodeAddress) {
	ipv4 := map[string]netip.Addr{}
	ipv6 := map[string]netip.Addr{}
	hasPrimary := map[string]bool{}

	for _, addr := range addrs {
		hasPrimary[addr.DeviceName] = hasPrimary[addr.DeviceName] || addr.Primary
		if !addr.Primary {
			continue
		}
		if addr.Addr.Is4() {
			if other, ok := ipv4[addr.DeviceName]; ok && other != addr.Addr {
				assert.Failf(t, "multiple primary IPv4 addresses", "device %q had multiple primary IPv4 addresses: %q and %q", addr.DeviceName, addr.Addr, other)
			}
			ipv4[addr.DeviceName] = addr.Addr
		} else {
			if other, ok := ipv6[addr.DeviceName]; ok && other != addr.Addr {
				assert.Failf(t, "multiple primary IPv6 addresses", "device %q had multiple primary IPv6 addresses: %q and %q", addr.DeviceName, addr.Addr, other)
			}
			ipv6[addr.DeviceName] = addr.Addr
		}
	}

	for dev, primary := range hasPrimary {
		if !primary {
			assert.Failf(t, "no primary address", "device %q had no primary addresses", dev)
		}
	}
}

func TestSortedAddresses(t *testing.T) {
	// Test cases to consider. These are in the order we expect. The test shuffles
	// them and verifies  that expected order is recovered.
	testCases := [][]DeviceAddress{
		// Primary vs Secondary
		{
			{Addr: netip.MustParseAddr("2.2.2.2"), Scope: unix.RT_SCOPE_SITE},
			{Addr: netip.MustParseAddr("1.1.1.1"), Scope: unix.RT_SCOPE_UNIVERSE, Secondary: true},
		},
		{
			{Addr: netip.MustParseAddr("1002::1"), Scope: unix.RT_SCOPE_SITE},
			{Addr: netip.MustParseAddr("1001::1"), Scope: unix.RT_SCOPE_UNIVERSE, Secondary: true},
		},

		// Scope
		{
			{Addr: netip.MustParseAddr("2.2.2.2"), Scope: unix.RT_SCOPE_UNIVERSE},
			{Addr: netip.MustParseAddr("1.1.1.1"), Scope: unix.RT_SCOPE_SITE},
		},
		{
			{Addr: netip.MustParseAddr("1002::1"), Scope: unix.RT_SCOPE_UNIVERSE},
			{Addr: netip.MustParseAddr("1001::1"), Scope: unix.RT_SCOPE_SITE},
		},

		// Public vs private
		{
			{Addr: netip.MustParseAddr("200.0.0.1"), Scope: unix.RT_SCOPE_UNIVERSE},
			{Addr: netip.MustParseAddr("192.168.1.1"), Scope: unix.RT_SCOPE_UNIVERSE},
		},
		{
			{Addr: netip.MustParseAddr("1001::1"), Scope: unix.RT_SCOPE_UNIVERSE},
			{Addr: netip.MustParseAddr("100::1"), Scope: unix.RT_SCOPE_UNIVERSE},
		},

		// Address itself
		{
			{Addr: netip.MustParseAddr("1.1.1.1"), Scope: unix.RT_SCOPE_UNIVERSE},
			{Addr: netip.MustParseAddr("2.2.2.2"), Scope: unix.RT_SCOPE_UNIVERSE},
		},
		{
			{Addr: netip.MustParseAddr("1001::1"), Scope: unix.RT_SCOPE_UNIVERSE},
			{Addr: netip.MustParseAddr("1002::1"), Scope: unix.RT_SCOPE_UNIVERSE},
		},
	}

	for _, expected := range testCases {
		actual := SortedAddresses(shuffleSlice(slices.Clone(expected)))
		assert.EqualValues(t, expected, actual)

		// Shuffle again.
		actual = SortedAddresses(shuffleSlice(slices.Clone(expected)))
		assert.Equal(t, expected, actual)
	}

}

func TestFallbackAddresses(t *testing.T) {
	var f fallbackAddresses

	f.update(&Device{
		Index: 2,
		Addrs: []DeviceAddress{
			{Addr: netip.MustParseAddr("10.0.0.1"), Scope: unix.RT_SCOPE_SITE},
		},
	})
	assert.Equal(t, f.ipv4.addr.Addr.String(), "10.0.0.1")
	f.update(&Device{
		Index: 3,
		Addrs: []DeviceAddress{
			{Addr: netip.MustParseAddr("1001::1"), Scope: unix.RT_SCOPE_SITE},
		},
	})
	assert.Equal(t, f.ipv6.addr.Addr.String(), "1001::1")

	// Lower scope wins
	f.update(&Device{
		Index: 4,
		Addrs: []DeviceAddress{
			{Addr: netip.MustParseAddr("10.0.0.2"), Scope: unix.RT_SCOPE_UNIVERSE},
		},
	})
	assert.Equal(t, f.ipv4.addr.Addr.String(), "10.0.0.2")

	// Lower ifindex wins
	f.update(&Device{
		Index: 1,
		Addrs: []DeviceAddress{
			{Addr: netip.MustParseAddr("10.0.0.3"), Scope: unix.RT_SCOPE_UNIVERSE},
		},
	})
	assert.Equal(t, f.ipv4.addr.Addr.String(), "10.0.0.3")

	// Public wins over private
	f.update(&Device{
		Index: 5,
		Addrs: []DeviceAddress{
			{Addr: netip.MustParseAddr("20.0.0.1"), Scope: unix.RT_SCOPE_SITE},
		},
	})
	assert.Equal(t, f.ipv4.addr.Addr.String(), "20.0.0.1")
}
