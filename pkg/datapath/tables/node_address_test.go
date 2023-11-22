// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package tables_test

import (
	"context"
	"math/rand"
	"net"
	"net/netip"
	"sort"
	"strings"
	"testing"

	"github.com/spf13/pflag"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"

	"github.com/cilium/cilium/pkg/datapath/tables"
	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/cilium/cilium/pkg/hive/job"
	"github.com/cilium/cilium/pkg/ip"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/statedb"
)

func TestNodeAddressConfig(t *testing.T) {
	var cfg tables.NodeAddressConfig
	newHive := func() *hive.Hive {
		return hive.New(
			cell.Config(tables.NodeAddressConfig{}),
			cell.Invoke(func(c tables.NodeAddressConfig) { cfg = c }),
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
	addrs        []tables.DeviceAddress // Addresses to add to the "test" device
	wantLocal    []net.IP               // e.g. LocalAddresses()
	wantNodePort []net.IP               // e.g. LoadBalancerNodeAddresses()
}{
	{
		name: "ipv4 simple",
		addrs: []tables.DeviceAddress{
			{
				Addr:  netip.MustParseAddr("10.0.0.1"),
				Scope: unix.RT_SCOPE_SITE,
			},
		},
		wantLocal: []net.IP{
			ciliumHostIP,
			ciliumHostIPLinkScoped,
			net.ParseIP("10.0.0.1"),
		},
		wantNodePort: []net.IP{
			net.ParseIP("10.0.0.1"),
		},
	},
	{
		name: "ipv6 simple",
		addrs: []tables.DeviceAddress{
			{
				Addr:  netip.MustParseAddr("2001:db8::1"),
				Scope: unix.RT_SCOPE_SITE,
			},
		},
		wantLocal: []net.IP{
			ciliumHostIP,
			ciliumHostIPLinkScoped,
			net.ParseIP("2001:db8::1"),
		},
		wantNodePort: []net.IP{
			net.ParseIP("2001:db8::1"),
		},
	},
	{
		name: "v4/v6 mix",
		addrs: []tables.DeviceAddress{
			{
				Addr:  netip.MustParseAddr("10.0.0.1"),
				Scope: unix.RT_SCOPE_SITE,
			},
			{
				Addr:  netip.MustParseAddr("2001:db8::1"),
				Scope: unix.RT_SCOPE_UNIVERSE,
			},
		},

		wantLocal: []net.IP{
			ciliumHostIP,
			ciliumHostIPLinkScoped,
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
		addrs: []tables.DeviceAddress{
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
		wantLocal: []net.IP{
			ciliumHostIP,
			ciliumHostIPLinkScoped,
			net.ParseIP("10.0.1.1"),
		},

		wantNodePort: []net.IP{
			net.ParseIP("10.0.1.1"),
		},
	},

	{
		name: "multiple",
		addrs: []tables.DeviceAddress{
			{
				Addr:  netip.MustParseAddr("10.0.0.1"),
				Scope: unix.RT_SCOPE_UNIVERSE,
			},
			{
				Addr:      netip.MustParseAddr("10.0.0.2"),
				Scope:     unix.RT_SCOPE_UNIVERSE,
				Secondary: true,
			},
		},

		wantLocal: []net.IP{
			ciliumHostIP,
			ciliumHostIPLinkScoped,
			net.ParseIP("10.0.0.1"),
			net.ParseIP("10.0.0.2"),
		},

		wantNodePort: []net.IP{
			net.ParseIP("10.0.0.1"),
		},
	},
	{
		name: "ipv6 multiple",
		addrs: []tables.DeviceAddress{
			{
				Addr:  netip.MustParseAddr("2600:beef::2"),
				Scope: unix.RT_SCOPE_SITE,
			},
			{
				Addr:  netip.MustParseAddr("2001:db8::1"),
				Scope: unix.RT_SCOPE_UNIVERSE,
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
	},
}

func TestNodeAddress(t *testing.T) {
	t.Parallel()

	for _, tt := range nodeAddressTests {
		t.Run(tt.name, func(t *testing.T) {
			var (
				db        *statedb.DB
				devices   statedb.RWTable[*tables.Device]
				nodeAddrs statedb.Table[tables.NodeAddress]
			)
			h := hive.New(
				job.Cell,
				statedb.Cell,
				tables.NodeAddressCell,
				cell.Provide(
					tables.NewDeviceTable,
					statedb.RWTable[*tables.Device].ToTable,
				),
				cell.Invoke(func(db_ *statedb.DB, d statedb.RWTable[*tables.Device], na statedb.Table[tables.NodeAddress]) {
					db = db_
					devices = d
					nodeAddrs = na
					db.RegisterTable(d)
				}),

				// option.DaemonConfig needed for AddressMaxScope. This flag will move into NodeAddressConfig
				// in a follow-up PR.
				cell.Provide(func() *option.DaemonConfig {
					return &option.DaemonConfig{
						AddressScopeMax: defaults.AddressScopeMax,
					}
				}),
			)

			if !assert.NoError(t, h.Start(context.TODO()), "Start") {
				return
			}

			txn := db.WriteTxn(devices)
			_, watch := nodeAddrs.All(txn)

			devices.Insert(txn, &tables.Device{
				Index: 1,
				Name:  "cilium_host",
				Flags: net.FlagUp,
				Addrs: []tables.DeviceAddress{
					{Addr: ip.MustAddrFromIP(ciliumHostIP), Scope: unix.RT_SCOPE_UNIVERSE},
					{Addr: ip.MustAddrFromIP(ciliumHostIPLinkScoped), Scope: unix.RT_SCOPE_LINK},
				},
				Selected: false,
			})

			shuffleSlice(tt.addrs) // For extra bit of randomness
			devices.Insert(txn,
				&tables.Device{
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
			for addr, _, ok := iter.Next(); ok; addr, _, ok = iter.Next() {
				local = append(local, addr.Addr.String())
				if addr.NodePort {
					nodePort = append(nodePort, addr.Addr.String())
				}
			}
			assert.ElementsMatch(t, local, ipStrings(tt.wantLocal), "LocalAddresses do not match")
			assert.ElementsMatch(t, nodePort, ipStrings(tt.wantNodePort), "LoadBalancerNodeAddresses do not match")
			assert.NoError(t, h.Stop(context.TODO()), "Stop")
		})
	}

}

var nodeAddressWhitelistTests = []struct {
	name         string
	cidrs        string                 // --nodeport-addresses
	addrs        []tables.DeviceAddress // Addresses to add to the "test" device
	wantLocal    []net.IP               // e.g. LocalAddresses()
	wantNodePort []net.IP               // e.g. LoadBalancerNodeAddresses()
}{
	{
		name:  "ipv4",
		cidrs: "10.0.0.0/8",
		addrs: []tables.DeviceAddress{
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
	},
	{
		name:  "ipv6",
		cidrs: "2001::/16",
		addrs: []tables.DeviceAddress{
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
	},
	{
		name:  "v4-v6 mix",
		cidrs: "2001::/16,10.0.0.0/8",
		addrs: []tables.DeviceAddress{
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
	},
}

func TestNodeAddressWhitelist(t *testing.T) {
	t.Parallel()

	for _, tt := range nodeAddressWhitelistTests {
		t.Run(tt.name, func(t *testing.T) {

			var (
				db        *statedb.DB
				devices   statedb.RWTable[*tables.Device]
				nodeAddrs statedb.Table[tables.NodeAddress]
			)
			h := hive.New(
				job.Cell,
				statedb.Cell,
				tables.NodeAddressCell,
				cell.Provide(
					tables.NewDeviceTable,
					statedb.RWTable[*tables.Device].ToTable,
				),
				cell.Invoke(func(db_ *statedb.DB, d statedb.RWTable[*tables.Device], na statedb.Table[tables.NodeAddress]) {
					db = db_
					devices = d
					nodeAddrs = na
					db.RegisterTable(d)
				}),

				// option.DaemonConfig needed for AddressMaxScope. This flag will move into NodeAddressConfig
				// in a follow-up PR.
				cell.Provide(func() *option.DaemonConfig {
					return &option.DaemonConfig{
						AddressScopeMax: defaults.AddressScopeMax,
					}
				}),
			)
			h.Viper().Set("nodeport-addresses", tt.cidrs)

			if !assert.NoError(t, h.Start(context.TODO()), "Start") {
				return
			}

			txn := db.WriteTxn(devices)
			_, watch := nodeAddrs.All(txn)

			devices.Insert(txn, &tables.Device{
				Index: 1,
				Name:  "cilium_host",
				Flags: net.FlagUp,
				Addrs: []tables.DeviceAddress{
					{Addr: ip.MustAddrFromIP(ciliumHostIP), Scope: unix.RT_SCOPE_UNIVERSE},
					{Addr: ip.MustAddrFromIP(ciliumHostIPLinkScoped), Scope: unix.RT_SCOPE_LINK},
				},
				Selected: false,
			})

			shuffleSlice(tt.addrs) // For extra bit of randomness
			devices.Insert(txn,
				&tables.Device{
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
			for addr, _, ok := iter.Next(); ok; addr, _, ok = iter.Next() {
				local = append(local, addr.Addr.String())
				if addr.NodePort {
					nodePort = append(nodePort, addr.Addr.String())
				}
			}
			assert.ElementsMatch(t, local, ipStrings(tt.wantLocal), "LocalAddresses do not match")
			assert.ElementsMatch(t, nodePort, ipStrings(tt.wantNodePort), "LoadBalancerNodeAddresses do not match")
			assert.NoError(t, h.Stop(context.TODO()), "Stop")
		})
	}

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

func shuffleSlice[T any](xs []T) {
	rand.Shuffle(
		len(xs),
		func(i, j int) {
			xs[i], xs[j] = xs[j], xs[i]
		})
}
