// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package datapath_test

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"testing"

	"github.com/spf13/pflag"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"

	"github.com/cilium/cilium/pkg/cidr"
	"github.com/cilium/cilium/pkg/datapath"
	"github.com/cilium/cilium/pkg/datapath/tables"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/cilium/cilium/pkg/statedb"
)

func setupDBAndDevices(t *testing.T) (db *statedb.DB, tbl statedb.RWTable[*tables.Device]) {
	h := hive.New(
		statedb.Cell,
		tables.DeviceTableCell,
		cell.Invoke(func(db_ *statedb.DB, tbl_ statedb.RWTable[*tables.Device]) {
			db = db_
			tbl = tbl_
		}),
	)
	require.NoError(t, h.Start(context.TODO()), "Start")
	t.Cleanup(func() {
		h.Stop(context.TODO())
	})
	return
}

func TestNodeAddressingConfig(t *testing.T) {
	var cfg datapath.NodeAddressingConfig
	newHive := func() *hive.Hive {
		return hive.New(
			cell.Config(datapath.NodeAddressingConfig{}),
			cell.Invoke(func(c datapath.NodeAddressingConfig) { cfg = c; fmt.Println("invoked") }),
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
		require.NoError(t, h.Start(context.TODO()), "Start")
		require.NoError(t, h.Stop(context.TODO()), "Stop")
		require.Len(t, cfg.NodePortAddresses, len(testCase))
		for i := range testCase {
			require.Equal(t, testCase[i], cfg.NodePortAddresses[i].String())
		}
	}
}

func TestNodeAddressingWhiteList(t *testing.T) {
	db, devices := setupDBAndDevices(t)
	cfg := datapath.NodeAddressingConfig{
		// Only consider addresses in these ranges.
		NodePortAddresses: []*cidr.CIDR{
			cidr.MustParseCIDR("10.0.0.0/8"),
			cidr.MustParseCIDR("2001::/8"),
			cidr.MustParseCIDR("2600::/8"),
		},
	}
	nodeAddressing := datapath.NewNodeAddressing(cfg, nil, db, devices)

	tests := []struct {
		name  string
		addrs []tables.DeviceAddress
		want  []net.IP
	}{
		{
			name: "multiple",
			addrs: []tables.DeviceAddress{
				{
					Addr: netip.MustParseAddr("10.0.0.1"),
				},
				{
					Addr: netip.MustParseAddr("10.0.0.2"),
				},
			},

			want: []net.IP{
				net.ParseIP("10.0.0.1"),
				net.ParseIP("10.0.0.2"),
			},
		},

		{
			name: "ipv6 multiple",
			addrs: []tables.DeviceAddress{
				{
					Addr: netip.MustParseAddr("2001:db8::"),
				},
				{
					Addr: netip.MustParseAddr("2600:beef::"),
				},
			},

			want: []net.IP{
				net.ParseIP("2001:db8::"),
				net.ParseIP("2600:beef::"),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			txn := db.WriteTxn(devices)
			devices.Insert(txn,
				&tables.Device{
					Name:     "test",
					Selected: true,
					Addrs:    tt.addrs,
				})
			txn.Commit()

			v4, err := nodeAddressing.IPv4().LocalAddresses()
			require.NoError(t, err, "IPv4().LocalAddresses()")
			v6, err := nodeAddressing.IPv6().LocalAddresses()
			require.NoError(t, err, "IPv6().LocalAddresses()")
			got := append(v4, v6...)

			require.ElementsMatch(t, ipStrings(got), ipStrings(tt.want), "Addresses do not match")
		})
	}

}

func TestLocalAddresses(t *testing.T) {
	db, devices := setupDBAndDevices(t)
	nodeAddressing := datapath.NewNodeAddressing(datapath.NodeAddressingConfig{}, nil, db, devices)

	tests := []struct {
		name  string
		addrs []tables.DeviceAddress
		want  []net.IP
	}{
		{
			name: "simple",
			addrs: []tables.DeviceAddress{
				{
					Addr: netip.MustParseAddr("10.0.0.1"),
				},
			},
			want: []net.IP{
				net.ParseIP("10.0.0.1"),
			},
		},
		{
			name: "multiple",
			addrs: []tables.DeviceAddress{
				{
					Addr: netip.MustParseAddr("10.0.0.1"),
				},
				{
					Addr: netip.MustParseAddr("10.0.0.2"),
				},
			},

			want: []net.IP{
				// Only first address is used
				net.ParseIP("10.0.0.1"),
			},
		},
		{
			name: "ipv6 simple",
			addrs: []tables.DeviceAddress{
				{
					Addr: netip.MustParseAddr("2001:db8::"),
				},
				{
					Addr: netip.MustParseAddr("2600:db8::"),
				},
			},

			want: []net.IP{
				net.ParseIP("2001:db8::"),
			},
		},
		{
			name: "v4/v6 mix",
			addrs: []tables.DeviceAddress{
				{
					Addr: netip.MustParseAddr("10.0.0.1"),
				},
				{
					Addr: netip.MustParseAddr("2001:db8::"),
				},
			},

			want: []net.IP{
				net.ParseIP("10.0.0.1"),
				net.ParseIP("2001:db8::"),
			},
		},
		{
			name: "include link-local v4",
			addrs: []tables.DeviceAddress{
				{
					Addr: netip.MustParseAddr("169.254.169.254"),
				},
			},

			want: []net.IP{
				net.ParseIP("169.254.169.254"),
			},
		},
		{
			name: "include link-local v6",
			addrs: []tables.DeviceAddress{
				{
					Addr: netip.MustParseAddr("10.0.0.1"),
				},
				{
					Addr: netip.MustParseAddr("fe80::1234"),
				},
			},
			want: []net.IP{
				net.ParseIP("10.0.0.1"),
				net.ParseIP("fe80::1234"),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			txn := db.WriteTxn(devices)
			devices.Insert(txn,
				&tables.Device{
					Name:     "test",
					Selected: true,
					Addrs:    tt.addrs,
				})
			txn.Commit()

			v4, err := nodeAddressing.IPv4().LocalAddresses()
			require.NoError(t, err, "IPv4().LocalAddresses()")
			v6, err := nodeAddressing.IPv6().LocalAddresses()
			require.NoError(t, err, "IPv6().LocalAddresses()")
			got := append(v4, v6...)

			require.ElementsMatch(t, ipStrings(got), ipStrings(tt.want), "Addresses do not match")
		})
	}
}

// ipStrings converts net.IP to a string. Used to assert equalence without having to deal
// with e.g. IPv4-mapped IPv6 presentation etc.
func ipStrings(ips []net.IP) (ss []string) {
	for i := range ips {
		ss = append(ss, ips[i].String())
	}
	return
}
