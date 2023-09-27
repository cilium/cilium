// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package linux_test

import (
	"context"
	"net"
	"net/netip"
	"testing"

	"github.com/cilium/cilium/pkg/datapath/linux"
	"github.com/cilium/cilium/pkg/datapath/tables"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/cilium/cilium/pkg/statedb"
	"github.com/stretchr/testify/require"
	"github.com/vishvananda/netlink"
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

func TestLocalAddresses(t *testing.T) {
	db, devices := setupDBAndDevices(t)
	nodeAddressing := linux.NewNodeAddressing(nil, db, devices)

	tests := []struct {
		name  string
		addrs []tables.DeviceAddress
		want  []net.IP
	}{
		{
			name: "simple",
			addrs: []tables.DeviceAddress{
				{
					Addr:  netip.MustParseAddr("10.0.0.1"),
					Scope: uint8(netlink.SCOPE_HOST),
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
					Addr:  netip.MustParseAddr("10.0.0.1"),
					Scope: uint8(netlink.SCOPE_HOST),
				},
				{
					Addr:  netip.MustParseAddr("10.0.0.2"),
					Scope: uint8(netlink.SCOPE_LINK),
				},
			},

			want: []net.IP{
				net.ParseIP("10.0.0.1"),
				net.ParseIP("10.0.0.2"),
			},
		},
		{
			name: "ipv6 simple",
			addrs: []tables.DeviceAddress{
				{
					Addr:  netip.MustParseAddr("2001:db8::"),
					Scope: uint8(netlink.SCOPE_HOST),
				},
			},

			want: []net.IP{
				net.ParseIP("2001:db8::"),
			},
		},
		{
			name: "ipv6 multiple",
			addrs: []tables.DeviceAddress{
				{
					Addr:  netip.MustParseAddr("2001:db8::"),
					Scope: uint8(netlink.SCOPE_HOST),
				},
				{
					Addr:  netip.MustParseAddr("2600:beef::"),
					Scope: uint8(netlink.SCOPE_HOST),
				},
			},

			want: []net.IP{
				net.ParseIP("2001:db8::"),
				net.ParseIP("2600:beef::"),
			},
		},
		{
			name: "v4/v6 mix",
			addrs: []tables.DeviceAddress{
				{
					Addr:  netip.MustParseAddr("10.0.0.1"),
					Scope: uint8(netlink.SCOPE_HOST),
				},
				{
					Addr:  netip.MustParseAddr("2001:db8::"),
					Scope: uint8(netlink.SCOPE_HOST),
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
					Addr:  netip.MustParseAddr("10.0.0.1"),
					Scope: uint8(netlink.SCOPE_HOST),
				},
				{
					Addr:  netip.MustParseAddr("169.254.20.10"),
					Scope: uint8(netlink.SCOPE_HOST),
				},
				{
					Addr:  netip.MustParseAddr("169.254.169.254"),
					Scope: uint8(netlink.SCOPE_HOST),
				},
			},

			want: []net.IP{
				net.ParseIP("10.0.0.1"),
				net.ParseIP("169.254.20.10"),
				net.ParseIP("169.254.169.254"),
			},
		},
		{
			name: "include link-local v6",
			addrs: []tables.DeviceAddress{
				{
					Addr:  netip.MustParseAddr("10.0.0.1"),
					Scope: uint8(netlink.SCOPE_HOST),
				},
				{
					Addr:  netip.MustParseAddr("fe80::"),
					Scope: uint8(netlink.SCOPE_HOST),
				},
				{
					Addr:  netip.MustParseAddr("fe80::1234"),
					Scope: uint8(netlink.SCOPE_HOST),
				},
			},
			want: []net.IP{
				net.ParseIP("10.0.0.1"),
				net.ParseIP("fe80::"),
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
