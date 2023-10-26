// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package tables_test

import (
	"context"
	"net"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"

	"github.com/cilium/cilium/pkg/datapath/tables"
	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/cilium/cilium/pkg/statedb"
)

func setupDBAndTable(t *testing.T) (db *statedb.DB, nodeAddrs statedb.RWTable[tables.NodeAddress], devices statedb.RWTable[*tables.Device]) {
	h := hive.New(
		statedb.Cell,
		tables.NodeAddressTestTableCell,
		tables.DeviceTableCell,
		cell.Invoke(func(db_ *statedb.DB, nodeAddrs_ statedb.RWTable[tables.NodeAddress], devices_ statedb.RWTable[*tables.Device]) {
			db = db_
			nodeAddrs = nodeAddrs_
			devices = devices_
		}),
	)
	require.NoError(t, h.Start(context.TODO()), "Start")
	t.Cleanup(func() {
		h.Stop(context.TODO())
	})
	return
}

func TestLocalAddresses(t *testing.T) {
	db, nodeAddrs, devices := setupDBAndTable(t)

	{
		txn := db.WriteTxn(devices)
		devices.Insert(txn, &tables.Device{
			Index: 1,
			Name:  "cilium_host",
			Flags: net.FlagUp,
			Addrs: []tables.DeviceAddress{
				{Addr: netip.MustParseAddr("9.9.9.9"), Scope: unix.RT_SCOPE_SITE},
			},
		})
		txn.Commit()
	}

	nodeAddressing := tables.NewNodeAddressing(
		tables.AddressScopeMax(defaults.AddressScopeMax), nil, db, nodeAddrs, devices,
	)

	tests := []struct {
		name  string
		addrs []tables.DeviceAddress
		want  []net.IP
	}{
		{
			name: "ipv4 simple",
			addrs: []tables.DeviceAddress{
				{
					Addr:  netip.MustParseAddr("10.0.0.1"),
					Scope: unix.RT_SCOPE_SITE,
				},
			},
			want: []net.IP{
				net.ParseIP("10.0.0.1"),
				net.ParseIP("9.9.9.9"), // cilium_host
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

			want: []net.IP{
				net.ParseIP("2001:db8::1"),
				net.ParseIP("9.9.9.9"), // cilium_host
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

			want: []net.IP{
				net.ParseIP("10.0.0.1"),
				net.ParseIP("2001:db8::1"),
				net.ParseIP("9.9.9.9"), // cilium_host
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
					Addr:  netip.MustParseAddr("10.0.3.3"),
					Scope: unix.RT_SCOPE_HOST,
				},
			},

			// The default AddressMaxScope is set to LINK-1, so addresses with
			// scope LINK or above are ignored
			want: []net.IP{
				net.ParseIP("10.0.1.1"),
				net.ParseIP("9.9.9.9"), // cilium_host
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			txn := db.WriteTxn(devices)
			devices.Insert(txn, &tables.Device{
				Index: 2,
				Name:  "test",
				Flags: net.FlagUp,
				Addrs: tt.addrs,
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
