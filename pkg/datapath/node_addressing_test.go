// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package datapath_test

import (
	"context"
	"net"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/datapath"
	"github.com/cilium/cilium/pkg/datapath/tables"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/cilium/cilium/pkg/statedb"
)

func setupDBAndTable(t *testing.T) (db *statedb.DB, tbl statedb.RWTable[tables.NodeAddress]) {
	h := hive.New(
		statedb.Cell,
		tables.NodeAddressTestTableCell,
		cell.Invoke(func(db_ *statedb.DB, tbl_ statedb.RWTable[tables.NodeAddress]) {
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
	db, nodeAddrs := setupDBAndTable(t)
	nodeAddressing := datapath.NewNodeAddressing(nil, db, nodeAddrs, nil)

	tests := []struct {
		name  string
		addrs []tables.NodeAddress
		want  []net.IP
	}{
		{
			name: "ipv4 simple",
			addrs: []tables.NodeAddress{
				{
					Addr: netip.MustParseAddr("10.0.0.1"),
				},
			},
			want: []net.IP{
				net.ParseIP("10.0.0.1"),
			},
		},
		{
			name: "ipv6 simple",
			addrs: []tables.NodeAddress{
				{
					Addr: netip.MustParseAddr("2001:db8::1"),
				},
			},

			want: []net.IP{
				net.ParseIP("2001:db8::1"),
			},
		},
		{
			name: "v4/v6 mix",
			addrs: []tables.NodeAddress{
				{
					Addr: netip.MustParseAddr("10.0.0.1"),
				},
				{
					Addr: netip.MustParseAddr("2001:db8::1"),
				},
			},

			want: []net.IP{
				net.ParseIP("10.0.0.1"),
				net.ParseIP("2001:db8::1"),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			txn := db.WriteTxn(nodeAddrs)
			nodeAddrs.DeleteAll(txn)
			for _, addr := range tt.addrs {
				nodeAddrs.Insert(txn, addr)
			}
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
