package tables_test

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"testing"

	"github.com/cilium/cilium/pkg/cidr"
	"github.com/cilium/cilium/pkg/datapath/tables"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/cilium/cilium/pkg/hive/job"
	"github.com/cilium/cilium/pkg/statedb"
	"github.com/spf13/pflag"
	"github.com/stretchr/testify/require"
)

func TestNodeAddressConfig(t *testing.T) {
	var cfg tables.NodeAddressConfig
	newHive := func() *hive.Hive {
		return hive.New(
			cell.Config(tables.NodeAddressConfig{}),
			cell.Invoke(func(c tables.NodeAddressConfig) { cfg = c; fmt.Println("invoked") }),
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
		flags.Set("node-addresses", strings.Join(testCase, ","))
		require.NoError(t, h.Start(context.TODO()), "Start")
		require.NoError(t, h.Stop(context.TODO()), "Stop")
		require.Len(t, cfg.NodeAddresses, len(testCase))
		for i := range testCase {
			require.Equal(t, testCase[i], cfg.NodeAddresses[i].String())
		}
	}
}

func TestNodeAddress(t *testing.T) {
	var (
		db        *statedb.DB
		devices   statedb.RWTable[*tables.Device]
		nodeAddrs statedb.Table[tables.NodeAddress]
	)
	h := hive.New(
		job.Cell,
		statedb.Cell,
		tables.NodeAddressCell,
		tables.DeviceTableCell,
		cell.Invoke(func(db_ *statedb.DB, d statedb.RWTable[*tables.Device], na statedb.Table[tables.NodeAddress]) {
			db = db_
			devices = d
			nodeAddrs = na
		}),
	)
	hive.AddConfigOverride(h, func(cfg *tables.NodeAddressConfig) {
		// Only consider addresses in these ranges.
		cfg.NodeAddresses = []*cidr.CIDR{
			cidr.MustParseCIDR("10.0.0.0/8"),
			cidr.MustParseCIDR("2001::/8"),
			cidr.MustParseCIDR("2600::/8"),
		}
	})
	require.NoError(t, h.Start(context.TODO()), "Start")

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
					Addr: netip.MustParseAddr("2001:db8::1"),
				},
				{
					Addr: netip.MustParseAddr("2600:beef::2"),
				},
			},

			want: []net.IP{
				net.ParseIP("2001:db8::1"),
				net.ParseIP("2600:beef::2"),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			txn := db.WriteTxn(devices)
			_, watch := nodeAddrs.All(txn)
			devices.Insert(txn,
				&tables.Device{
					Name:     "test",
					Selected: true,
					Addrs:    tt.addrs,
				})
			txn.Commit()
			<-watch // wait for propagation

			iter, _ := nodeAddrs.All(db.ReadTxn())
			got := []string{}
			for addr, _, ok := iter.Next(); ok; addr, _, ok = iter.Next() {
				got = append(got, addr.Addr.String())
			}
			require.ElementsMatch(t, got, ipStrings(tt.want), "Addresses do not match")
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
