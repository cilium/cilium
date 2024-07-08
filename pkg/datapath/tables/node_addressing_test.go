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
	"github.com/cilium/cilium/pkg/datapath/types"
	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/cilium/cilium/pkg/hive/job"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/statedb"
)

var (
	v4Wild = net.ParseIP("0.0.0.0")
	v6Wild = net.ParseIP("::")
)

func setupNodeAddressing(t *testing.T, addrs []tables.DeviceAddress) (nodeAddressing types.NodeAddressing) {
	h := hive.New(
		job.Cell,
		statedb.Cell,

		// Table[*Device] infrastructure, to be filled with some fakes below.
		cell.Provide(tables.NewDeviceTable),
		cell.Invoke(statedb.RegisterTable[*tables.Device]),

		cell.Provide(func(db *statedb.DB, devices statedb.RWTable[*tables.Device]) statedb.Table[*tables.Device] {
			// Simulate the DevicesController and populate the devices table.
			txn := db.WriteTxn(devices)
			devices.Insert(txn, &tables.Device{
				Index: 1,
				Name:  "cilium_host",
				Flags: net.FlagUp,
				Addrs: []tables.DeviceAddress{
					{Addr: netip.MustParseAddr("9.9.9.9"), Scope: unix.RT_SCOPE_SITE},
					{Addr: netip.MustParseAddr("9.9.9.8"), Scope: unix.RT_SCOPE_LINK},
				},
				Selected: false,
			})
			devices.Insert(txn, &tables.Device{
				Index:    2,
				Name:     "test",
				Flags:    net.FlagUp,
				Addrs:    addrs,
				Selected: true,
			})
			txn.Commit()
			return devices
		}),

		// Table[NodeAddress] and controller that populates it from devices.
		tables.NodeAddressCell,

		// LocalNodeStore as required by Router(), PrimaryExternal(), etc.
		node.LocalNodeStoreCell,
		cell.Provide(func() node.LocalNodeSynchronizer { return testLocalNodeSync{} }),

		// option.DaemonConfig needed for AddressMaxScope. This flag will move into NodeAddressConfig
		// in a follow-up PR.
		cell.Provide(func() *option.DaemonConfig {
			return &option.DaemonConfig{
				AddressScopeMax: defaults.AddressScopeMax,
			}
		}),

		tables.NodeAddressingCell,
		cell.Invoke(func(nodeAddressing_ types.NodeAddressing) {
			nodeAddressing = nodeAddressing_
		}),
	)
	require.NoError(t, h.Start(context.TODO()), "Start")
	t.Cleanup(func() {
		h.Stop(context.TODO())
	})
	return
}

// TestNodeAddressing is an integration test that checks that from a [tables.Device] the
// correct [NodeAddress] is derived and [NodeAddressing] returns the correct results from
// there.
func TestNodeAddressing(t *testing.T) {
	// LocalAddresses() and LoadBalancerNodeAddresses()
	for _, tt := range nodeAddressTests {
		t.Run(tt.name, func(t *testing.T) {
			nodeAddressing := setupNodeAddressing(t, tt.addrs)

			{
				v4, err := nodeAddressing.IPv4().LocalAddresses()
				require.NoError(t, err, "IPv4().LocalAddresses()")
				v6, err := nodeAddressing.IPv6().LocalAddresses()
				require.NoError(t, err, "IPv6().LocalAddresses()")
				got := ipStrings(append(v4, v6...))

				want := ipStrings(tt.wantAddrs)
				require.ElementsMatch(t, got, want, "LocalAddresses() do not match")
			}
			{
				v4 := nodeAddressing.IPv4().LoadBalancerNodeAddresses()
				v6 := nodeAddressing.IPv6().LoadBalancerNodeAddresses()
				got := ipStrings(append(v4, v6...))
				want := ipStrings(append(tt.wantNodePort, v4Wild, v6Wild))
				require.ElementsMatch(t, got, want, "LoadBalancerNodeAddresses() do not match")
			}

		})
	}
}
