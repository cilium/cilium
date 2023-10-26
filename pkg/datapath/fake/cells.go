// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package fake

import (
	"net"
	"net/netip"
	"time"

	"golang.org/x/sys/unix"

	"github.com/cilium/cilium/pkg/datapath/tables"
	"github.com/cilium/cilium/pkg/datapath/types"
	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/cilium/cilium/pkg/ip"
	"github.com/cilium/cilium/pkg/maps/authmap"
	"github.com/cilium/cilium/pkg/maps/egressmap"
	"github.com/cilium/cilium/pkg/maps/signalmap"
	"github.com/cilium/cilium/pkg/statedb"

	fakeauthmap "github.com/cilium/cilium/pkg/maps/authmap/fake"
	fakesignalmap "github.com/cilium/cilium/pkg/maps/signalmap/fake"
)

// Cell provides a fake version of the datapath cell.
//
// Used in integration tests in daemon/cmd and test/controlplane.
var Cell = cell.Module(
	"fake-datapath",
	"Fake Datapath",

	cell.Provide(
		func(na types.NodeAddressing) (*FakeDatapath, types.Datapath, types.NodeIDHandler) {
			dp := newDatapath(na)
			return dp, dp, dp.NodeIDs()
		},

		func() signalmap.Map { return fakesignalmap.NewFakeSignalMap([][]byte{}, time.Second) },
		func() authmap.Map { return fakeauthmap.NewFakeAuthMap() },
		func() egressmap.PolicyMap { return nil },
	),

	// This cell defines StateDB tables and their schemas for tables which are used to transfer information
	// between datapath components and more high-level components.
	tables.Cell,
	tables.DeviceTableCell,
	cell.Provide(fakeDevices),
)

func fakeDevices(db *statedb.DB, devices statedb.RWTable[*tables.Device]) statedb.Table[*tables.Device] {
	txn := db.WriteTxn(devices)
	defer txn.Commit()

	devices.Insert(txn, &tables.Device{
		Index:        1,
		MTU:          1500,
		Name:         "test0",
		HardwareAddr: []byte{1, 2, 3, 4, 5, 6},
		Flags:        net.FlagUp,
		Addrs: []tables.DeviceAddress{
			{Addr: ip.MustAddrFromIP(IPv4NodePortAddress), Scope: unix.RT_SCOPE_UNIVERSE},
			{Addr: ip.MustAddrFromIP(IPv6NodePortAddress), Scope: unix.RT_SCOPE_UNIVERSE},
		},
		Type:     "test",
		Selected: true,
	})

	devices.Insert(txn, &tables.Device{
		Index:        2,
		MTU:          1500,
		Name:         "test1",
		HardwareAddr: []byte{2, 3, 4, 5, 6, 7},
		Flags:        net.FlagUp,
		Addrs: []tables.DeviceAddress{
			{Addr: ip.MustAddrFromIP(IPv4InternalAddress), Scope: unix.RT_SCOPE_SITE},
			{Addr: ip.MustAddrFromIP(IPv6InternalAddress), Scope: unix.RT_SCOPE_SITE},

			{Addr: netip.MustParseAddr("10.0.0.4"), Scope: unix.RT_SCOPE_SITE},
			{Addr: netip.MustParseAddr("f00d::3"), Scope: unix.RT_SCOPE_UNIVERSE},
		},
		Type:     "test",
		Selected: true,
	})

	return devices
}
