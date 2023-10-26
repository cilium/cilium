// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package fake

import (
	"net"
	"time"

	"github.com/cilium/cilium/pkg/datapath/tables"
	"github.com/cilium/cilium/pkg/datapath/types"
	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/cilium/cilium/pkg/ip"
	"github.com/cilium/cilium/pkg/maps/authmap"
	"github.com/cilium/cilium/pkg/maps/egressmap"
	"github.com/cilium/cilium/pkg/maps/signalmap"
	"github.com/cilium/cilium/pkg/statedb"
	"golang.org/x/sys/unix"

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
		func() (*FakeDatapath, types.Datapath, types.NodeAddressing, types.NodeIDHandler) {
			dp := NewDatapath()
			return dp, dp, dp.LocalNodeAddressing(), dp.NodeIDs()
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

	// FIXME: Remove "FakeNodeAddressing" and instead derive it from the devices here.
	devices.Insert(txn, &tables.Device{
		Index:        1,
		MTU:          1500,
		Name:         "test",
		HardwareAddr: []byte{1, 2, 3, 4, 5, 6},
		Flags:        net.FlagUp,
		Addrs: []tables.DeviceAddress{
			{Addr: ip.MustAddrFromIP(IPv4NodePortAddress), Scope: unix.RT_SCOPE_UNIVERSE},
			{Addr: ip.MustAddrFromIP(IPv4InternalAddress), Scope: unix.RT_SCOPE_SITE},
			{Addr: ip.MustAddrFromIP(IPv6NodePortAddress), Scope: unix.RT_SCOPE_UNIVERSE},
			{Addr: ip.MustAddrFromIP(IPv6InternalAddress), Scope: unix.RT_SCOPE_SITE},
		},
		Type:     "test",
		Selected: true,
	})
	return devices
}
