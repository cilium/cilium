// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package fake

import (
	"net"
	"net/netip"

	"github.com/cilium/hive/cell"
	"github.com/cilium/statedb"
	"go4.org/netipx"
	"golang.org/x/sys/unix"

	"github.com/cilium/cilium/pkg/datapath"
	fakeTypes "github.com/cilium/cilium/pkg/datapath/fake/types"
	"github.com/cilium/cilium/pkg/datapath/iptables/ipset"
	"github.com/cilium/cilium/pkg/datapath/linux/bigtcp"
	"github.com/cilium/cilium/pkg/datapath/linux/sysctl"
	"github.com/cilium/cilium/pkg/datapath/loader"
	"github.com/cilium/cilium/pkg/datapath/tables"
	"github.com/cilium/cilium/pkg/datapath/tunnel"
	"github.com/cilium/cilium/pkg/datapath/types"
	"github.com/cilium/cilium/pkg/maps/authmap"
	fakeauthmap "github.com/cilium/cilium/pkg/maps/authmap/fake"
	"github.com/cilium/cilium/pkg/maps/egressmap"
	"github.com/cilium/cilium/pkg/maps/nat"
	"github.com/cilium/cilium/pkg/maps/signalmap"
	fakesignalmap "github.com/cilium/cilium/pkg/maps/signalmap/fake"
	"github.com/cilium/cilium/pkg/mtu"
	"github.com/cilium/cilium/pkg/node/manager"
	"github.com/cilium/cilium/pkg/promise"
	"github.com/cilium/cilium/pkg/testutils/mockmaps"
	"github.com/cilium/cilium/pkg/time"
	wg "github.com/cilium/cilium/pkg/wireguard/agent"
)

// Cell provides a fake version of the datapath cell.
//
// Used in integration tests in daemon/cmd and test/controlplane.
var Cell = cell.Module(
	"fake-datapath",
	"Fake Datapath",

	cell.Provide(
		func(lifecycle cell.Lifecycle, na types.NodeAddressing, nodeManager manager.NodeManager) (types.NodeIDHandler, types.NodeHandler, types.NodeNeighbors, *fakeTypes.FakeNodeHandler) {
			fakeNodeHandler := fakeTypes.NewNodeHandler()
			nodeManager.Subscribe(fakeNodeHandler)
			return fakeNodeHandler, fakeNodeHandler, fakeNodeHandler, fakeNodeHandler
		},
		func(lifecycle cell.Lifecycle, na types.NodeAddressing, nodeManager manager.NodeManager) (types.LBMap, *mockmaps.LBMockMap) {
			lbMap := mockmaps.NewLBMockMap()
			return lbMap, lbMap
		},
		func() signalmap.Map { return fakesignalmap.NewFakeSignalMap([][]byte{}, time.Second) },
		func() authmap.Map { return fakeauthmap.NewFakeAuthMap() },
		func() egressmap.PolicyMap { return nil },
		func() *bigtcp.Configuration { return &bigtcp.Configuration{} },
		func() types.IptablesManager { return &fakeTypes.FakeIptablesManager{} },
		func() ipset.Manager { return &fakeTypes.IPSet{} },
		func() types.BandwidthManager { return &fakeTypes.BandwidthManager{} },
		func() types.IPsecKeyCustodian { return &ipsecKeyCustodian{} },
		func() mtu.MTU { return &fakeTypes.MTU{} },
		func() *wg.Agent { return nil },
		func() types.Loader { return &fakeTypes.FakeLoader{} },
		func() types.Orchestrator { return &fakeTypes.FakeOrchestrator{} },
		loader.NewCompilationLock,
		func() sysctl.Sysctl { return &Sysctl{} },
		func() (promise.Promise[nat.NatMap4], promise.Promise[nat.NatMap6]) {
			r4, p4 := promise.New[nat.NatMap4]()
			r6, p6 := promise.New[nat.NatMap6]()
			r4.Reject(nat.MapDisabled)
			r6.Reject(nat.MapDisabled)
			return p4, p6
		},

		tables.NewDeviceTable,
		tables.NewL2AnnounceTable, statedb.RWTable[*tables.L2AnnounceEntry].ToTable,
		tables.NewRouteTable, statedb.RWTable[*tables.Route].ToTable,
	),

	tables.NodeAddressCell,
	datapath.NodeAddressingCell,
	tables.DirectRoutingDeviceCell,

	cell.Invoke(
		statedb.RegisterTable[*tables.Device],
		statedb.RegisterTable[*tables.L2AnnounceEntry],
		statedb.RegisterTable[*tables.Route],
	),

	tunnel.Cell,
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
			{Addr: netipx.MustFromStdIP(fakeTypes.IPv4NodePortAddress), Scope: unix.RT_SCOPE_UNIVERSE},
			{Addr: netipx.MustFromStdIP(fakeTypes.IPv6NodePortAddress), Scope: unix.RT_SCOPE_UNIVERSE},
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
			{Addr: netipx.MustFromStdIP(fakeTypes.IPv4InternalAddress), Scope: unix.RT_SCOPE_UNIVERSE},
			{Addr: netipx.MustFromStdIP(fakeTypes.IPv6InternalAddress), Scope: unix.RT_SCOPE_UNIVERSE},

			{Addr: netip.MustParseAddr("10.0.0.4"), Scope: unix.RT_SCOPE_UNIVERSE, Secondary: true},
			{Addr: netip.MustParseAddr("f00d::3"), Scope: unix.RT_SCOPE_UNIVERSE, Secondary: true},
		},
		Type:     "test",
		Selected: true,
	})

	return devices
}
