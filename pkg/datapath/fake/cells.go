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
	"github.com/cilium/cilium/pkg/datapath/gneigh"
	"github.com/cilium/cilium/pkg/datapath/iptables/ipset"
	"github.com/cilium/cilium/pkg/datapath/link"
	"github.com/cilium/cilium/pkg/datapath/linux/bigtcp"
	"github.com/cilium/cilium/pkg/datapath/linux/sysctl"
	"github.com/cilium/cilium/pkg/datapath/loader"
	"github.com/cilium/cilium/pkg/datapath/tables"
	"github.com/cilium/cilium/pkg/datapath/tunnel"
	"github.com/cilium/cilium/pkg/datapath/types"
	"github.com/cilium/cilium/pkg/maps/authmap"
	fakeauthmap "github.com/cilium/cilium/pkg/maps/authmap/fake"
	"github.com/cilium/cilium/pkg/maps/egressmap"
	"github.com/cilium/cilium/pkg/maps/encrypt"
	fakeencryptmap "github.com/cilium/cilium/pkg/maps/encrypt/fake"
	"github.com/cilium/cilium/pkg/maps/lxcmap"
	"github.com/cilium/cilium/pkg/maps/nat"
	"github.com/cilium/cilium/pkg/maps/signalmap"
	fakesignalmap "github.com/cilium/cilium/pkg/maps/signalmap/fake"
	"github.com/cilium/cilium/pkg/mtu"
	"github.com/cilium/cilium/pkg/node/manager"
	"github.com/cilium/cilium/pkg/time"
	wgTypes "github.com/cilium/cilium/pkg/wireguard/types"
)

// Cell provides a fake version of the datapath cell.
//
// Used in integration tests in daemon/cmd and test/controlplane.
var Cell = cell.Module(
	"fake-datapath",
	"Fake Datapath",

	cell.Provide(
		func(lifecycle cell.Lifecycle, na types.NodeAddressing, nodeManager manager.NodeManager) (types.NodeIDHandler, types.NodeHandler, *fakeTypes.FakeNodeHandler) {
			fakeNodeHandler := fakeTypes.NewNodeHandler()
			nodeManager.Subscribe(fakeNodeHandler)
			return fakeNodeHandler, fakeNodeHandler, fakeNodeHandler
		},
		func() signalmap.Map { return fakesignalmap.NewFakeSignalMap([][]byte{}, time.Second) },
		func() authmap.Map { return fakeauthmap.NewFakeAuthMap() },
		func() encrypt.EncryptMap { return fakeencryptmap.NewFakeEncryptMap() },
		func() *egressmap.PolicyMap4 { return nil },
		func() *egressmap.PolicyMap6 { return nil },
		func() lxcmap.Map { return nil },
		func() *bigtcp.Configuration { return &bigtcp.Configuration{} },
		func() types.IptablesManager { return &fakeTypes.FakeIptablesManager{} },
		func() ipset.Manager { return &fakeTypes.IPSet{} },
		func() types.BandwidthManager { return &fakeTypes.BandwidthManager{} },
		func() types.IPsecAgent { return &fakeTypes.IPsecAgent{} },
		func() types.IPsecConfig { return &fakeTypes.IPsecConfig{} },
		func() mtu.MTU { return &fakeTypes.MTU{} },
		func() wgTypes.WireguardAgent { return &fakeTypes.WireguardAgent{} },
		func() wgTypes.WireguardConfig { return &fakeTypes.WireguardConfig{} },
		func() types.Loader { return &fakeTypes.FakeLoader{} },
		func() types.Orchestrator { return &fakeTypes.FakeOrchestrator{} },
		loader.NewCompilationLock,
		func() sysctl.Sysctl { return &Sysctl{} },
		func() (nat.NatMap4, nat.NatMap6) {
			return nil, nil
		},

		tables.NewDeviceTable,
		tables.NewL2AnnounceTable, statedb.RWTable[*tables.L2AnnounceEntry].ToTable,
		tables.NewRouteTable, statedb.RWTable[*tables.Route].ToTable,

		func() types.BigTCPConfig { return &fakeTypes.BigTCPUserConfig{} },

		func() gneigh.L2PodAnnouncementConfig { return &fakeTypes.GNeighConfig{} },
		func() types.ConnectorConfig { return fakeTypes.NewFakeConnectorVeth() },
	),

	tables.NodeAddressCell,
	datapath.NodeAddressingCell,
	tables.DirectRoutingDeviceCell,

	tunnel.Cell,
	cell.Provide(fakeDevices),
	link.Cell,
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
