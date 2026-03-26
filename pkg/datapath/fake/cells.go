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
	"github.com/cilium/cilium/pkg/datapath/connector"
	fakeconnector "github.com/cilium/cilium/pkg/datapath/connector/fake"
	fakeTypes "github.com/cilium/cilium/pkg/datapath/fake/types"
	"github.com/cilium/cilium/pkg/datapath/gneigh"
	"github.com/cilium/cilium/pkg/datapath/iptables"
	fakeiptables "github.com/cilium/cilium/pkg/datapath/iptables/fake"
	"github.com/cilium/cilium/pkg/datapath/iptables/ipset"
	"github.com/cilium/cilium/pkg/datapath/link"
	"github.com/cilium/cilium/pkg/datapath/linux/bandwidth"
	fakebandwidth "github.com/cilium/cilium/pkg/datapath/linux/bandwidth/fake"
	"github.com/cilium/cilium/pkg/datapath/linux/bigtcp"
	fakebigtcp "github.com/cilium/cilium/pkg/datapath/linux/bigtcp/fake"
	"github.com/cilium/cilium/pkg/datapath/linux/sysctl"
	"github.com/cilium/cilium/pkg/datapath/loader"
	fakeloader "github.com/cilium/cilium/pkg/datapath/loader/fake"
	loaderTypes "github.com/cilium/cilium/pkg/datapath/loader/types"
	"github.com/cilium/cilium/pkg/datapath/tables"
	"github.com/cilium/cilium/pkg/datapath/tunnel"
	"github.com/cilium/cilium/pkg/datapath/types"
	fakeendpoint "github.com/cilium/cilium/pkg/endpoint/fake"
	endpoint "github.com/cilium/cilium/pkg/endpoint/types"
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
	"github.com/cilium/cilium/pkg/node"
	fakenode "github.com/cilium/cilium/pkg/node/fake"
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
		func(lifecycle cell.Lifecycle, na types.NodeAddressing, nodeManager manager.NodeManager) (types.NodeIDHandler, node.Handler, *fakenode.Handler) {
			fakeNodeHandler := fakenode.NewHandler()
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
		func() iptables.Manager { return fakeiptables.NewManager() },
		func() ipset.Manager { return &fakeTypes.IPSet{} },
		func() bandwidth.Manager { return &fakebandwidth.Manager{} },
		func() types.IPsecAgent { return &fakeTypes.IPsecAgent{} },
		func() types.IPsecConfig { return &fakeTypes.IPsecConfig{} },
		func() mtu.MTU { return &fakeTypes.MTU{} },
		func() wgTypes.WireguardAgent { return &fakeTypes.WireguardAgent{} },
		func() wgTypes.WireguardConfig { return &fakeTypes.WireguardConfig{} },
		func() loaderTypes.Loader { return &fakeloader.Loader{} },
		func() endpoint.Orchestrator { return &fakeendpoint.FakeOrchestrator{} },
		loader.NewCompilationLock,
		func() sysctl.Sysctl { return &Sysctl{} },
		func() (nat.NatMap4, nat.NatMap6) {
			return nil, nil
		},

		tables.NewDeviceTable,
		tables.NewL2AnnounceTable, statedb.RWTable[*tables.L2AnnounceEntry].ToTable,
		tables.NewRouteTable, statedb.RWTable[*tables.Route].ToTable,

		func() bigtcp.Features { return &fakebigtcp.UserConfig{} },

		func() gneigh.L2PodAnnouncementConfig { return &fakeTypes.GNeighConfig{} },
		func() connector.Config { return fakeconnector.NewVeth() },
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
