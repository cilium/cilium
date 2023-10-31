// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package fake

import (
	"github.com/cilium/cilium/pkg/datapath/iptables"
	"github.com/cilium/cilium/pkg/datapath/linux/bigtcp"
	"github.com/cilium/cilium/pkg/datapath/tables"
	"github.com/cilium/cilium/pkg/datapath/types"
	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/cilium/cilium/pkg/maps/authmap"
	"github.com/cilium/cilium/pkg/maps/egressmap"
	"github.com/cilium/cilium/pkg/maps/signalmap"
	"github.com/cilium/cilium/pkg/statedb"
	"github.com/cilium/cilium/pkg/time"

	fakeauthmap "github.com/cilium/cilium/pkg/maps/authmap/fake"
	fakesignalmap "github.com/cilium/cilium/pkg/maps/signalmap/fake"
)

// Cell provides a fake version of the datapath cell.
//
// Used in integration tests such as test/controlplane.
var Cell = cell.Module(
	"fake-datapath",
	"Fake Datapath",

	cell.Provide(
		func() (*FakeDatapath, types.Datapath, types.NodeIDHandler) {
			dp := NewDatapath()
			return dp, dp, dp.NodeIDs()
		},

		func() signalmap.Map { return fakesignalmap.NewFakeSignalMap([][]byte{}, time.Second) },
		func() authmap.Map { return fakeauthmap.NewFakeAuthMap() },
		func() egressmap.PolicyMap { return nil },
		func() *bigtcp.Configuration { return &bigtcp.Configuration{} },
		func() *iptables.Manager { return &iptables.Manager{} },

		tables.NewDeviceTable, statedb.RWTable[*tables.Device].ToTable,
		tables.NewL2AnnounceTable, statedb.RWTable[*tables.L2AnnounceEntry].ToTable,
		tables.NewRouteTable, statedb.RWTable[*tables.Route].ToTable,
	),

	tables.NodeAddressCell,

	cell.Invoke(
		statedb.RegisterTable[*tables.Device],
		statedb.RegisterTable[*tables.L2AnnounceEntry],
		statedb.RegisterTable[*tables.Route],
	),
)
