// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package tables

import (
	"context"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/hivetest"
	"github.com/cilium/statedb"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/inctimer"
	"github.com/cilium/cilium/pkg/ip"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/node/addressing"
	"github.com/cilium/cilium/pkg/node/types"
)

var testIP = net.ParseIP("192.168.0.1")

func TestDirectRoutingDevice(t *testing.T) {
	var (
		db               *statedb.DB
		devicesTable     statedb.RWTable[*Device]
		directRoutingDev DirectRoutingDevice
	)

	h := hive.New(
		cell.Provide(
			func() node.LocalNode {
				return node.LocalNode{
					Node: types.Node{
						IPAddresses: []types.Address{
							{
								Type: addressing.NodeInternalIP,
								IP:   testIP,
							},
						},
					},
				}
			},
			node.NewTestLocalNodeStore,
			NewDeviceTable,
			func(_ *statedb.DB, devices statedb.RWTable[*Device]) statedb.Table[*Device] {
				return devices
			},
		),
		DirectRoutingDeviceCell,
		cell.Invoke(
			statedb.RegisterTable[*Device],
			func(db_ *statedb.DB, table statedb.RWTable[*Device], dev DirectRoutingDevice) {
				db = db_
				devicesTable = table
				directRoutingDev = dev
			},
		),
	)

	ctx := context.Background()
	log := hivetest.Logger(t)
	err := h.Start(log, ctx)
	require.NoError(t, err)
	t.Cleanup(func() { h.Stop(log, ctx) })
	require.NotNil(t, h)
	require.NotNil(t, db)
	require.NotNil(t, devicesTable)
	require.NotNil(t, directRoutingDev)

	// No devices - ensure that we don't get a device.
	tctx, cancel := context.WithTimeout(ctx, time.Millisecond)
	dev, _ := directRoutingDev.Get(tctx, db.ReadTxn())
	cancel()
	require.Nil(t, dev)

	// Insert a device
	txn := db.WriteTxn(devicesTable)
	want := Device{
		Index:    1,
		Name:     "direct0",
		Selected: true,
	}
	devicesTable.Insert(txn, &want)
	txn.Commit()

	// And check that it's returned
	tctx, cancel = context.WithTimeout(ctx, time.Millisecond)
	got, watch := directRoutingDev.Get(tctx, db.ReadTxn())
	cancel()
	require.NotNil(t, got)
	require.Equal(t, want.Name, got.Name)
	select {
	case <-watch:
		t.Error("watch channel closed even though it should not")
	case <-inctimer.After(time.Millisecond):
	}

	// Insert another device.
	txn = db.WriteTxn(devicesTable)
	dummyDev := Device{
		Index:    2,
		Name:     "dummy0",
		Selected: true,
	}
	devicesTable.Insert(txn, &dummyDev)
	txn.Commit()

	// Two selected devices - ensure that we don't get a device.
	tctx, cancel = context.WithTimeout(ctx, time.Millisecond)
	dev, watch = directRoutingDev.Get(tctx, db.ReadTxn())
	cancel()
	require.Nil(t, dev)
	select {
	case <-watch:
		t.Error("watch channel closed even though it should not")
	case <-inctimer.After(time.Millisecond):
	}

	// If one of the devices matches the K8s Node IP, it is returned.
	want.Addrs = []DeviceAddress{
		{
			Addr: ip.MustAddrFromIP(testIP),
		},
	}
	tctx, cancel = context.WithTimeout(ctx, time.Millisecond)
	got, watch = directRoutingDev.Get(tctx, db.ReadTxn())
	cancel()
	require.NotNil(t, got)
	require.Equal(t, want.Name, got.Name)
	select {
	case <-watch:
		t.Error("watch channel closed even though it should not")
	case <-inctimer.After(time.Millisecond):
	}
	want.Addrs = nil
}

func TestDirectRoutingDevice_withConfig(t *testing.T) {
	for _, tc := range []struct {
		config  string
		name    string
		want    Device
		wantErr bool
	}{
		{
			name:   "config which doesn't match any device",
			config: "nope",
			want: Device{
				Index:    1,
				Name:     "direct0",
				Selected: true,
			},
		},
		{
			name:   "config does match one device",
			config: "direct+",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var (
				db               *statedb.DB
				devicesTable     statedb.RWTable[*Device]
				directRoutingDev DirectRoutingDevice
			)

			h := hive.New(
				cell.Provide(
					func() node.LocalNode {
						return node.LocalNode{
							Node: types.Node{
								IPAddresses: []types.Address{
									{
										Type: addressing.NodeInternalIP,
										IP:   testIP,
									},
								},
							},
						}
					},
					node.NewTestLocalNodeStore,
					NewDeviceTable,
					func(_ *statedb.DB, devices statedb.RWTable[*Device]) statedb.Table[*Device] {
						return devices
					},
				),
				DirectRoutingDeviceCell,
				cell.Invoke(
					statedb.RegisterTable[*Device],
					func(db_ *statedb.DB, table_ statedb.RWTable[*Device], dev DirectRoutingDevice) {
						db = db_
						devicesTable = table_
						directRoutingDev = dev
					},
				),
			)
			hive.AddConfigOverride(h, func(c *DirectRoutingDeviceConfig) {
				c.DirectRoutingDevice = tc.config
			})

			ctx := context.Background()
			log := hivetest.Logger(t)
			err := h.Start(log, ctx)
			require.NoError(t, err)
			t.Cleanup(func() { h.Stop(log, ctx) })
			require.NotNil(t, db)
			require.NotNil(t, devicesTable)
			require.NotNil(t, directRoutingDev)

			// Insert devices
			txn := db.WriteTxn(devicesTable)
			devicesTable.Insert(txn, &Device{
				Index:    10,
				Name:     "dummy0",
				Selected: true,
				Addrs: []DeviceAddress{
					{
						Addr: netip.MustParseAddr("1.2.3.4"),
					},
				},
			})
			devicesTable.Insert(txn, &tc.want)
			txn.Commit()

			tctx, cancel := context.WithTimeout(ctx, time.Millisecond)
			got, watch := directRoutingDev.Get(tctx, db.ReadTxn())
			cancel()
			if tc.wantErr == (got == nil) {
				t.Errorf("wantErr %v but have err %v", tc.wantErr, err)
			}
			if got != nil {
				require.Equal(t, tc.want.Index, got.Index)
				require.Equal(t, tc.want.Name, got.Name)
				require.Equal(t, tc.want.Addrs, got.Addrs)
			}
			select {
			case <-watch:
				t.Error("watch channel closed even though it should not")
			case <-inctimer.After(time.Millisecond):
			}
		})
	}
}
