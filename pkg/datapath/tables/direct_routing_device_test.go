// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package tables

import (
	"context"
	"net"
	"net/netip"
	"testing"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/hivetest"
	"github.com/cilium/statedb"
	"github.com/stretchr/testify/require"
	"go4.org/netipx"

	"github.com/cilium/cilium/pkg/hive"
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

	tctx := context.Background()
	log := hivetest.Logger(t)
	err := h.Start(log, tctx)
	require.NoError(t, err)
	t.Cleanup(func() { h.Stop(log, tctx) })
	require.NotNil(t, h)
	require.NotNil(t, db)
	require.NotNil(t, devicesTable)
	require.NotNil(t, directRoutingDev)

	// No devices - ensure that we don't get a device.
	dev, _ := directRoutingDev.Get(tctx, db.ReadTxn())
	require.Nil(t, dev)

	// Insert a device
	txn := db.WriteTxn(devicesTable)
	want := Device{
		Index:    1,
		Name:     "direct0",
		Selected: true,
	}
	_, _, err = devicesTable.Insert(txn, &want)
	require.NoError(t, err)
	txn.Commit()

	// And check that it's returned
	got, watch := directRoutingDev.Get(tctx, db.ReadTxn())
	require.NotNil(t, got)
	require.Equal(t, want.Name, got.Name)
	select {
	case <-watch:
		t.Error("watch channel closed even though it should not")
	default:
	}

	// Insert another device.
	txn = db.WriteTxn(devicesTable)
	dummyDev := Device{
		Index:    2,
		Name:     "dummy0",
		Selected: true,
	}
	_, _, err = devicesTable.Insert(txn, &dummyDev)
	require.NoError(t, err)
	txn.Commit()

	// Two selected devices - ensure that we don't get a device.
	dev, watch = directRoutingDev.Get(tctx, db.ReadTxn())
	require.Nil(t, dev)
	select {
	case <-watch:
		t.Error("watch channel closed even though it should not")
	default:
	}

	// If one of the devices matches the K8s Node IP, it is returned.
	want.Addrs = []DeviceAddress{
		{
			Addr: netipx.MustFromStdIP(testIP),
		},
	}
	got, watch = directRoutingDev.Get(tctx, db.ReadTxn())
	require.NotNil(t, got)
	require.Equal(t, want.Name, got.Name)
	select {
	case <-watch:
		t.Error("watch channel closed even though it should not")
	default:
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

			tctx := context.Background()
			log := hivetest.Logger(t)
			err := h.Start(log, tctx)
			require.NoError(t, err)
			t.Cleanup(func() { h.Stop(log, tctx) })
			require.NotNil(t, db)
			require.NotNil(t, devicesTable)
			require.NotNil(t, directRoutingDev)

			// Insert devices
			txn := db.WriteTxn(devicesTable)
			_, _, err = devicesTable.Insert(txn, &Device{
				Index:    10,
				Name:     "dummy0",
				Selected: true,
				Addrs: []DeviceAddress{
					{
						Addr: netip.MustParseAddr("1.2.3.4"),
					},
				},
			})
			require.NoError(t, err)
			_, _, err = devicesTable.Insert(txn, &tc.want)
			require.NoError(t, err)
			txn.Commit()

			got, watch := directRoutingDev.Get(tctx, db.ReadTxn())
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
			default:
			}
		})
	}
}
