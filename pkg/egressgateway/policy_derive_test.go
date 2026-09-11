// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package egressgateway

import (
	"net/netip"
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/cilium/statedb"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/datapath/tables"
)

// newDeriveTestManager returns a Manager wired with in-memory device and
// node-address tables, sufficient to exercise deriveFromPolicyGatewayConfig.
func newDeriveTestManager(t *testing.T, dev *tables.Device, addrs []tables.NodeAddress) *Manager {
	t.Helper()

	db := statedb.New()
	devTable, err := tables.NewDeviceTable(db)
	require.NoError(t, err)
	addrTable, err := tables.NewNodeAddressTable(db)
	require.NoError(t, err)

	txn := db.WriteTxn(devTable, addrTable)
	_, _, err = devTable.Insert(txn, dev)
	require.NoError(t, err)
	for _, addr := range addrs {
		_, _, err = addrTable.Insert(txn, addr)
		require.NoError(t, err)
	}
	txn.Commit()

	return &Manager{
		logger:        hivetest.Logger(t),
		db:            db,
		deviceTable:   devTable,
		nodeAddrTable: addrTable,
	}
}

// TestDeriveFromPolicyGatewayConfigDualStack covers the derivation of the
// egress IPs for policies whose destinationCIDRs span both address families
// while egressGateway.egressIP explicitly configures a single address.
//
// Regression test for https://github.com/cilium/cilium/issues/48660: an
// IPv4 egressIP combined with dual-stack destinationCIDRs on a gateway
// interface without an IPv6 address must still program the IPv4 egress IP
// instead of black-holing IPv4 traffic with an all-zero entry.
func TestDeriveFromPolicyGatewayConfigDualStack(t *testing.T) {
	egressIP4 := netip.MustParseAddr("192.168.100.10")
	egressIP6 := netip.MustParseAddr("fd00::10")

	dev := &tables.Device{
		Index: 42,
		Name:  "eth1",
		Addrs: []tables.DeviceAddress{
			{Addr: egressIP4},
		},
	}
	devDual := &tables.Device{
		Index: 42,
		Name:  "eth1",
		Addrs: []tables.DeviceAddress{
			{Addr: egressIP4},
			{Addr: egressIP6},
		},
	}
	addr4 := tables.NodeAddress{Addr: egressIP4, Primary: true, DeviceName: "eth1"}
	addr6 := tables.NodeAddress{Addr: egressIP6, Primary: true, DeviceName: "eth1"}

	t.Run("IPv4 egressIP, no IPv6 on interface", func(t *testing.T) {
		manager := newDeriveTestManager(t, dev, []tables.NodeAddress{addr4})

		gwc := gatewayConfig{}
		err := gwc.deriveFromPolicyGatewayConfig(manager, &policyGatewayConfig{egressIP: egressIP4}, true, true)

		require.NoError(t, err)
		require.Equal(t, "eth1", gwc.ifaceName)
		require.Equal(t, egressIP4, gwc.egressIP4, "the explicitly configured IPv4 egress IP must be programmed")
		require.Equal(t, EgressIPNotFoundIPv6, gwc.egressIP6, "only the IPv6 side may be marked as not found")
		require.True(t, gwc.localNodeConfiguredAsGateway)
	})

	t.Run("IPv4 egressIP, IPv6 present on interface", func(t *testing.T) {
		manager := newDeriveTestManager(t, devDual, []tables.NodeAddress{addr4, addr6})

		gwc := gatewayConfig{}
		err := gwc.deriveFromPolicyGatewayConfig(manager, &policyGatewayConfig{egressIP: egressIP4}, true, true)

		require.NoError(t, err)
		require.Equal(t, egressIP4, gwc.egressIP4)
		require.Equal(t, egressIP6, gwc.egressIP6, "the IPv6 egress IP must be derived from the interface")
	})

	t.Run("IPv6 egressIP, no IPv4 on interface", func(t *testing.T) {
		devV6 := &tables.Device{
			Index: 42,
			Name:  "eth1",
			Addrs: []tables.DeviceAddress{
				{Addr: egressIP6},
			},
		}
		manager := newDeriveTestManager(t, devV6, []tables.NodeAddress{addr6})

		gwc := gatewayConfig{}
		err := gwc.deriveFromPolicyGatewayConfig(manager, &policyGatewayConfig{egressIP: egressIP6}, true, true)

		require.NoError(t, err)
		require.Equal(t, egressIP6, gwc.egressIP6, "the explicitly configured IPv6 egress IP must be programmed")
		require.Equal(t, EgressIPNotFoundIPv4, gwc.egressIP4, "only the IPv4 side may be marked as not found")
	})
}
