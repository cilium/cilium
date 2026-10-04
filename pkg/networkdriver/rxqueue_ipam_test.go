// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package networkdriver

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/vishvananda/netlink"

	"github.com/cilium/cilium/pkg/ipam"
	"github.com/cilium/cilium/pkg/networkdriver/rxqueue"
)

func TestRXQueueSafetyWithoutNetworkDriver(t *testing.T) {
	oldReset := resetLeasedRXQueueFlows
	t.Cleanup(func() { resetLeasedRXQueueFlows = oldReset })
	errCleanup := errors.New("unknown active lease")
	resetLeasedRXQueueFlows = func(context.Context, func(netlink.Link) (bool, error)) error { return errCleanup }
	primaryIPAM := &ipam.IPAM{}
	require.Nil(t, registerNetworkDriver(networkDriverParams{PrimaryIPAM: primaryIPAM}))
	require.ErrorIs(t, primaryIPAM.ConfigureAllocator(t.Context()), errCleanup,
		"startup cleanup must precede IPAM even when Network Driver is disabled")
}

func TestRXQueueAddressRelease(t *testing.T) {
	f := newRXQueueControllerFixture(t)
	f.allocate(nil)
	guard := &rxQueueAddressGuard{driver: f.driver}
	oldRevoke := rxQueueRevokeForIP
	t.Cleanup(func() { rxQueueRevokeForIP = oldRevoke })
	errCleanup := errors.New("rule withdrawal failed")
	var calls []netip.Addr
	rxQueueRevokeForIP = func(device *rxqueue.RXQueueDevice, address netip.Addr) (*rxqueue.RXQueueDevice, error) {
		calls = append(calls, address)
		return &rxqueue.RXQueueDevice{PhysicalIfName: device.PhysicalIfName, Prepared: true}, errCleanup
	}
	v4, v6 := netip.MustParseAddr("192.0.2.10"), netip.MustParseAddr("2001:db8::10")
	// A slow DRA prepare must not stall IPAM while it holds driver.lock.
	f.driver.lock.Lock()
	released := make(chan error, 1)
	go func() { released <- guard.BeforeRelease(v4, ipam.PoolDefault()) }()
	var releaseErr error
	select {
	case releaseErr = <-released:
	case <-time.After(5 * time.Second):
		f.driver.lock.Unlock()
		<-released
		t.Fatal("address release waited for driver.lock")
	}
	f.driver.lock.Unlock()
	require.ErrorIs(t, releaseErr, errCleanup)
	for row := range f.driver.allocationTable.All(f.db.ReadTxn()) {
		require.Nil(t, row.PreparedDevice.(*rxqueue.RXQueueDevice).Binding)
	}
	require.ErrorIs(t, guard.BeforeRelease(v4, ipam.PoolDefault()), errCleanup)
	require.ErrorIs(t, guard.BeforeRelease(v6, ipam.PoolDefault()), errCleanup)
	errCleanup = nil
	require.NoError(t, guard.BeforeRelease(v6, ipam.PoolDefault()))
	require.Equal(t, []netip.Addr{v4, v4, v6, v6}, calls)
}

func TestRXQueueAddressReleaseKeepsRepreparedAllocation(t *testing.T) {
	f := newRXQueueControllerFixture(t)
	row := f.allocate(nil)
	oldDevice := row.PreparedDevice.(*rxqueue.RXQueueDevice)
	reprepared := row.Clone()
	reprepared.PreparedDevice = &rxqueue.RXQueueDevice{
		PhysicalIfName: oldDevice.PhysicalIfName, Prepared: true, PhysicalQueueID: 6,
	}
	oldRevoke := rxQueueRevokeForIP
	t.Cleanup(func() { rxQueueRevokeForIP = oldRevoke })
	rxQueueRevokeForIP = func(device *rxqueue.RXQueueDevice, _ netip.Addr) (*rxqueue.RXQueueDevice, error) {
		require.Same(t, oldDevice, device)
		// Model unprepare/reprepare between revocation and its StateDB update.
		f.driver.deleteAllocations([]allocation{allocationFromRow(row)})
		f.driver.storeAllocations([]allocation{allocationFromRow(reprepared)}, row.PodUID, row.ClaimUID)
		return &rxqueue.RXQueueDevice{
			PhysicalIfName: device.PhysicalIfName, Prepared: true, PhysicalQueueID: 7,
		}, nil
	}
	guard := &rxQueueAddressGuard{driver: f.driver}
	require.NoError(t, guard.BeforeRelease(netip.MustParseAddr("192.0.2.10"), ipam.PoolDefault()))
	current, _, found := f.driver.allocationTable.Get(f.db.ReadTxn(),
		allocationByKey.Query(allocationTableKey(allocationFromRow(row))))
	require.True(t, found)
	require.Same(t, reprepared.PreparedDevice, current.PreparedDevice,
		"revoking an old device must not overwrite the re-prepared allocation")
}
