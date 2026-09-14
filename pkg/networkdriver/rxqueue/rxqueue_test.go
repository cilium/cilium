// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package rxqueue

import (
	"context"
	"errors"
	"net"
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
	resourceapi "k8s.io/api/resource/v1"
	apiresource "k8s.io/apimachinery/pkg/api/resource"
	kube_types "k8s.io/apimachinery/pkg/types"

	"github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	"github.com/cilium/cilium/pkg/networkdriver/types"
)

const (
	testPhysicalIfName = "eth0"
	testPhysicalIndex  = 10
	testShareID        = kube_types.UID("11111111-2222-3333-4444-555555555555")
)

func publishedDevices(t *testing.T, mgr *RXQueueManager) []types.Device {
	t.Helper()
	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	var devices []types.Device
	require.NoError(t, mgr.Run(ctx, func(current []types.Device) {
		devices = current
	}))
	return devices
}

type fakeNetlink struct {
	links        map[string]netlink.Link
	leases       map[uint32]*netlink.NetDevQueueLease
	realRXQueues int
}

func newFakeNetlink(maxRXQueues, realRXQueues int) *fakeNetlink {
	hwAddr, _ := net.ParseMAC("02:00:00:00:00:01")
	physical := &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{
		Name:         testPhysicalIfName,
		Index:        testPhysicalIndex,
		MTU:          9000,
		HardwareAddr: hwAddr,
		Flags:        net.FlagUp,
		NumRxQueues:  maxRXQueues,
	}}
	return &fakeNetlink{
		links: map[string]netlink.Link{
			testPhysicalIfName: physical,
		},
		leases:       make(map[uint32]*netlink.NetDevQueueLease),
		realRXQueues: realRXQueues,
	}
}

func (f *fakeNetlink) install(t *testing.T) {
	t.Helper()

	originalLinkByName := netlinkLinkByName
	originalQueueGet := netlinkNetDevQueueGet
	t.Cleanup(func() {
		netlinkLinkByName = originalLinkByName
		netlinkNetDevQueueGet = originalQueueGet
	})

	netlinkLinkByName = func(name string) (netlink.Link, error) {
		link, exists := f.links[name]
		if !exists {
			return nil, netlink.LinkNotFoundError{}
		}
		return link, nil
	}
	netlinkNetDevQueueGet = func(ifIndex int, queueID uint32, queueType netlink.NetDevQueueType) (*netlink.NetDevQueue, error) {
		if ifIndex != testPhysicalIndex {
			return nil, unix.ENODEV
		}
		if queueType != netlink.NetDevQueueTypeRx || int(queueID) >= f.realRXQueues {
			return nil, unix.EINVAL
		}
		return &netlink.NetDevQueue{
			IfIndex: uint32(ifIndex),
			ID:      queueID,
			Type:    queueType,
			Lease:   f.leases[queueID],
		}, nil
	}
}

func testDeviceWithCount(total, count int) *RXQueueDevice {
	return &RXQueueDevice{
		PhysicalIfName:   testPhysicalIfName,
		HardwareAddress:  "02:00:00:00:00:01",
		MTU:              9000,
		TotalRXQueues:    total,
		ReservedQueueIDs: reservedRXQueueIDs(total, count),
		reservations:     &queueReservations{owners: make(map[uint32]kube_types.UID)},
	}
}

func testAllocation(shareID kube_types.UID) types.DeviceAllocation {
	return types.DeviceAllocation{
		ShareID: shareID,
		ConsumedCapacity: map[resourceapi.QualifiedName]apiresource.Quantity{
			types.RXQueuesCapacity: apiresource.MustParse("1"),
		},
	}
}

func TestReservedRXQueueIDs(t *testing.T) {
	tests := []struct {
		total int
		count int
		want  []uint32
	}{
		{total: 0, count: 1},
		{total: 1, count: 1},
		{total: 8, count: 0},
		{total: 8, count: 8},
		{total: 2, count: 1, want: []uint32{1}},
		{total: 4, count: 3, want: []uint32{3, 2, 1}},
		{total: 64, count: 4, want: []uint32{63, 62, 61, 60}},
	}

	for _, tt := range tests {
		require.Equal(t, tt.want, reservedRXQueueIDs(tt.total, tt.count),
			"total RX queues: %d, reserved: %d", tt.total, tt.count)
	}
}

func TestValidateConfig(t *testing.T) {
	require.ErrorIs(t, validateConfig(nil), errNoInterfaces)
	require.ErrorIs(t, validateConfig(&v2alpha1.RXQueueDeviceManagerConfig{}), errNoInterfaces)
	require.Error(t, validateConfig(&v2alpha1.RXQueueDeviceManagerConfig{
		Ifaces: []v2alpha1.RXQueueDeviceConfig{{IfName: ""}},
	}))
	require.Error(t, validateConfig(&v2alpha1.RXQueueDeviceManagerConfig{
		Ifaces: []v2alpha1.RXQueueDeviceConfig{{IfName: "lo"}},
	}))
	require.Error(t, validateConfig(&v2alpha1.RXQueueDeviceManagerConfig{
		Ifaces: []v2alpha1.RXQueueDeviceConfig{{IfName: "eth0", Count: -1}},
	}))
	require.ErrorIs(t, validateConfig(&v2alpha1.RXQueueDeviceManagerConfig{
		Ifaces: []v2alpha1.RXQueueDeviceConfig{{IfName: "eth0"}, {IfName: "eth0"}},
	}), errDuplicateInterface)
	require.NoError(t, validateConfig(&v2alpha1.RXQueueDeviceManagerConfig{
		Ifaces: []v2alpha1.RXQueueDeviceConfig{{IfName: "eth0"}, {IfName: "eth1"}},
	}))
}

func TestActiveRXQueueCount(t *testing.T) {
	t.Run("uses real queue count", func(t *testing.T) {
		fake := newFakeNetlink(16, 12)
		fake.install(t)

		count, err := activeRXQueueCount(fake.links[testPhysicalIfName])
		require.NoError(t, err)
		require.Equal(t, 12, count)
	})

	t.Run("interface must be up", func(t *testing.T) {
		fake := newFakeNetlink(8, 8)
		fake.install(t)
		fake.links[testPhysicalIfName].Attrs().Flags = 0

		_, err := activeRXQueueCount(fake.links[testPhysicalIfName])
		require.ErrorContains(t, err, "down")
	})

	t.Run("queue error is returned", func(t *testing.T) {
		fake := newFakeNetlink(8, 8)
		fake.install(t)
		boom := errors.New("queue query failed")
		netlinkNetDevQueueGet = func(int, uint32, netlink.NetDevQueueType) (*netlink.NetDevQueue, error) {
			return nil, boom
		}

		_, err := activeRXQueueCount(fake.links[testPhysicalIfName])
		require.ErrorIs(t, err, boom)
	})
}

func TestNewManager(t *testing.T) {
	t.Run("leaves one queue for normal receive processing", func(t *testing.T) {
		fake := newFakeNetlink(8, 1)
		fake.install(t)

		_, err := NewManager(hivetest.Logger(t), &v2alpha1.RXQueueDeviceManagerConfig{
			Ifaces: []v2alpha1.RXQueueDeviceConfig{{IfName: testPhysicalIfName}},
		})
		require.ErrorIs(t, err, errInsufficientRXQueues)
	})

	t.Run("publishes configured capacity", func(t *testing.T) {
		fake := newFakeNetlink(16, 8)
		fake.install(t)

		mgr, err := NewManager(hivetest.Logger(t), &v2alpha1.RXQueueDeviceManagerConfig{
			Ifaces: []v2alpha1.RXQueueDeviceConfig{{IfName: testPhysicalIfName, Count: 3}},
		})
		require.NoError(t, err)
		require.Equal(t, types.DeviceManagerTypeRXQueue, mgr.Type())

		devices := publishedDevices(t, mgr)
		require.Len(t, devices, 1)
		dev := devices[0].(*RXQueueDevice)
		require.Equal(t, []uint32{7, 6, 5}, dev.ReservedQueueIDs)
		require.Equal(t, testPhysicalIfName, dev.IfName())
		require.True(t, dev.AllowMultipleAllocations())

		capacity := dev.GetCapacity()[types.RXQueuesCapacity]
		require.Zero(t, capacity.Value.Cmp(apiresource.MustParse("3")))
		require.Equal(t, []apiresource.Quantity{apiresource.MustParse("1")}, capacity.RequestPolicy.ValidValues)
	})
}

func TestRXQueueReservations(t *testing.T) {
	fake := newFakeNetlink(8, 8)
	fake.install(t)
	advertised := testDeviceWithCount(8, 2)
	first := testAllocation(testShareID)
	second := testAllocation(kube_types.UID("second"))
	third := testAllocation(kube_types.UID("third"))

	preparedFirst, err := advertised.Setup(first)
	require.NoError(t, err)
	firstDev := preparedFirst.(*RXQueueDevice)
	require.EqualValues(t, 7, firstDev.PhysicalQueueID)
	require.Equal(t, types.DefaultRXQueuePodIfName, firstDev.PodIfName)
	require.EqualValues(t, firstLeasedRXQueueID, firstDev.VirtualQueueID)

	repeated, err := advertised.Setup(first)
	require.NoError(t, err)
	require.Equal(t, firstDev.PhysicalQueueID, repeated.(*RXQueueDevice).PhysicalQueueID)

	preparedSecond, err := advertised.Setup(second)
	require.NoError(t, err)
	require.EqualValues(t, 6, preparedSecond.(*RXQueueDevice).PhysicalQueueID)

	_, err = advertised.Setup(third)
	require.ErrorIs(t, err, errNoAvailableRXQueue)

	require.NoError(t, firstDev.Free(first))
	preparedThird, err := advertised.Setup(third)
	require.NoError(t, err)
	require.EqualValues(t, 7, preparedThird.(*RXQueueDevice).PhysicalQueueID)
}

func TestRXQueueReservationSkipsKernelLease(t *testing.T) {
	fake := newFakeNetlink(8, 8)
	fake.leases[7] = &netlink.NetDevQueueLease{IfIndex: 99}
	fake.install(t)

	prepared, err := testDeviceWithCount(8, 2).Setup(testAllocation(testShareID))
	require.NoError(t, err)
	require.EqualValues(t, 6, prepared.(*RXQueueDevice).PhysicalQueueID)
}

func TestRXQueueFreeRejectsActiveLease(t *testing.T) {
	fake := newFakeNetlink(8, 8)
	fake.install(t)
	allocation := testAllocation(testShareID)

	prepared, err := testDeviceWithCount(8, 1).Setup(allocation)
	require.NoError(t, err)
	dev := prepared.(*RXQueueDevice)
	fake.leases[dev.PhysicalQueueID] = &netlink.NetDevQueueLease{IfIndex: 99}

	require.ErrorIs(t, dev.Free(allocation), errActiveLease)
	require.Equal(t, testShareID, dev.reservations.owners[dev.PhysicalQueueID])
}

func TestRecoverRXQueueReservation(t *testing.T) {
	fake := newFakeNetlink(8, 8)
	fake.install(t)
	allocation := testAllocation(testShareID)
	allocation.Config.PodIfName = "net1"

	prepared, err := testDeviceWithCount(8, 1).Setup(allocation)
	require.NoError(t, err)
	data, err := prepared.MarshalBinary()
	require.NoError(t, err)

	mgr := &RXQueueManager{reservations: make(map[string]*queueReservations)}
	restored, err := mgr.RestoreDevice(data)
	require.NoError(t, err)
	recovered, err := restored.Recover(allocation)
	require.NoError(t, err)
	require.Equal(t, prepared.(*RXQueueDevice).PhysicalQueueID, recovered.(*RXQueueDevice).PhysicalQueueID)

	wrongShare := allocation
	wrongShare.ShareID = "different"
	_, err = restored.Recover(wrongShare)
	require.ErrorIs(t, err, errInvalidAllocation)

	wrongInterface := allocation
	wrongInterface.Config.PodIfName = "net2"
	_, err = restored.Recover(wrongInterface)
	require.ErrorIs(t, err, errInvalidAllocation)
}

func TestDeviceMetadataAndSerialization(t *testing.T) {
	dev := testDeviceWithCount(8, 2)
	fake := newFakeNetlink(8, 8)
	fake.install(t)

	attrs := dev.GetAttrs()
	require.Equal(t, testPhysicalIfName, *attrs[types.IfNameLabel].StringValue)
	require.Equal(t, "02:00:00:00:00:01", *attrs[types.HWAddrLabel].StringValue)
	require.NotContains(t, attrs, types.RXQueueIDLabel)

	allocation := testAllocation(testShareID)
	allocation.Config.PodIfName = "net1"
	prepared, err := dev.Setup(allocation)
	require.NoError(t, err)
	preparedDev := prepared.(*RXQueueDevice)
	attrs = preparedDev.GetAttrs()
	require.EqualValues(t, firstLeasedRXQueueID, *attrs[types.RXQueueIDLabel].IntValue)
	require.Equal(t, "net1", preparedDev.IfName())

	data, err := preparedDev.MarshalBinary()
	require.NoError(t, err)
	var restored RXQueueDevice
	require.NoError(t, restored.UnmarshalBinary(data))
	require.Equal(t, preparedDev.PhysicalIfName, restored.PhysicalIfName)
	require.Equal(t, preparedDev.ReservedQueueIDs, restored.ReservedQueueIDs)
	require.Equal(t, preparedDev.ShareID, restored.ShareID)
	require.Equal(t, preparedDev.PodIfName, restored.PodIfName)
	require.Equal(t, preparedDev.PhysicalQueueID, restored.PhysicalQueueID)
	require.Equal(t, preparedDev.VirtualQueueID, restored.VirtualQueueID)
}

func TestValidateAllocation(t *testing.T) {
	valid := testAllocation(testShareID)
	require.NoError(t, validateAllocation(valid))

	missingShare := valid
	missingShare.ShareID = ""
	require.ErrorIs(t, validateAllocation(missingShare), errInvalidAllocation)

	missingCapacity := valid
	missingCapacity.ConsumedCapacity = nil
	require.ErrorIs(t, validateAllocation(missingCapacity), errInvalidAllocation)

	wrongCapacity := valid
	wrongCapacity.ConsumedCapacity = map[resourceapi.QualifiedName]apiresource.Quantity{
		types.RXQueuesCapacity: apiresource.MustParse("2"),
	}
	require.ErrorIs(t, validateAllocation(wrongCapacity), errInvalidAllocation)
}
