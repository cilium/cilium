// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package rxqueue

import (
	"context"
	"errors"
	"net"
	"slices"
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
	links          map[string]netlink.Link
	leases         map[uint32]*netlink.NetDevQueueLease
	realRXQueues   int
	rss            netlink.NetDevRSS
	rings          netlink.NetDevRings
	rssSetCalls    []netlink.NetDevRSSConfig
	ringsSetCalls  []netlink.NetDevRingsConfig
	rssSetError    error
	ringsSetError  error
	ignoreRSSSet   bool
	ignoreRingsSet bool
}

func newFakeNetlink(maxRXQueues, realRXQueues int, _ ...kube_types.UID) *fakeNetlink {
	hwAddr, _ := net.ParseMAC("02:00:00:00:00:01")
	physical := &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{
		Name:         testPhysicalIfName,
		Index:        testPhysicalIndex,
		MTU:          9000,
		HardwareAddr: hwAddr,
		Flags:        net.FlagUp,
		NumRxQueues:  maxRXQueues,
	}}
	indirectionTable := make([]uint32, realRXQueues*2)
	for i := range indirectionTable {
		indirectionTable[i] = uint32(i % realRXQueues)
	}
	return &fakeNetlink{
		links: map[string]netlink.Link{
			testPhysicalIfName: physical,
		},
		leases:       make(map[uint32]*netlink.NetDevQueueLease),
		realRXQueues: realRXQueues,
		rss: netlink.NetDevRSS{
			HashFunction:        netlink.NetDevRSSHashFunctionToeplitz,
			IndirectionTable:    indirectionTable,
			HashKey:             []byte{1, 2, 3, 4},
			InputTransformation: netlink.NetDevRSSInputTransformationNone,
		},
		rings: netlink.NetDevRings{
			RxMax:           4096,
			TxMax:           4096,
			Rx:              512,
			Tx:              512,
			TCPDataSplit:    netlink.NetDevTCPDataSplitDisabled,
			HDSThresholdMax: 4096,
		},
	}
}

func (f *fakeNetlink) install(t *testing.T) {
	t.Helper()

	originalLinkByName := netlinkLinkByName
	originalQueueGet := netlinkNetDevQueueGet
	originalRSSGet := netlinkNetDevRSSGet
	originalRSSSet := netlinkNetDevRSSSet
	originalRingsGet := netlinkNetDevRingsGet
	originalRingsSet := netlinkNetDevRingsSet
	t.Cleanup(func() {
		netlinkLinkByName = originalLinkByName
		netlinkNetDevQueueGet = originalQueueGet
		netlinkNetDevRSSGet = originalRSSGet
		netlinkNetDevRSSSet = originalRSSSet
		netlinkNetDevRingsGet = originalRingsGet
		netlinkNetDevRingsSet = originalRingsSet
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
		return &netlink.NetDevQueue{IfIndex: uint32(ifIndex), ID: queueID, Type: queueType, Lease: f.leases[queueID]}, nil
	}
	netlinkNetDevRSSGet = func(ifIndex int, context uint32) (*netlink.NetDevRSS, error) {
		if ifIndex != testPhysicalIndex {
			return nil, unix.ENODEV
		}
		if context != mainRSSContext {
			return nil, unix.EINVAL
		}
		return cloneNetDevRSS(&f.rss), nil
	}
	netlinkNetDevRSSSet = func(ifIndex int, context uint32, config netlink.NetDevRSSConfig) error {
		if ifIndex != testPhysicalIndex {
			return unix.ENODEV
		}
		if context != mainRSSContext {
			return unix.EINVAL
		}
		config.IndirectionTable = slices.Clone(config.IndirectionTable)
		config.HashKey = slices.Clone(config.HashKey)
		f.rssSetCalls = append(f.rssSetCalls, config)
		if f.rssSetError != nil {
			return f.rssSetError
		}
		if !f.ignoreRSSSet && config.IndirectionTable != nil {
			f.rss.IndirectionTable = slices.Clone(config.IndirectionTable)
		}
		return nil
	}
	netlinkNetDevRingsGet = func(ifIndex int) (*netlink.NetDevRings, error) {
		if ifIndex != testPhysicalIndex {
			return nil, unix.ENODEV
		}
		rings := f.rings
		return &rings, nil
	}
	netlinkNetDevRingsSet = func(ifIndex int, config netlink.NetDevRingsConfig) error {
		if ifIndex != testPhysicalIndex {
			return unix.ENODEV
		}
		f.ringsSetCalls = append(f.ringsSetCalls, config)
		if f.ringsSetError != nil {
			return f.ringsSetError
		}
		if !f.ignoreRingsSet && config.TCPDataSplit != nil {
			f.rings.TCPDataSplit = *config.TCPDataSplit
		}
		if !f.ignoreRingsSet && config.HDSThreshold != nil {
			f.rings.HDSThreshold = *config.HDSThreshold
		}
		return nil
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

func TestRSSTableWithoutReservedQueues(t *testing.T) {
	t.Run("reassigns only reserved queues", func(t *testing.T) {
		table := []uint32{0, 0, 3, 3, 1, 2, 3, 3}

		got, err := rssTableWithoutReservedQueues(table, 4, []uint32{3})
		require.NoError(t, err)
		require.Equal(t, []uint32{0, 0, 1, 2, 1, 2, 0, 1}, got)
		require.Equal(t, []uint32{0, 0, 3, 3, 1, 2, 3, 3}, table)
	})

	t.Run("does not introduce an unused queue", func(t *testing.T) {
		table := []uint32{0, 3, 0, 3}

		got, err := rssTableWithoutReservedQueues(table, 4, []uint32{3})
		require.NoError(t, err)
		require.Equal(t, []uint32{0, 0, 0, 0}, got)
	})

	t.Run("leaves an isolated table unchanged", func(t *testing.T) {
		table := []uint32{0, 1, 2, 0}

		got, err := rssTableWithoutReservedQueues(table, 4, []uint32{3})
		require.NoError(t, err)
		require.Equal(t, table, got)
		got[0] = 2
		require.Equal(t, uint32(0), table[0])
	})

	t.Run("rejects an empty table", func(t *testing.T) {
		_, err := rssTableWithoutReservedQueues(nil, 4, []uint32{3})
		require.Error(t, err)
	})

	t.Run("rejects an out-of-range table entry", func(t *testing.T) {
		_, err := rssTableWithoutReservedQueues([]uint32{0, 4}, 4, []uint32{3})
		require.Error(t, err)
	})

	t.Run("requires a normal receive queue", func(t *testing.T) {
		_, err := rssTableWithoutReservedQueues([]uint32{0, 1}, 2, []uint32{0, 1})
		require.Error(t, err)
	})

	t.Run("rejects duplicate reserved queues", func(t *testing.T) {
		_, err := rssTableWithoutReservedQueues([]uint32{0, 1}, 2, []uint32{1, 1})
		require.Error(t, err)
	})
}

func TestNewManager(t *testing.T) {
	t.Run("leaves one queue for normal receive processing", func(t *testing.T) {
		fake := newFakeNetlink(8, 1, testShareID)
		fake.install(t)

		_, err := NewManager(hivetest.Logger(t), &v2alpha1.RXQueueDeviceManagerConfig{
			Ifaces: []v2alpha1.RXQueueDeviceConfig{{IfName: testPhysicalIfName}},
		})
		require.ErrorIs(t, err, errInsufficientRXQueues)
	})

	t.Run("defaults to one reserved queue", func(t *testing.T) {
		fake := newFakeNetlink(16, 2, testShareID)
		fake.install(t)

		mgr, err := NewManager(hivetest.Logger(t), &v2alpha1.RXQueueDeviceManagerConfig{
			Ifaces: []v2alpha1.RXQueueDeviceConfig{{IfName: testPhysicalIfName}},
		})
		require.NoError(t, err)
		require.Equal(t, types.DeviceManagerTypeRXQueue, mgr.Type())

		devices := publishedDevices(t, mgr)
		require.Len(t, devices, 1)

		dev := devices[0].(*RXQueueDevice)
		require.Equal(t, []uint32{1}, dev.ReservedQueueIDs)
		require.Equal(t, testPhysicalIfName, dev.IfName())
		require.True(t, dev.AllowMultipleAllocations())

		capacity := dev.GetCapacity()[types.RXQueuesCapacity]
		require.Zero(t, capacity.Value.Cmp(apiresource.MustParse("1")))
		require.NotNil(t, capacity.RequestPolicy)
		require.Equal(t, []apiresource.Quantity{apiresource.MustParse("1")}, capacity.RequestPolicy.ValidValues)
	})

	t.Run("advertises configured reserved capacity", func(t *testing.T) {
		fake := newFakeNetlink(16, 8, testShareID)
		fake.install(t)

		mgr, err := NewManager(hivetest.Logger(t), &v2alpha1.RXQueueDeviceManagerConfig{
			Ifaces: []v2alpha1.RXQueueDeviceConfig{{IfName: testPhysicalIfName, Count: 3}},
		})
		require.NoError(t, err)

		devices := publishedDevices(t, mgr)
		dev := devices[0].(*RXQueueDevice)
		require.Equal(t, []uint32{7, 6, 5}, dev.ReservedQueueIDs)

		capacity := dev.GetCapacity()[types.RXQueuesCapacity]
		require.Zero(t, capacity.Value.Cmp(apiresource.MustParse("3")))
	})

	t.Run("programs and verifies NIC receive configuration", func(t *testing.T) {
		fake := newFakeNetlink(8, 4, testShareID)
		fake.rss.IndirectionTable = []uint32{0, 3, 1, 3, 2, 3}
		originalHashKey := slices.Clone(fake.rss.HashKey)
		fake.install(t)

		_, err := NewManager(hivetest.Logger(t), &v2alpha1.RXQueueDeviceManagerConfig{
			Ifaces: []v2alpha1.RXQueueDeviceConfig{{IfName: testPhysicalIfName}},
		})
		require.NoError(t, err)
		require.Equal(t, []uint32{0, 0, 1, 1, 2, 2}, fake.rss.IndirectionTable)
		require.Equal(t, originalHashKey, fake.rss.HashKey)
		require.Equal(t, netlink.NetDevTCPDataSplitEnabled, fake.rings.TCPDataSplit)
		require.Len(t, fake.rssSetCalls, 1)
		require.Len(t, fake.ringsSetCalls, 1)
	})

	t.Run("accepts an already prepared NIC without writing", func(t *testing.T) {
		fake := newFakeNetlink(8, 4, testShareID)
		fake.rss.IndirectionTable = []uint32{0, 1, 2, 0}
		fake.rings.TCPDataSplit = netlink.NetDevTCPDataSplitEnabled
		fake.install(t)

		_, err := NewManager(hivetest.Logger(t), &v2alpha1.RXQueueDeviceManagerConfig{
			Ifaces: []v2alpha1.RXQueueDeviceConfig{{IfName: testPhysicalIfName}},
		})
		require.NoError(t, err)
		require.Empty(t, fake.rssSetCalls)
		require.Empty(t, fake.ringsSetCalls)
	})

	t.Run("enables TCP data splitting when the driver does not report it", func(t *testing.T) {
		fake := newFakeNetlink(8, 4, testShareID)
		fake.rings.TCPDataSplit = netlink.NetDevTCPDataSplitUnknown
		fake.rings.HDSThreshold = 256
		fake.install(t)

		_, err := NewManager(hivetest.Logger(t), &v2alpha1.RXQueueDeviceManagerConfig{
			Ifaces: []v2alpha1.RXQueueDeviceConfig{{IfName: testPhysicalIfName}},
		})
		require.NoError(t, err)
		require.Equal(t, netlink.NetDevTCPDataSplitEnabled, fake.rings.TCPDataSplit)
		require.Zero(t, fake.rings.HDSThreshold)
	})

	t.Run("does not change rings when the RSS update fails", func(t *testing.T) {
		fake := newFakeNetlink(8, 4, testShareID)
		originalRSS := cloneNetDevRSS(&fake.rss)
		boom := errors.New("RSS update failed")
		fake.rssSetError = boom
		fake.install(t)

		_, err := NewManager(hivetest.Logger(t), &v2alpha1.RXQueueDeviceManagerConfig{
			Ifaces: []v2alpha1.RXQueueDeviceConfig{{IfName: testPhysicalIfName}},
		})
		require.ErrorIs(t, err, boom)
		require.True(t, equalNetDevRSS(originalRSS, &fake.rss))
		require.Equal(t, netlink.NetDevTCPDataSplitDisabled, fake.rings.TCPDataSplit)
		require.Len(t, fake.rssSetCalls, 1)
		require.Empty(t, fake.ringsSetCalls)
	})

	t.Run("restores RSS when enabling TCP data splitting fails", func(t *testing.T) {
		fake := newFakeNetlink(8, 4, testShareID)
		fake.rss.IndirectionTable = []uint32{0, 3, 1, 3, 2, 3}
		originalRSS := cloneNetDevRSS(&fake.rss)
		boom := errors.New("ring update failed")
		fake.ringsSetError = boom
		fake.install(t)

		_, err := NewManager(hivetest.Logger(t), &v2alpha1.RXQueueDeviceManagerConfig{
			Ifaces: []v2alpha1.RXQueueDeviceConfig{{IfName: testPhysicalIfName}},
		})
		require.ErrorIs(t, err, boom)
		require.True(t, equalNetDevRSS(originalRSS, &fake.rss))
		require.Equal(t, netlink.NetDevTCPDataSplitDisabled, fake.rings.TCPDataSplit)
		require.Len(t, fake.rssSetCalls, 2)
		require.Len(t, fake.ringsSetCalls, 1)
	})

	t.Run("restores both settings when readback does not match", func(t *testing.T) {
		fake := newFakeNetlink(8, 4, testShareID)
		fake.rss.IndirectionTable = []uint32{0, 3, 1, 3, 2, 3}
		originalRSS := cloneNetDevRSS(&fake.rss)
		originalRings := fake.rings
		fake.ignoreRingsSet = true
		fake.install(t)

		_, err := NewManager(hivetest.Logger(t), &v2alpha1.RXQueueDeviceManagerConfig{
			Ifaces: []v2alpha1.RXQueueDeviceConfig{{IfName: testPhysicalIfName}},
		})
		require.Error(t, err)
		require.Contains(t, err.Error(), "ring configuration read back incorrectly")
		require.True(t, equalNetDevRSS(originalRSS, &fake.rss))
		require.Equal(t, originalRings, fake.rings)
		require.Len(t, fake.rssSetCalls, 2)
		require.Len(t, fake.ringsSetCalls, 2)
	})

	t.Run("restores both settings when RSS readback does not match", func(t *testing.T) {
		fake := newFakeNetlink(8, 4, testShareID)
		originalRSS := cloneNetDevRSS(&fake.rss)
		originalRings := fake.rings
		fake.ignoreRSSSet = true
		fake.install(t)

		_, err := NewManager(hivetest.Logger(t), &v2alpha1.RXQueueDeviceManagerConfig{
			Ifaces: []v2alpha1.RXQueueDeviceConfig{{IfName: testPhysicalIfName}},
		})
		require.Error(t, err)
		require.Contains(t, err.Error(), "RSS configuration read back incorrectly")
		require.True(t, equalNetDevRSS(originalRSS, &fake.rss))
		require.Equal(t, originalRings, fake.rings)
		require.Len(t, fake.rssSetCalls, 2)
		require.Len(t, fake.ringsSetCalls, 2)
	})

	t.Run("restores earlier NICs when later discovery fails", func(t *testing.T) {
		fake := newFakeNetlink(8, 4, testShareID)
		originalRSS := cloneNetDevRSS(&fake.rss)
		originalRings := fake.rings
		fake.links["eth1"] = &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{
			Name:        "eth1",
			Index:       testPhysicalIndex + 1,
			Flags:       net.FlagUp,
			NumRxQueues: 4,
		}}
		fake.install(t)

		firstQueueGet := netlinkNetDevQueueGet
		boom := errors.New("second NIC failed")
		netlinkNetDevQueueGet = func(ifIndex int, queueID uint32, queueType netlink.NetDevQueueType) (*netlink.NetDevQueue, error) {
			if ifIndex == testPhysicalIndex+1 {
				return nil, boom
			}
			return firstQueueGet(ifIndex, queueID, queueType)
		}

		_, err := NewManager(hivetest.Logger(t), &v2alpha1.RXQueueDeviceManagerConfig{
			Ifaces: []v2alpha1.RXQueueDeviceConfig{
				{IfName: testPhysicalIfName},
				{IfName: "eth1"},
			},
		})
		require.ErrorIs(t, err, boom)
		require.True(t, equalNetDevRSS(originalRSS, &fake.rss))
		require.Equal(t, originalRings, fake.rings)
		require.Len(t, fake.rssSetCalls, 2)
		require.Len(t, fake.ringsSetCalls, 2)
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
