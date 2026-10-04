// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package rxqueue

import (
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/vishvananda/netlink"
	kube_types "k8s.io/apimachinery/pkg/types"

	ciliumnetns "github.com/cilium/cilium/pkg/netns"
)

const fakePodNetNSID = 24

type fakeQueueNetlinkHandle struct {
	peer       netlink.Link
	netlink    *fakeNetlink
	creates    []netlink.NetDevQueueCreateRequest
	netNSID    int
	setNSCalls int
}

func (h *fakeQueueNetlinkHandle) LinkByName(name string) (netlink.Link, error) {
	if h.peer != nil && h.peer.Attrs().Name == name {
		return h.peer, nil
	}
	return nil, netlink.LinkNotFoundError{}
}

func (h *fakeQueueNetlinkHandle) NetDevQueueCreate(req netlink.NetDevQueueCreateRequest) (uint32, error) {
	h.creates = append(h.creates, req)
	h.netlink.leases[req.Lease.Queue.ID] = &netlink.NetDevQueueLease{
		IfIndex: uint32(req.IfIndex),
		Queue: netlink.NetDevQueueID{
			ID:   firstLeasedRXQueueID,
			Type: netlink.NetDevQueueTypeRx,
		},
		NetNSID:    fakePodNetNSID,
		NetNSIDSet: true,
	}
	return firstLeasedRXQueueID, nil
}

func (h *fakeQueueNetlinkHandle) GetNetNsIdByFd(int) (int, error) {
	return h.netNSID, nil
}

func (h *fakeQueueNetlinkHandle) SetNetNsIdByFd(int, int) error {
	h.setNSCalls++
	h.netNSID = 42
	return nil
}

func (*fakeQueueNetlinkHandle) Close() error { return nil }

func installQueueLeaseFakes(t *testing.T, fake *fakeNetlink, peer netlink.Link) *fakeQueueNetlinkHandle {
	t.Helper()

	handle := &fakeQueueNetlinkHandle{
		peer:    peer,
		netlink: fake,
		netNSID: -1,
	}
	originalNewHandle := newQueueNetlinkHandle
	originalCurrentNS := currentNetNS
	originalIsPrimary := netkitIsPrimary
	originalHostGetNSID := hostGetNetNSIDByFD
	originalHostSetNSID := hostSetNetNSIDByFD
	hostNSID := -1
	t.Cleanup(func() {
		newQueueNetlinkHandle = originalNewHandle
		currentNetNS = originalCurrentNS
		netkitIsPrimary = originalIsPrimary
		hostGetNetNSIDByFD = originalHostGetNSID
		hostSetNetNSIDByFD = originalHostSetNSID
	})
	newQueueNetlinkHandle = func(*ciliumnetns.NetNS) (queueNetlinkHandle, error) {
		return handle, nil
	}
	currentNetNS = func() (*ciliumnetns.NetNS, error) {
		return &ciliumnetns.NetNS{}, nil
	}
	hostGetNetNSIDByFD = func(int) (int, error) { return hostNSID, nil }
	hostSetNetNSIDByFD = func(int, int) error {
		hostNSID = fakePodNetNSID
		return nil
	}
	netkitIsPrimary = func(*netlink.Netkit) bool { return false }
	return handle
}

func testPodNetkit(rxQueues int) *netlink.Netkit {
	return &netlink.Netkit{LinkAttrs: netlink.LinkAttrs{
		Name:        "eth0",
		Index:       testPeerIndex,
		NumRxQueues: rxQueues,
	}}
}

func TestLeaseRXQueueToPodNetkit(t *testing.T) {
	fake := newFakeNetlink(8, 8, testShareID)
	fake.install(t)
	handle := installQueueLeaseFakes(t, fake, testPodNetkit(2))

	advertised := testDevice(8)
	device, err := advertised.Setup(testAllocation(testShareID))
	require.NoError(t, err)
	prepared := device.(*RXQueueDevice)

	require.NoError(t, prepared.LeaseRXQueue(&ciliumnetns.NetNS{}))
	require.Len(t, handle.creates, 1)
	require.Equal(t, testPeerIndex, handle.creates[0].IfIndex)
	require.Equal(t, uint32(testPhysicalIndex), handle.creates[0].Lease.IfIndex)
	require.Equal(t, uint32(7), handle.creates[0].Lease.Queue.ID)
	require.True(t, handle.creates[0].Lease.NetNSIDSet)
	require.Equal(t, int32(42), handle.creates[0].Lease.NetNSID)
	require.Equal(t, 1, handle.setNSCalls)

	require.NoError(t, prepared.LeaseRXQueue(&ciliumnetns.NetNS{}))
	require.Len(t, handle.creates, 1, "an existing lease is adopted")

	require.ErrorIs(t, prepared.Free(testAllocation(testShareID)), errActiveLease)
	delete(fake.leases, uint32(7))
	require.NoError(t, prepared.Free(testAllocation(testShareID)))

	nextShare := kube_types.UID("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee")
	next, err := advertised.Setup(testAllocation(nextShare))
	require.NoError(t, err)
	require.Equal(t, uint32(7), next.(*RXQueueDevice).PhysicalQueueID)
}

func TestLeaseRXQueueValidatesPodNetkit(t *testing.T) {
	setup := func(t *testing.T, peer netlink.Link) (*fakeNetlink, *RXQueueDevice) {
		fake := newFakeNetlink(8, 8, testShareID)
		fake.install(t)
		installQueueLeaseFakes(t, fake, peer)
		device, err := testDevice(8).Setup(testAllocation(testShareID))
		require.NoError(t, err)
		return fake, device.(*RXQueueDevice)
	}

	t.Run("requires a netkit peer", func(t *testing.T) {
		_, device := setup(t, &netlink.Veth{LinkAttrs: netlink.LinkAttrs{Name: "eth0", NumRxQueues: 2}})
		require.ErrorIs(t, device.LeaseRXQueue(&ciliumnetns.NetNS{}), errInvalidAllocation)
	})

	t.Run("requires queue capacity", func(t *testing.T) {
		_, device := setup(t, testPodNetkit(1))
		require.ErrorContains(t, device.LeaseRXQueue(&ciliumnetns.NetNS{}), "does not have capacity")
	})

	t.Run("rejects a competing lease", func(t *testing.T) {
		fake, device := setup(t, testPodNetkit(2))
		fake.leases[7] = &netlink.NetDevQueueLease{
			IfIndex:    testPeerIndex,
			NetNSID:    fakePodNetNSID + 1,
			NetNSIDSet: true,
			Queue: netlink.NetDevQueueID{
				ID:   firstLeasedRXQueueID,
				Type: netlink.NetDevQueueTypeRx,
			},
		}
		require.ErrorIs(t, device.LeaseRXQueue(&ciliumnetns.NetNS{}), errNoAvailableRXQueue)
	})
}
