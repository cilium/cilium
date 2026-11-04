// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package rxqueue

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
	corev1 "k8s.io/api/core/v1"
	kube_types "k8s.io/apimachinery/pkg/types"

	ciliumnetns "github.com/cilium/cilium/pkg/netns"
	"github.com/cilium/cilium/pkg/networkdriver/types"
)

const fakePodNetNSID = 24

type fakeQueueNetlinkHandle struct {
	peer         netlink.Link
	netlink      *fakeNetlink
	creates      []netlink.NetDevQueueCreateRequest
	netNSID      int
	setNSCalls   int
	beforeCreate func()
}

func (h *fakeQueueNetlinkHandle) LinkByName(name string) (netlink.Link, error) {
	if h.peer != nil && h.peer.Attrs().Name == name {
		return h.peer, nil
	}
	return nil, netlink.LinkNotFoundError{}
}

func (h *fakeQueueNetlinkHandle) NetDevQueueCreate(req netlink.NetDevQueueCreateRequest) (uint32, error) {
	if h.beforeCreate != nil {
		h.beforeCreate()
	}
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

func TestBindRXQueueToPodNetkit(t *testing.T) {
	fake := newFakeNetlink(8, 8, testShareID)
	fake.install(t)
	handle := installQueueLeaseFakes(t, fake, testPodNetkit(2))

	advertised := testDevice(8)
	device, err := advertised.Setup(testAllocation(testShareID))
	require.NoError(t, err)
	prepared := device.(*RXQueueDevice)

	flow := testFlow("192.0.2.10", 9000, corev1.ProtocolTCP)
	require.NoError(t, syncRXFlows(testPhysicalIfName, 7, []types.RXQueueFlow{flow}))
	handle.beforeCreate = func() { require.Empty(t, fake.flows, "clear rules before exposing the lease") }
	addresses := []netip.Addr{flow.DestinationIP}
	bound, err := prepared.BindRXQueue(&ciliumnetns.NetNS{}, "sandbox-a:eth0", addresses)
	require.NoError(t, err)
	require.Equal(t, uint64(1), bound.Binding.Generation)
	require.Nil(t, prepared.Binding, "published snapshots must not be mutated")
	addresses[0] = netip.MustParseAddr("192.0.2.99")
	require.Equal(t, flow.DestinationIP, bound.Binding.Addresses[0])
	require.Len(t, handle.creates, 1)
	require.Equal(t, testPeerIndex, handle.creates[0].IfIndex)
	require.Equal(t, uint32(testPhysicalIndex), handle.creates[0].Lease.IfIndex)
	require.Equal(t, uint32(7), handle.creates[0].Lease.Queue.ID)
	require.True(t, handle.creates[0].Lease.NetNSIDSet)
	require.Equal(t, int32(42), handle.creates[0].Lease.NetNSID)
	require.Equal(t, 1, handle.setNSCalls)

	require.NoError(t, bound.SyncRXFlows(testShareID, 7, bound.Binding.Generation, []types.RXQueueFlow{flow}))
	binding := prepared.reservations.queues[7].binding
	_, err = advertised.Setup(testAllocation(testShareID))
	require.NoError(t, err)
	require.Same(t, binding, prepared.reservations.queues[7].binding, "repeated reserve preserves the binding")
	require.NoError(t, prepared.restoreReservation())
	require.Same(t, binding, prepared.reservations.queues[7].binding, "repeated restore preserves the binding")
	deletes := fake.flowDeletes
	boundAgain, err := prepared.BindRXQueue(&ciliumnetns.NetNS{}, "sandbox-a:eth0", []netip.Addr{flow.DestinationIP})
	require.NoError(t, err)
	require.Equal(t, bound.Binding, boundAgain.Binding)
	require.Equal(t, deletes, fake.flowDeletes, "a healthy binding keeps its rules")
	require.Len(t, handle.creates, 1, "an existing lease is adopted")
	serialized, err := bound.MarshalBinary()
	require.NoError(t, err)
	require.NotContains(t, string(serialized), "sandbox-a", "runtime bindings are not allocation recovery authority")
	restored := bound.clone()
	require.NoError(t, restored.UnmarshalBinary(serialized))
	require.Nil(t, restored.Binding)

	require.ErrorIs(t, prepared.Free(testAllocation(testShareID)), errActiveLease)
	delete(fake.leases, uint32(7))
	require.NoError(t, prepared.Free(testAllocation(testShareID)))
	require.Empty(t, fake.flows, "Free removes rules without a stop notification")
	require.NotContains(t, prepared.reservations.queues, uint32(7))

	nextShare := kube_types.UID("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee")
	next, err := advertised.Setup(testAllocation(nextShare))
	require.NoError(t, err)
	require.Equal(t, uint32(7), next.(*RXQueueDevice).PhysicalQueueID)
}

func TestBindRXQueueValidatesPodNetkit(t *testing.T) {
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
		_, err := device.BindRXQueue(&ciliumnetns.NetNS{}, "sandbox-a:eth0", []netip.Addr{netip.MustParseAddr("192.0.2.10")})
		require.ErrorIs(t, err, errInvalidAllocation)
	})

	t.Run("requires queue capacity", func(t *testing.T) {
		_, device := setup(t, testPodNetkit(1))
		_, err := device.BindRXQueue(&ciliumnetns.NetNS{}, "sandbox-a:eth0", []netip.Addr{netip.MustParseAddr("192.0.2.10")})
		require.ErrorContains(t, err, "does not have capacity")
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
		_, err := device.BindRXQueue(&ciliumnetns.NetNS{}, "sandbox-a:eth0", []netip.Addr{netip.MustParseAddr("192.0.2.10")})
		require.ErrorIs(t, err, errNoAvailableRXQueue)
	})

	t.Run("cleanup failure prevents lease activation", func(t *testing.T) {
		fake, device := setup(t, testPodNetkit(2))
		flow := testFlow("192.0.2.10", 9000, corev1.ProtocolTCP)
		require.NoError(t, syncRXFlows(testPhysicalIfName, 7, []types.RXQueueFlow{flow}))
		netlinkNetDevRxFlowDelete = func(string, uint32) error { return unix.EIO }
		unbound, err := device.BindRXQueue(&ciliumnetns.NetNS{}, "sandbox-a:eth0", []netip.Addr{flow.DestinationIP})
		require.ErrorIs(t, err, unix.EIO)
		require.NotNil(t, unbound)
		require.Nil(t, unbound.Binding)
		require.Empty(t, fake.leases)
		_, err = device.BindRXQueue(&ciliumnetns.NetNS{}, "sandbox-a:eth0", []netip.Addr{flow.DestinationIP})
		require.ErrorContains(t, err, "retired")
	})
}

func TestRXQueueBindingReplacement(t *testing.T) {
	fake := newFakeNetlink(8, 8)
	fake.install(t)
	handle := installQueueLeaseFakes(t, fake, testPodNetkit(2))
	device, err := testDevice(8).Setup(testAllocation(testShareID))
	require.NoError(t, err)
	prepared := device.(*RXQueueDevice)
	firstFlow := testFlow("192.0.2.10", 9000, corev1.ProtocolTCP)
	secondFlow := testFlow("192.0.2.11", 9000, corev1.ProtocolTCP)
	first, err := prepared.BindRXQueue(&ciliumnetns.NetNS{}, "sandbox-a:eth0", []netip.Addr{firstFlow.DestinationIP})
	require.NoError(t, err)
	require.NoError(t, first.SyncRXFlows(testShareID, 7, first.Binding.Generation, []types.RXQueueFlow{firstFlow}))

	// The runtime removes the old interface before creating its replacement.
	delete(fake.leases, uint32(7))
	handle.peer = testPodNetkit(2)
	handle.peer.Attrs().Index++
	handle.beforeCreate = func() { require.Empty(t, fake.flows) }
	second, err := prepared.BindRXQueue(&ciliumnetns.NetNS{}, "sandbox-b:eth0", []netip.Addr{secondFlow.DestinationIP})
	require.NoError(t, err)
	require.Greater(t, second.Binding.Generation, first.Binding.Generation)
	require.NoError(t, second.SyncRXFlows(testShareID, 7, second.Binding.Generation, []types.RXQueueFlow{secondFlow}))
	require.NoError(t, first.SyncRXFlows(testShareID, 7, first.Binding.Generation, []types.RXQueueFlow{firstFlow}))
	require.Equal(t, []types.RXQueueFlow{secondFlow}, fake.steeredFlows(7))

	// A stale Run cannot invalidate the current binding, even without a lease.
	handle.peer = testPodNetkit(2)
	_, err = first.BindRXQueue(&ciliumnetns.NetNS{}, "sandbox-a:eth0", []netip.Addr{firstFlow.DestinationIP})
	require.ErrorIs(t, err, errNoAvailableRXQueue)
	delete(fake.leases, uint32(7))
	_, err = first.BindRXQueue(&ciliumnetns.NetNS{}, "sandbox-a:eth0", []netip.Addr{firstFlow.DestinationIP})
	require.ErrorContains(t, err, "retired")
	require.Equal(t, []types.RXQueueFlow{secondFlow}, fake.steeredFlows(7))
}

func TestRXQueueBindingReprepareSameShare(t *testing.T) {
	fake := newFakeNetlink(8, 8)
	fake.install(t)
	installQueueLeaseFakes(t, fake, testPodNetkit(2))
	advertised := testDevice(8)
	allocation := testAllocation(testShareID)
	firstFlow := testFlow("192.0.2.10", 9000, corev1.ProtocolTCP)
	secondFlow := testFlow("192.0.2.20", 9000, corev1.ProtocolTCP)
	device, err := advertised.Setup(allocation)
	require.NoError(t, err)
	first, err := device.(*RXQueueDevice).BindRXQueue(&ciliumnetns.NetNS{}, "sandbox-a:eth0", []netip.Addr{firstFlow.DestinationIP})
	require.NoError(t, err)
	queueID := first.PhysicalQueueID
	require.NoError(t, advertised.SyncRXFlows(testShareID, queueID, first.Binding.Generation, []types.RXQueueFlow{firstFlow}))

	_, err = first.RevokeRXQueueForIP(firstFlow.DestinationIP)
	require.NoError(t, err)
	delete(fake.leases, queueID)
	require.NoError(t, first.Free(allocation))
	require.NotContains(t, advertised.reservations.queues, queueID)
	device, err = advertised.Setup(allocation)
	require.NoError(t, err)
	second, err := device.(*RXQueueDevice).BindRXQueue(&ciliumnetns.NetNS{}, "sandbox-b:eth0", []netip.Addr{secondFlow.DestinationIP})
	require.NoError(t, err)
	require.Equal(t, first.ShareID, second.ShareID)
	require.Equal(t, queueID, second.PhysicalQueueID)
	require.NoError(t, advertised.SyncRXFlows(testShareID, queueID, second.Binding.Generation, []types.RXQueueFlow{secondFlow}))

	// Replay an update captured before the same claim was unprepared.
	require.NoError(t, advertised.SyncRXFlows(testShareID, queueID, first.Binding.Generation, []types.RXQueueFlow{firstFlow}))
	require.Equal(t, []types.RXQueueFlow{secondFlow}, fake.steeredFlows(queueID))
	require.Greater(t, second.Binding.Generation, first.Binding.Generation)
}

func TestRXQueueBindingRecoveryAndRevocation(t *testing.T) {
	fake := newFakeNetlink(8, 8)
	fake.install(t)
	installQueueLeaseFakes(t, fake, testPodNetkit(2))
	device, err := testDevice(8).Setup(testAllocation(testShareID))
	require.NoError(t, err)
	prepared := device.(*RXQueueDevice)
	flow := testFlow("192.0.2.10", 9000, corev1.ProtocolTCP)
	addresses := []netip.Addr{flow.DestinationIP, netip.MustParseAddr("2001:db8::10")}
	bound, err := prepared.BindRXQueue(&ciliumnetns.NetNS{}, "sandbox-a:eth0", addresses)
	require.NoError(t, err)
	require.NoError(t, bound.SyncRXFlows(testShareID, 7, bound.Binding.Generation, []types.RXQueueFlow{flow}))

	firstGeneration := bound.Binding.Generation
	prepared.reservations.queues[7].binding = nil // agent restart loses runtime binding state
	bound, err = prepared.BindRXQueue(&ciliumnetns.NetNS{}, "sandbox-a:eth0", addresses)
	require.NoError(t, err)
	require.Greater(t, bound.Binding.Generation, firstGeneration)
	require.Zero(t, fake.flowDeletes, "matching recovery adopts existing rules")

	deleteRule := netlinkNetDevRxFlowDelete
	netlinkNetDevRxFlowDelete = func(string, uint32) error { return unix.EIO }
	// Address release must revoke steering without any NRI stop notification.
	unbound, err := bound.RevokeRXQueueForIP(addresses[0])
	require.ErrorIs(t, err, unix.EIO)
	require.NotNil(t, unbound)
	require.Nil(t, unbound.Binding, "failed cleanup still invalidates the published generation")
	binding := prepared.reservations.queues[7].binding
	_, err = prepared.Setup(testAllocation(testShareID))
	require.NoError(t, err)
	require.NoError(t, prepared.restoreReservation())
	require.Same(t, binding, prepared.reservations.queues[7].binding, "reserve and restore preserve pending cleanup")
	for _, address := range addresses {
		_, err = unbound.RevokeRXQueueForIP(address)
		require.ErrorIs(t, err, unix.EIO, "every release must retry a failed withdrawal")
	}
	require.NoError(t, bound.SyncRXFlows(testShareID, 7, bound.Binding.Generation, nil))
	_, err = bound.BindRXQueue(&ciliumnetns.NetNS{}, "sandbox-a:eth0", addresses)
	require.ErrorContains(t, err, "retired")
	netlinkNetDevRxFlowDelete = deleteRule
	unbound, err = unbound.RevokeRXQueueForIP(addresses[1])
	require.NoError(t, err)
	require.Nil(t, unbound.Binding)
	require.Empty(t, fake.flows)
	require.NoError(t, bound.SyncRXFlows(testShareID, 7, bound.Binding.Generation, []types.RXQueueFlow{flow}))
	require.Empty(t, fake.flows, "a delayed update cannot restore rules after address release")
	_, err = bound.BindRXQueue(&ciliumnetns.NetNS{}, "sandbox-a:eth0", addresses)
	require.ErrorContains(t, err, "retired")
}
