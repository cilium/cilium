// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package rxqueue

import (
	"maps"
	"net"
	"net/netip"
	"slices"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/vishvananda/netlink"
	corev1 "k8s.io/api/core/v1"
	kube_types "k8s.io/apimachinery/pkg/types"

	"github.com/cilium/cilium/pkg/networkdriver/types"
)

func testFlow(addr string, port uint16, protocol corev1.Protocol) types.RXQueueFlow {
	return types.RXQueueFlow{
		DestinationIP:   netip.MustParseAddr(addr),
		DestinationPort: port,
		Protocol:        protocol,
	}
}

func (f *fakeNetlink) steeredFlows(queueID uint32) []types.RXQueueFlow {
	var flows []types.RXQueueFlow
	for _, location := range slices.Sorted(maps.Keys(f.flows)) {
		rule := f.flows[location]
		if flow, ok := rxFlowFromMatch(rule.Match); ok && rule.Action.Queue == queueID {
			flows = append(flows, flow)
		}
	}
	return flows
}

func TestSyncRXFlows(t *testing.T) {
	fake := newFakeNetlink(8, 8)
	fake.install(t)
	tcp4 := testFlow("192.0.2.10", 9000, corev1.ProtocolTCP)
	udp6 := testFlow("2001:db8::10", 9000, corev1.ProtocolUDP)

	// Rules that deliver elsewhere, including to queue 7 of a virtual
	// function, belong to someone else and must survive.
	foreign := netlink.NetDevRxFlow{Match: netlink.EtherFlow{}, Action: netlink.NetDevRxFlowAction{Queue: 3}, Location: 1}
	fake.flows[1] = foreign
	fake.flows[4] = netlink.NetDevRxFlow{Match: netlink.EtherFlow{}, Action: netlink.NetDevRxFlowAction{Queue: 7}, Location: 4}
	fake.flowActions[4] = netlink.NetDevRxFlowAction{VF: 1, Queue: 7}
	// A rule that targets the reserved queue is removed even if this package
	// cannot represent what it matches, such as a VLAN-qualified rule.
	fake.flows[2] = netlink.NetDevRxFlow{Action: netlink.NetDevRxFlowAction{Queue: 7}, Location: 2}
	fake.flowGetErrors[2] = netlink.ErrNotImplemented

	require.NoError(t, syncRXFlows(testPhysicalIfName, 7, []types.RXQueueFlow{tcp4, udp6}))
	require.ElementsMatch(t, []types.RXQueueFlow{tcp4, udp6}, fake.steeredFlows(7))
	require.Equal(t, 2, fake.flowInserts)
	require.NotContains(t, fake.flows, uint32(2))

	require.NoError(t, syncRXFlows(testPhysicalIfName, 7, []types.RXQueueFlow{udp6, tcp4}))
	require.Equal(t, 2, fake.flowInserts, "existing rules are adopted")

	// A changed selector replaces the stale rule, and so does any other rule
	// that directs traffic to the reserved queue.
	fake.flows[3] = netlink.NetDevRxFlow{Match: netlink.EtherFlow{}, Action: netlink.NetDevRxFlowAction{Queue: 7}, Location: 3}
	tcp4Moved := testFlow("192.0.2.10", 9001, corev1.ProtocolTCP)
	require.NoError(t, syncRXFlows(testPhysicalIfName, 7, []types.RXQueueFlow{tcp4Moved, udp6}))
	require.ElementsMatch(t, []types.RXQueueFlow{tcp4Moved, udp6}, fake.steeredFlows(7))
	require.NotContains(t, fake.flows, uint32(3))

	require.NoError(t, syncRXFlows(testPhysicalIfName, 7, nil))
	require.Empty(t, fake.steeredFlows(7))
	require.Equal(t, foreign, fake.flows[1])
	require.Contains(t, fake.flows, uint32(4))

	require.ErrorIs(t, syncRXFlows(testPhysicalIfName, 7, []types.RXQueueFlow{
		testFlow("192.0.2.10", 0, corev1.ProtocolTCP),
	}), errInvalidAllocation)
}

func TestRXFlowFromMatchRequiresExactShape(t *testing.T) {
	flow := testFlow("2001:db8::10", 443, corev1.ProtocolTCP)
	match, err := rxFlowMatch(flow)
	require.NoError(t, err)
	got, ok := rxFlowFromMatch(match)
	require.True(t, ok)
	require.Equal(t, flow, got)

	widened := match.(netlink.TCP6Flow)
	widened.DstIPMask = net.IP(net.CIDRMask(64, 128))
	_, ok = rxFlowFromMatch(widened)
	require.False(t, ok)
}

// TestSyncRXFlowsRequiresQueueOwner replays an update that was delayed until
// its allocation had been freed and the queue reserved for another share.
func TestSyncRXFlowsRequiresQueueOwner(t *testing.T) {
	fake := newFakeNetlink(8, 8)
	fake.install(t)
	advertised := testDevice(8)
	first, second := testShareID, kube_types.UID("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee")
	firstFlow := testFlow("192.0.2.10", 9000, corev1.ProtocolTCP)
	secondFlow := testFlow("192.0.2.11", 9000, corev1.ProtocolTCP)

	// A rule left on the queue, for example when cilium-agent stopped before
	// it could free an allocation, is removed when the queue is reserved.
	require.NoError(t, syncRXFlows(testPhysicalIfName, 7, []types.RXQueueFlow{secondFlow}))
	device, err := advertised.Setup(testAllocation(first))
	require.NoError(t, err)
	prepared := device.(*RXQueueDevice)
	advertised.reservations.queues[7].binding = &queueBinding{
		RXQueueBinding: RXQueueBinding{Generation: 1, Addresses: []netip.Addr{firstFlow.DestinationIP}}, retired: make(map[string]struct{}),
	}
	require.Equal(t, uint32(7), prepared.PhysicalQueueID)
	require.Empty(t, fake.steeredFlows(7))

	require.NoError(t, advertised.SyncRXFlows(first, 7, 1, []types.RXQueueFlow{firstFlow}))
	require.Equal(t, []types.RXQueueFlow{firstFlow}, fake.steeredFlows(7))

	// Refusing another attachment's address must leave the current rules intact.
	require.ErrorIs(t, advertised.SyncRXFlows(first, 7, 1, []types.RXQueueFlow{secondFlow}), errInvalidAllocation)
	require.Equal(t, []types.RXQueueFlow{firstFlow}, fake.steeredFlows(7))

	// Freeing the allocation removes its rules before releasing the queue.
	require.NoError(t, prepared.Free(testAllocation(first)))
	require.Empty(t, fake.flows)
	device, err = advertised.Setup(testAllocation(second))
	require.NoError(t, err)
	require.Equal(t, uint32(7), device.(*RXQueueDevice).PhysicalQueueID)
	advertised.reservations.queues[7].binding = &queueBinding{
		RXQueueBinding: RXQueueBinding{Generation: 1, Addresses: []netip.Addr{secondFlow.DestinationIP}}, retired: make(map[string]struct{}),
	}

	require.NoError(t, advertised.SyncRXFlows(first, 7, 1, []types.RXQueueFlow{firstFlow}))
	require.Empty(t, fake.steeredFlows(7), "a freed allocation must not program the queue")
	require.NoError(t, advertised.SyncRXFlows(second, 7, 1, []types.RXQueueFlow{secondFlow}))
	require.Equal(t, []types.RXQueueFlow{secondFlow}, fake.steeredFlows(7))
}

func TestSyncRXFlowsRejectsEmptyShareID(t *testing.T) {
	for _, tt := range []struct {
		name    string
		queueID uint32
	}{
		{name: "unallocated reserved queue", queueID: 7},
		{name: "ordinary queue", queueID: 0},
	} {
		t.Run(tt.name, func(t *testing.T) {
			fake := newFakeNetlink(8, 8)
			fake.install(t)
			device := testDevice(8)
			rule := netlink.NetDevRxFlow{Match: netlink.EtherFlow{}, Action: netlink.NetDevRxFlowAction{Queue: tt.queueID}, Location: 1}
			fake.flows[1] = rule

			require.NotContains(t, device.reservations.queues, tt.queueID)
			require.NoError(t, device.SyncRXFlows("", tt.queueID, 1, []types.RXQueueFlow{
				testFlow("192.0.2.10", 9000, corev1.ProtocolTCP),
			}))
			require.Zero(t, fake.flowInserts)
			require.Zero(t, fake.flowDeletes)
			require.Equal(t, rule, fake.flows[1])
		})
	}
}

func TestSyncRXFlowsChoosesLocations(t *testing.T) {
	fake := newFakeNetlink(8, 8)
	fake.install(t)
	fake.flowSpecialLocations = false
	fake.flowTableSize = 3
	fake.flows[0] = netlink.NetDevRxFlow{Match: netlink.EtherFlow{}, Action: netlink.NetDevRxFlowAction{Queue: 3}, Location: 0}

	tcp4 := testFlow("192.0.2.10", 9000, corev1.ProtocolTCP)
	tcp6 := testFlow("2001:db8::10", 9000, corev1.ProtocolTCP)
	require.NoError(t, syncRXFlows(testPhysicalIfName, 7, []types.RXQueueFlow{tcp4, tcp6}))
	require.ElementsMatch(t, []uint32{0, 1, 2}, slices.Collect(maps.Keys(fake.flows)))
	require.ElementsMatch(t, []types.RXQueueFlow{tcp4, tcp6}, fake.steeredFlows(7))

	require.ErrorContains(t, syncRXFlows(testPhysicalIfName, 6, []types.RXQueueFlow{
		testFlow("192.0.2.11", 9000, corev1.ProtocolTCP),
	}), "is full")
}
