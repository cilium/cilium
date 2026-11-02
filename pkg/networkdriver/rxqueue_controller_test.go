// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package networkdriver

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/hivetest"
	"github.com/cilium/statedb"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	kube_types "k8s.io/apimachinery/pkg/types"

	k8sTables "github.com/cilium/cilium/pkg/k8s/tables"
	"github.com/cilium/cilium/pkg/networkdriver/rxqueue"
	"github.com/cilium/cilium/pkg/networkdriver/types"
)

const rxQueueTestPodUID = kube_types.UID("rx-queue-pod")

type rxQueueControllerFixture struct {
	db     *statedb.DB
	driver *Driver
	pods   statedb.RWTable[k8sTables.LocalPod]
}

func newRXQueueControllerFixture(t *testing.T) rxQueueControllerFixture {
	f := rxQueueControllerFixture{db: statedb.New()}
	allocations, err := newAllocationTable(f.db)
	require.NoError(t, err)
	flows, err := newRXQueueFlowsTable(f.db)
	require.NoError(t, err)
	f.pods, err = k8sTables.NewPodTable(f.db)
	require.NoError(t, err)

	f.driver = &Driver{
		logger:          hivetest.Logger(t),
		db:              f.db,
		allocationTable: allocations,
		rxQueueFlows:    flows,
		localPods:       f.pods,
	}
	return f
}

func (f rxQueueControllerFixture) allocate(config *types.RXQueueConfig) *DRAAllocation {
	allocation := &DRAAllocation{
		DeviceName:  "ens1",
		LogicalPool: "rx-queues",
		ShareID:     "share",
		Manager:     types.DeviceManagerTypeRXQueue,
		PodUID:      rxQueueTestPodUID,
		Config:      types.DeviceConfig{RXQueue: config},
		PreparedDevice: &rxqueue.RXQueueDevice{
			PhysicalIfName:  "ens1",
			Prepared:        true,
			PhysicalQueueID: 7,
			Binding: &rxqueue.RXQueueBinding{AttachmentID: "sandbox:eth0", Generation: 1, Addresses: []netip.Addr{
				netip.MustParseAddr("192.0.2.10"), netip.MustParseAddr("2001:db8::10"),
			}},
		},
	}
	wtxn := f.db.WriteTxn(f.driver.allocationTable)
	f.driver.allocationTable.Insert(wtxn, allocation)
	wtxn.Commit()
	return allocation
}

func (f rxQueueControllerFixture) setBinding(allocation *DRAAllocation, binding *rxqueue.RXQueueBinding) *DRAAllocation {
	allocation = allocation.Clone()
	allocation.PreparedDevice = &rxqueue.RXQueueDevice{
		PhysicalIfName: "ens1", Prepared: true, PhysicalQueueID: 7, Binding: binding,
	}
	wtxn := f.db.WriteTxn(f.driver.allocationTable)
	f.driver.allocationTable.Insert(wtxn, allocation)
	wtxn.Commit()
	return allocation
}

func (f rxQueueControllerFixture) upsertPod() {
	pod := rxQueueTestPod()
	pod.UID = rxQueueTestPodUID
	wtxn := f.db.WriteTxn(f.pods)
	f.pods.Insert(wtxn, k8sTables.LocalPod{Pod: pod})
	wtxn.Commit()
}

func (f rxQueueControllerFixture) update(t *testing.T) []*RXQueueFlows {
	wtxn := f.db.WriteTxn(f.driver.rxQueueFlows)
	f.driver.updateRXQueueFlows(t.Context(), wtxn, statedb.NewWatchSet())
	wtxn.Commit()
	return statedb.Collect(f.driver.rxQueueFlows.All(f.db.ReadTxn()))
}

func TestUpdateRXQueueFlows(t *testing.T) {
	f := newRXQueueControllerFixture(t)
	allocation := f.allocate(&types.RXQueueConfig{
		PodEndpoint: &types.RXQueuePodEndpoint{Port: "rpc", Protocol: corev1.ProtocolTCP},
	})

	rows := f.update(t)
	require.Len(t, rows, 1)
	require.Equal(t, "Pod is not running on this node", rows[0].Unresolved)
	require.Empty(t, rows[0].Flows)
	require.Equal(t, "ens1", rows[0].PhysicalIfName)
	require.Equal(t, allocation.ShareID, rows[0].ShareID)
	require.Equal(t, uint32(7), rows[0].QueueID)

	f.upsertPod()
	rows = f.update(t)
	require.Empty(t, rows[0].Unresolved)
	require.Equal(t, []types.RXQueueFlow{
		{DestinationIP: netip.MustParseAddr("192.0.2.10"), DestinationPort: 8080, Protocol: corev1.ProtocolTCP},
		{DestinationIP: netip.MustParseAddr("2001:db8::10"), DestinationPort: 8080, Protocol: corev1.ProtocolTCP},
	}, rows[0].Flows)

	revision := f.driver.rxQueueFlows.Revision(f.db.ReadTxn())
	f.update(t)
	require.Equal(t, revision, f.driver.rxQueueFlows.Revision(f.db.ReadTxn()), "unchanged rows are not rewritten")

	allocation = allocation.Clone()
	allocation.Config.RXQueue = &types.RXQueueConfig{}
	wtxn := f.db.WriteTxn(f.driver.allocationTable)
	f.driver.allocationTable.Insert(wtxn, allocation)
	wtxn.Commit()
	rows = f.update(t)
	require.Contains(t, rows[0].Unresolved, "podEndpoint")
	require.Nil(t, rows[0].Flows)

	wtxn = f.db.WriteTxn(f.driver.allocationTable)
	f.driver.allocationTable.Delete(wtxn, allocation)
	wtxn.Commit()
	require.Empty(t, f.update(t))
}

func TestRXQueueFlowController(t *testing.T) {
	f := newRXQueueControllerFixture(t)
	f.upsertPod()
	f.allocate(&types.RXQueueConfig{
		PodEndpoint: &types.RXQueuePodEndpoint{Port: "rpc", Protocol: corev1.ProtocolTCP},
	})

	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error)
	health, _ := cell.NewSimpleHealth()
	go func() { done <- f.driver.runRXQueueFlowController(ctx, health) }()
	t.Cleanup(func() {
		cancel()
		require.NoError(t, <-done)
	})

	require.Eventually(t, func() bool {
		return f.driver.rxQueueFlows.NumObjects(f.db.ReadTxn()) == 1
	}, 5*time.Second, 10*time.Millisecond)
	rows := statedb.Collect(f.driver.rxQueueFlows.All(f.db.ReadTxn()))
	require.Len(t, rows[0].Flows, 2)
	require.Equal(t, uint16(8080), rows[0].Flows[0].DestinationPort)

	pod := rxQueueTestPod()
	pod.UID = rxQueueTestPodUID
	wtxn := f.db.WriteTxn(f.pods)
	f.pods.Delete(wtxn, k8sTables.LocalPod{Pod: pod})
	wtxn.Commit()
	require.Eventually(t, func() bool {
		rows := statedb.Collect(f.driver.rxQueueFlows.All(f.db.ReadTxn()))
		return len(rows) == 1 && rows[0].Unresolved == "Pod is not running on this node" && rows[0].Flows == nil
	}, 5*time.Second, 10*time.Millisecond)
}

func TestRXQueueFlowControllerBindingUpdates(t *testing.T) {
	f := newRXQueueControllerFixture(t)
	f.upsertPod()
	allocation := f.allocate(&types.RXQueueConfig{
		PodEndpoint: &types.RXQueuePodEndpoint{Port: "rpc", Protocol: corev1.ProtocolTCP},
	})
	allocation = f.setBinding(allocation, nil)
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error)
	health, _ := cell.NewSimpleHealth()
	go func() { done <- f.driver.runRXQueueFlowController(ctx, health) }()
	t.Cleanup(func() {
		cancel()
		require.NoError(t, <-done)
	})
	waitForBinding := func(generation uint64) *RXQueueFlows {
		t.Helper()
		var result *RXQueueFlows
		require.Eventually(t, func() bool {
			rows := statedb.Collect(f.driver.rxQueueFlows.All(f.db.ReadTxn()))
			if len(rows) != 1 || rows[0].BindingGeneration != generation {
				return false
			}
			result = rows[0]
			return true
		}, 5*time.Second, 10*time.Millisecond)
		return result
	}
	row := waitForBinding(0)
	require.Nil(t, row.Flows, "API PodIPs alone must not authorize steering")
	require.Contains(t, row.Unresolved, "not bound")

	address := netip.MustParseAddr("192.0.2.20")
	for i, attachment := range []string{"first:eth0", "replacement:eth0"} {
		generation := uint64(i + 1)
		allocation = f.setBinding(allocation, &rxqueue.RXQueueBinding{
			AttachmentID: attachment, Generation: generation, Addresses: []netip.Addr{address},
		})
		row = waitForBinding(generation)
		require.Empty(t, row.Unresolved)
		require.Equal(t, []types.RXQueueFlow{{DestinationIP: address, DestinationPort: 8080, Protocol: corev1.ProtocolTCP}}, row.Flows,
			"allocation publication must wake the controller even without a Pod update")
	}
	f.setBinding(allocation, nil)
	row = waitForBinding(0)
	require.Nil(t, row.Flows)
	require.Contains(t, row.Unresolved, "not bound")
}

func TestRXQueueFlowConflicts(t *testing.T) {
	flow := types.RXQueueFlow{DestinationIP: netip.MustParseAddr("192.0.2.100"), DestinationPort: 9000, Protocol: corev1.ProtocolTCP}
	desired := map[string]*RXQueueFlows{}
	for _, name := range []string{"a", "b", "c", "another-nic"} {
		desired[name] = &RXQueueFlows{Allocation: name, PhysicalIfName: "ens1", Flows: []types.RXQueueFlow{flow}}
	}
	desired["another-nic"].PhysicalIfName = "ens2"
	invalidateRXQueueFlowConflicts(desired)
	for _, name := range []string{"a", "b", "c"} {
		require.Empty(t, desired[name].Flows)
		require.Contains(t, desired[name].Unresolved, "another allocation")
	}
	require.Equal(t, []types.RXQueueFlow{flow}, desired["another-nic"].Flows)
	require.Empty(t, desired["another-nic"].Unresolved)
}
