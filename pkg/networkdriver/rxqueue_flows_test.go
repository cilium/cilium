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
	"github.com/cilium/statedb/reconciler"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	kube_types "k8s.io/apimachinery/pkg/types"

	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/networkdriver/config"
	"github.com/cilium/cilium/pkg/networkdriver/rxqueue"
	"github.com/cilium/cilium/pkg/networkdriver/types"
)

var testRXQueueFlow = types.RXQueueFlow{
	DestinationIP:   netip.MustParseAddr("192.0.2.10"),
	DestinationPort: 9000,
	Protocol:        corev1.ProtocolTCP,
}

type recordedRXQueueFlows struct {
	mu     lock.Mutex
	synced []RXQueueFlows
}

func stubRXQueueFlowOps(t *testing.T) *recordedRXQueueFlows {
	recorded := &recordedRXQueueFlows{}
	originalSync := rxQueueSyncFlows
	t.Cleanup(func() { rxQueueSyncFlows = originalSync })
	rxQueueSyncFlows = func(nic *rxqueue.RXQueueDevice, shareID kube_types.UID, queueID uint32, flows []types.RXQueueFlow) error {
		recorded.mu.Lock()
		defer recorded.mu.Unlock()
		recorded.synced = append(recorded.synced, RXQueueFlows{
			ShareID: shareID, PhysicalIfName: nic.PhysicalIfName, QueueID: queueID, Flows: flows,
		})
		return nil
	}
	return recorded
}

func insertTestRXQueueNIC(db *statedb.DB, devices statedb.RWTable[*DRADevice]) {
	wtxn := db.WriteTxn(devices)
	devices.Insert(wtxn, &DRADevice{Name: "ens1", Manager: types.DeviceManagerTypeRXQueue, Dev: &rxqueue.RXQueueDevice{
		PhysicalIfName:   "ens1",
		ReservedQueueIDs: []uint32{6, 7},
	}})
	wtxn.Commit()
}

func TestRXQueueFlowOpsUpdate(t *testing.T) {
	recorded := stubRXQueueFlowOps(t)
	db := statedb.New()
	devices, err := newDeviceTable(db)
	require.NoError(t, err)
	ops := rxQueueFlowOps{devices: devices}
	row := &RXQueueFlows{ShareID: "share", PhysicalIfName: "ens1", QueueID: 7, Flows: []types.RXQueueFlow{testRXQueueFlow}}

	require.ErrorContains(t, ops.Update(t.Context(), db.ReadTxn(), 1, row), "not available")

	insertTestRXQueueNIC(db, devices)
	require.NoError(t, ops.Update(t.Context(), db.ReadTxn(), 1, row))
	require.Equal(t, []RXQueueFlows{*row}, recorded.synced)
}

func TestRXQueueFlowReconciler(t *testing.T) {
	recorded := stubRXQueueFlowOps(t)
	var (
		db    *statedb.DB
		flows statedb.RWTable[*RXQueueFlows]
	)
	h := hive.New(
		cell.Provide(
			newRXQueueFlowsTable,
			newDeviceTable,
			func() config.Config { return config.Config{Enabled: true} },
		),
		cell.Invoke(
			registerRXQueueFlowReconciler,
			func(d *statedb.DB, f statedb.RWTable[*RXQueueFlows], devices statedb.RWTable[*DRADevice]) {
				db, flows = d, f
				insertTestRXQueueNIC(db, devices)
			},
		),
	)
	tlog := hivetest.Logger(t)
	require.NoError(t, h.Start(tlog, t.Context()))
	t.Cleanup(func() { require.NoError(t, h.Stop(tlog, context.Background())) })

	wtxn := db.WriteTxn(flows)
	flows.Insert(wtxn, &RXQueueFlows{
		Allocation:     "pool/ens1/share",
		ShareID:        "share",
		PhysicalIfName: "ens1",
		QueueID:        7,
		Flows:          []types.RXQueueFlow{testRXQueueFlow},
		Status:         reconciler.StatusPending(),
	})
	wtxn.Commit()

	require.Eventually(t, func() bool {
		row, _, found := flows.Get(db.ReadTxn(), rxQueueFlowsByAllocation.Query("pool/ens1/share"))
		return found && row.Status.Kind == reconciler.StatusKindDone
	}, 5*time.Second, 10*time.Millisecond)

	recorded.mu.Lock()
	defer recorded.mu.Unlock()
	require.Equal(t, []RXQueueFlows{{
		ShareID:        "share",
		PhysicalIfName: "ens1",
		QueueID:        7,
		Flows:          []types.RXQueueFlow{testRXQueueFlow},
	}}, recorded.synced)
}
