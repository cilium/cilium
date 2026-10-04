// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package networkdriver

import (
	"context"
	"fmt"
	"iter"
	"strconv"

	"github.com/cilium/statedb"
	"github.com/cilium/statedb/index"
	"github.com/cilium/statedb/reconciler"
	kube_types "k8s.io/apimachinery/pkg/types"

	"github.com/cilium/cilium/pkg/networkdriver/config"
	"github.com/cilium/cilium/pkg/networkdriver/rxqueue"
	"github.com/cilium/cilium/pkg/networkdriver/types"
)

const RXQueueFlowsTableName = "networkdriver-rx-queue-flows"

// RXQueueFlows is the flow steering desired for the physical queue reserved
// by one RX queue allocation.
type RXQueueFlows struct {
	// Allocation is the key of the DRAAllocation that reserved the queue.
	Allocation string
	// ShareID identifies the allocation's share. Rules are only programmed
	// while the queue is still reserved for it.
	ShareID        kube_types.UID
	PhysicalIfName string
	QueueID        uint32
	Flows          []types.RXQueueFlow
	// Unresolved explains why the allocation's selector yields no flows.
	Unresolved string
	Status     reconciler.Status
}

func (f *RXQueueFlows) Clone() *RXQueueFlows {
	c := *f
	return &c
}

func (f *RXQueueFlows) GetStatus() reconciler.Status {
	return f.Status
}

func (f *RXQueueFlows) SetStatus(status reconciler.Status) *RXQueueFlows {
	f.Status = status
	return f
}

func (f *RXQueueFlows) TableHeader() []string {
	return []string{"Allocation", "Device", "Queue", "Flows", "Unresolved", "Status"}
}

func (f *RXQueueFlows) TableRow() []string {
	return []string{
		f.Allocation, f.PhysicalIfName, strconv.FormatUint(uint64(f.QueueID), 10),
		fmt.Sprint(f.Flows), f.Unresolved, f.Status.String(),
	}
}

var rxQueueFlowsByAllocation = statedb.Index[*RXQueueFlows, string]{
	Name: "allocation",
	FromObject: func(f *RXQueueFlows) index.KeySet {
		return index.NewKeySet(index.String(f.Allocation))
	},
	FromKey:    index.String,
	FromString: index.FromString,
	Unique:     true,
}

func newRXQueueFlowsTable(db *statedb.DB) (statedb.RWTable[*RXQueueFlows], error) {
	return statedb.NewTable(db, RXQueueFlowsTableName, rxQueueFlowsByAllocation)
}

var (
	rxQueueSyncFlows = (*rxqueue.RXQueueDevice).SyncRXFlows
)

// rxQueueFlowOps programs the NIC rules for the desired RX queue flows.
type rxQueueFlowOps struct {
	devices statedb.Table[*DRADevice]
}

// Update programs the rules through the NIC's queue reservations, which apply
// them only while the queue is still reserved for the row's share.
func (ops rxQueueFlowOps) Update(_ context.Context, txn statedb.ReadTxn, _ statedb.Revision, f *RXQueueFlows) error {
	device, _, found := ops.devices.Get(txn, deviceByName.Query(f.PhysicalIfName))
	if found {
		if nic, ok := device.Dev.(*rxqueue.RXQueueDevice); ok {
			return rxQueueSyncFlows(nic, f.ShareID, f.QueueID, f.Flows)
		}
	}
	return fmt.Errorf("RX queue device %s is not available", f.PhysicalIfName)
}

// Delete does nothing. A row is removed once its allocation has been freed,
// and freeing the allocation removes the rules for its queue.
func (rxQueueFlowOps) Delete(context.Context, statedb.ReadTxn, statedb.Revision, *RXQueueFlows) error {
	return nil
}

// Prune does nothing. Reserving a queue removes any rules left on it, so
// rules that outlive their allocation never reach a new one.
func (rxQueueFlowOps) Prune(context.Context, statedb.ReadTxn, iter.Seq2[*RXQueueFlows, statedb.Revision]) error {
	return nil
}

func registerRXQueueFlowReconciler(
	cfg config.Config,
	params reconciler.Params,
	flows statedb.RWTable[*RXQueueFlows],
	devices statedb.RWTable[*DRADevice],
) error {
	if !cfg.Enabled {
		return nil
	}
	_, err := reconciler.Register(
		params,
		flows,
		(*RXQueueFlows).Clone,
		(*RXQueueFlows).SetStatus,
		(*RXQueueFlows).GetStatus,
		rxQueueFlowOps{devices: devices},
		nil,
		reconciler.WithoutPruning(),
	)
	return err
}
