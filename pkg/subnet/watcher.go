// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package subnet

import (
	"fmt"
	"log/slog"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/cilium/statedb"

	"github.com/cilium/cilium/pkg/dynamicconfig"
	subnetTable "github.com/cilium/cilium/pkg/maps/subnet"
	"github.com/cilium/cilium/pkg/subnet/topology"
)

type watcherParams struct {
	cell.In

	Logger             *slog.Logger
	DynamicConfigTable statedb.Table[dynamicconfig.DynamicConfig]
	SubnetTable        statedb.RWTable[subnetTable.SubnetTableEntry]
	DB                 *statedb.DB
	JobGroup           job.Group
}

type SubnetWatcher struct {
	logger             *slog.Logger
	dynamicConfigTable statedb.Table[dynamicconfig.DynamicConfig]
	subnetTable        statedb.RWTable[subnetTable.SubnetTableEntry]
	db                 *statedb.DB
	jobGroup           job.Group
}

func newSubnetWatcher(params watcherParams) *SubnetWatcher {
	return &SubnetWatcher{
		logger:             params.Logger,
		dynamicConfigTable: params.DynamicConfigTable,
		subnetTable:        params.SubnetTable,
		db:                 params.DB,
		jobGroup:           params.JobGroup,
	}
}

func (w *SubnetWatcher) processSubnetConfigEntry(entry dynamicconfig.DynamicConfig) error {
	decoded, err := topology.Decode(entry.Value)
	if err != nil {
		return fmt.Errorf("failed to decode subnet-topology dynamic config value: %w", err)
	}

	// Write to the subnet table.
	// Reset the table and write all entries afresh.
	wTx := w.db.WriteTxn(w.subnetTable)
	defer wTx.Abort()

	if err := w.subnetTable.DeleteAll(wTx); err != nil {
		return fmt.Errorf("failed to reset subnet table: %w", err)
	}
	for _, e := range decoded {
		entry := subnetTable.NewSubnetEntry(e.Key, e.Value)
		if _, _, err := w.subnetTable.Insert(wTx, entry); err != nil {
			return fmt.Errorf("failed to upsert subnet entry %v: %w", entry, err)
		}
	}
	wTx.Commit()
	return nil
}
