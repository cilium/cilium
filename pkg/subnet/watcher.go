// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package subnet

import (
	"fmt"
	"log/slog"
	"net/netip"
	"strings"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/cilium/statedb"

	"github.com/cilium/cilium/pkg/dynamicconfig"
	subnetTable "github.com/cilium/cilium/pkg/maps/subnet"
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
	subnetEntries, err := decodeJson(entry.Value)
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
	for _, entry := range subnetEntries {
		if _, _, err := w.subnetTable.Insert(wTx, entry); err != nil {
			return fmt.Errorf("failed to upsert subnet entry %v: %w", entry, err)
		}
	}
	wTx.Commit()
	return nil
}

// decodeJson decodes a JSON string into a slice of SubnetTableEntry.
// Ex: data=10.0.0.1/24,10.10.0.1/24;10.20.0.1/24;2001:0db8:85a3::/64
// would decode into four SubnetTableEntry objects.
// | Key | Value |
// |------|-----------|
// | 10.0.0.1/24 | 1  |
// | 10.10.0.1/24 | 1 |
// | 10.20.0.1/24 | 2 |
// | 2001:0db8:85a3::/64 | 3 |
func decodeJson(data string) ([]subnetTable.SubnetTableEntry, error) {
	data = strings.TrimSpace(data)
	if data == "" {
		return []subnetTable.SubnetTableEntry{}, nil
	}

	var entries []subnetTable.SubnetTableEntry

	// Split by semicolons to get groups
	groups := strings.Split(data, ";")

	for groupID, group := range groups {
		group = strings.TrimSpace(group)
		if group == "" {
			continue
		}

		// Split by commas to get individual subnets within a group
		subnets := strings.SplitSeq(group, ",")

		for subnet := range subnets {
			subnet = strings.TrimSpace(subnet)
			if subnet == "" {
				continue
			}

			// Validate CIDR format
			prefix, err := netip.ParsePrefix(subnet)
			if err != nil {
				return nil, fmt.Errorf("invalid CIDR %q: %w", subnet, err)
			}

			// Identity is groupID + 1 to avoid using identity 0.
			entries = append(entries, subnetTable.NewSubnetEntry(prefix, uint32(groupID+1)))
		}
	}

	if len(entries) == 0 {
		return nil, fmt.Errorf("no valid subnets found in data")
	}

	return entries, nil
}
