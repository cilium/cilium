// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package subnet

import (
	"fmt"
	"iter"
	"net/netip"

	"github.com/cilium/statedb"
	"github.com/cilium/statedb/reconciler"
)

const TableName = "subnet-identities"

type SubnetTableEntry struct {
	Key netip.Prefix

	// Identity is the uint64 identifier associated with this subnet.
	Value uint32

	// Status represents the reconciliation status of the subnet entry.
	Status reconciler.Status
}

func NewSubnetEntry(key netip.Prefix, value uint32) SubnetTableEntry {
	return SubnetTableEntry{
		Key:    key,
		Value:  value,
		Status: reconciler.StatusPending(),
	}
}

// TableHeader returns the header for the table representation of SubnetEntry.
func (s SubnetTableEntry) TableHeader() []string {
	return []string{"Prefix", "Identity"}
}

// TableRow returns the row representation of SubnetEntry.
func (s SubnetTableEntry) TableRow() []string {
	return []string{s.Key.String(), fmt.Sprintf("%d", s.Value)}
}

// clone returns a shallow copy of the SubnetTableEntry.
func (s SubnetTableEntry) clone() SubnetTableEntry {
	return SubnetTableEntry{
		Key:    s.Key,
		Value:  s.Value,
		Status: s.Status,
	}
}

// setStatus sets the reconciliation status and returns the updated entry.
func (s SubnetTableEntry) setStatus(status reconciler.Status) SubnetTableEntry {
	s.Status = status
	return s
}

// getStatus returns the current reconciliation status.
func (s SubnetTableEntry) getStatus() reconciler.Status {
	return s.Status
}

// SubnetLPMIndex is the primary index for SubnetEntry, indexing by Prefix.
var SubnetLPMIndex = statedb.NetIPPrefixIndex[SubnetTableEntry]{
	Name: "prefix",
	FromObject: func(s SubnetTableEntry) iter.Seq[netip.Prefix] {
		return statedb.Just(s.Key)
	},
	Unique: true,
}

// newSubnetEntryTable creates and registers the subnet entry table in stateDB.
func newSubnetEntryTable(db *statedb.DB) (statedb.RWTable[SubnetTableEntry], error) {
	return statedb.NewTable(
		db,
		TableName,
		SubnetLPMIndex,
	)
}
