// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package compute

import (
	"strconv"

	"github.com/cilium/statedb"
	"github.com/cilium/statedb/index"

	"github.com/cilium/cilium/pkg/identity"
)

func NewPolicyComputationTable(db *statedb.DB) (statedb.RWTable[Result], statedb.Index[Result, identity.NumericIdentity], error) {
	tbl, err := statedb.NewTable(
		db,
		"policy-computations",
		PolicyComputationNameIndex,
	)
	return tbl, PolicyComputationNameIndex, err
}

var (
	PolicyComputationNameIndex = statedb.Index[Result, identity.NumericIdentity]{
		Name: "numeric-identity",
		FromObject: func(r Result) index.KeySet {
			return index.NewKeySet(index.Uint32(uint32(r.Identity)))
		},
		FromKey:    func(i identity.NumericIdentity) index.Key { return index.Uint32(uint32(i)) },
		FromString: index.Uint32String,
		Unique:     true,
	}

	PolicyComputationByIdentity = PolicyComputationNameIndex.Query
)

func (Result) TableHeader() []string {
	return []string{"Identity", "PolicyRevision", "Revision", "CurrentAtRevision", "Err"}
}

func (r Result) TableRow() []string {
	var serr string
	if r.Err != nil {
		serr = r.Err.Error()
	}

	return []string{
		r.Identity.String(),
		strconv.FormatUint(r.Policy.GetRevision(), 10),
		strconv.FormatUint(r.Revision, 10),
		strconv.FormatUint(r.CurrentAtRevision, 10),
		serr,
	}
}
