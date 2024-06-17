// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package tables

import (
	"fmt"

	"github.com/cilium/statedb"
	"github.com/cilium/statedb/index"
	"github.com/cilium/statedb/reconciler"

	"github.com/cilium/cilium/pkg/time"
)

// BandwidthQDisc defines the desired state for a qdisc. Used by Bandwidth Manager
// to setup the correct queueing disciplines on the native devices to enforce
// bandwidth limits.
type BandwidthQDisc struct {
	LinkIndex int               // Interface index
	LinkName  string            // Interface name (purely informative)
	FqHorizon time.Duration     // Maximum allowed departure time
	FqBuckets uint32            // Hash table size for flow lookup (2^FqBuckets)
	Status    reconciler.Status // Reconciliation status
}

func (dq *BandwidthQDisc) TableHeader() []string {
	return []string{
		"LinkIndex",
		"LinkName",
		"FqHorizon",
		"FqBuckets",
		"Status",
	}
}

func (dq *BandwidthQDisc) TableRow() []string {
	return []string{
		fmt.Sprintf("%d", dq.LinkIndex),
		dq.LinkName,
		fmt.Sprintf("%d", dq.FqHorizon),
		fmt.Sprintf("%d", dq.FqBuckets),
		dq.Status.String(),
	}
}

func (dq *BandwidthQDisc) GetStatus() reconciler.Status {
	return dq.Status
}

func (dq *BandwidthQDisc) SetStatus(s reconciler.Status) *BandwidthQDisc {
	dq.Status = s
	return dq
}

func (dq *BandwidthQDisc) Clone() *BandwidthQDisc {
	dq2 := *dq
	return &dq2
}

var (
	BandwidthQDiscIndex = statedb.Index[*BandwidthQDisc, int]{
		Name: "id",
		FromObject: func(obj *BandwidthQDisc) index.KeySet {
			return index.NewKeySet(index.Int(obj.LinkIndex))
		},
		FromKey: index.Int,
		Unique:  true,
	}

	BandwidthQDiscTableName = "bandwidth-qdiscs"
)

func NewBandwidthQDiscTable(db *statedb.DB) (statedb.RWTable[*BandwidthQDisc], error) {
	tbl, err := statedb.NewTable(
		BandwidthQDiscTableName,
		BandwidthQDiscIndex,
	)
	if err == nil {
		err = db.RegisterTable(tbl)
	}
	return tbl, err
}
