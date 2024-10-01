// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package bwmap

import (
	"encoding"
	"strconv"

	"github.com/cilium/statedb"
	"github.com/cilium/statedb/index"
	"github.com/cilium/statedb/reconciler"
	"k8s.io/apimachinery/pkg/api/resource"

	"github.com/cilium/cilium/pkg/bpf"
)

const EdtTableName = "bandwidth-edts"

// Edt is defines the "earliest departure time" pacing for a specific
// Cilium endpoint. This structure is stored in Table[Edt] and reconciled
// to the cilium_throttle BPF map.
//
// Edt is stored by value as it's relatively tiny.
type Edt struct {
	// EndpointID is the identity of the endpoint being throttled.
	EndpointID uint16

	// BytesPerSecond is the bandwidth limit for the endpoint.
	BytesPerSecond uint64

	Prio uint32

	// TimeHorizonDrop is the maximum allowed departure time nanoseconds
	// delta in future.
	TimeHorizonDrop uint64

	// Status is the BPF map reconciliation status of this throttle entry.
	Status reconciler.Status
}

var EdtIDIndex = statedb.Index[Edt, uint16]{
	Name: "endpoint-id",
	FromObject: func(t Edt) index.KeySet {
		return index.NewKeySet(index.Uint16(t.EndpointID))
	},
	FromKey: index.Uint16,
	Unique:  true,
}

func NewEdt(endpointID uint16, bytesPerSecond uint64, prio uint32) Edt {
	return Edt{
		EndpointID:      endpointID,
		BytesPerSecond:  bytesPerSecond,
		Prio:            prio,
		TimeHorizonDrop: uint64(DefaultDropHorizon),
		Status:          reconciler.StatusPending(),
	}
}

func NewEdtTable() (statedb.RWTable[Edt], error) {
	return statedb.NewTable(
		EdtTableName,
		EdtIDIndex,
	)
}

func (e Edt) BinaryKey() encoding.BinaryMarshaler {
	k := EdtId{uint64(e.EndpointID)}
	return bpf.StructBinaryMarshaler{Target: &k}
}

func (e Edt) BinaryValue() encoding.BinaryMarshaler {
	v := EdtInfo{
		Bps:             e.BytesPerSecond,
		TimeLast:        0, // Used on the BPF-side
		TimeHorizonDrop: e.TimeHorizonDrop,
		Prio:            e.Prio,
	}
	return bpf.StructBinaryMarshaler{Target: &v}
}

func (e Edt) TableHeader() []string {
	return []string{
		"EndpointID",
		"BitsPerSecond",
		"Prio",
		"TimeHorizonDrop",
		"Status",
	}
}

func (e Edt) TableRow() []string {
	// Show the limit as bits per second as that's how it is configured via
	// the annotation.
	quantity := resource.NewQuantity(int64(e.BytesPerSecond*8), resource.DecimalSI)
	return []string{
		strconv.FormatUint(uint64(e.EndpointID), 10),
		quantity.String(),
		strconv.FormatUint(uint64(e.Prio), 10),
		strconv.FormatUint(e.TimeHorizonDrop, 10),
		e.Status.String(),
	}
}
