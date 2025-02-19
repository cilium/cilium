// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package bwmap

import (
	"encoding"
	"strconv"
	"strings"

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
	EdtIDKey

	// BytesPerSecond is the bandwidth limit for the endpoint.
	BytesPerSecond uint64

	Prio uint32

	// TimeHorizonDrop is the maximum allowed departure time nanoseconds
	// delta in future.
	TimeHorizonDrop uint64

	// Status is the BPF map reconciliation status of this throttle entry.
	Status reconciler.Status
}

type EdtIDKey struct {
	EndpointID uint16
	Direction  uint8
}

func (k EdtIDKey) Key() index.Key {
	key := append(index.Uint16(k.EndpointID), '+')
	key = append(key, index.Uint16(uint16(k.Direction))...)
	return key
}

var EdtIDIndex = statedb.Index[Edt, EdtIDKey]{
	Name: "endpoint-id",
	FromObject: func(t Edt) index.KeySet {
		return index.NewKeySet(t.Key())
	},
	FromKey: EdtIDKey.Key,
	FromString: func(key string) (index.Key, error) {
		epS, directionS, _ := strings.Cut(key, "+")
		ep, err := strconv.ParseUint(epS, 10, 16)
		if err != nil {
			return index.Key{}, err
		}
		direction, err := strconv.ParseUint(directionS, 10, 16)
		if err != nil {
			return index.Key{}, err
		}
		return EdtIDKey{EndpointID: uint16(ep), Direction: uint8(direction)}.Key(), nil
	},
	Unique: true,
}

func NewEdt(endpointID uint16, direction uint8, bytesPerSecond uint64, prio uint32) Edt {
	return Edt{
		EdtIDKey: EdtIDKey{
			EndpointID: endpointID,
			Direction:  direction,
		},
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
	k := EdtId{Id: uint32(e.EndpointID), Direction: e.Direction}
	return bpf.StructBinaryMarshaler{Target: &k}
}

func (e Edt) BinaryValue() encoding.BinaryMarshaler {
	v := EdtInfo{
		Bps:      e.BytesPerSecond,
		TimeLast: 0, // Used on the BPF-side
	}
	if e.Direction == 0 {
		// egress
		v.TimeHorizonDropOrTokens = e.TimeHorizonDrop
		v.Prio = e.Prio
	} else {
		v.TimeHorizonDropOrTokens = 0
	}

	return bpf.StructBinaryMarshaler{Target: &v}
}

func (e Edt) TableHeader() []string {
	if e.Direction == 0 {
		return []string{
			"EndpointID",
			"BitsPerSecond",
			"Prio",
			"TimeHorizonDrop",
			"Status",
		}
	}
	return []string{
		"EndpointID",
		"BitsPerSecond",
		"Status",
	}
}

func (e Edt) TableRow() []string {
	// Show the limit as bits per second as that's how it is configured via
	// the annotation.
	quantity := resource.NewQuantity(int64(e.BytesPerSecond*8), resource.DecimalSI)

	if e.Direction == 0 {
		return []string{
			strconv.FormatUint(uint64(e.EndpointID), 10),
			quantity.String(),
			strconv.FormatUint(uint64(e.Prio), 10),
			strconv.FormatUint(e.TimeHorizonDrop, 10),
			e.Status.String(),
		}
	}
	return []string{
		strconv.FormatUint(uint64(e.EndpointID), 10),
		quantity.String(),
		e.Status.String(),
	}
}
