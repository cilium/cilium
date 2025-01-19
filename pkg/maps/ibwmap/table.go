// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ibwmap

import (
	"encoding"
	"strconv"

	"github.com/cilium/statedb"
	"github.com/cilium/statedb/index"
	"github.com/cilium/statedb/reconciler"
	"k8s.io/apimachinery/pkg/api/resource"

	"github.com/cilium/cilium/pkg/bpf"
)

const IngressTableName = "bandwidth-ingress"

// Throttle is defines the token bucket for a specific
// Cilium endpoint. This structure is stored in Table[Throttle] and reconciled
// to the cilium_ingress_throttle BPF map.
//
// Throttle is stored by value as it's relatively tiny.
type Throttle struct {
	// EndpointID is the identity of the endpoint being throttled.
	EndpointID uint16

	// BytesPerSecond is the bandwidth limit for the endpoint.
	BytesPerSecond uint64

	// Tokens is the maximum allowed departure time nanoseconds
	// delta in future.
	Tokens uint64

	// Status is the BPF map reconciliation status of this throttle entry.
	Status reconciler.Status
}

var ThrottleIDIndex = statedb.Index[Throttle, uint16]{
	Name: "endpoint-id",
	FromObject: func(t Throttle) index.KeySet {
		return index.NewKeySet(index.Uint16(t.EndpointID))
	},
	FromKey: index.Uint16,
	Unique:  true,
}

func NewIngressThrottle(endpointID uint16, bytesPerSecond uint64) Throttle {
	return Throttle{
		EndpointID:     endpointID,
		BytesPerSecond: bytesPerSecond,
		Tokens:         uint64(bytesPerSecond * 8),
		Status:         reconciler.StatusPending(),
	}
}

func NewIngressThrottleTable() (statedb.RWTable[Throttle], error) {
	return statedb.NewTable(
		IngressTableName,
		ThrottleIDIndex,
	)
}

func (e Throttle) BinaryKey() encoding.BinaryMarshaler {
	k := ThrottleID{Id: uint64(e.EndpointID)}
	return bpf.StructBinaryMarshaler{Target: &k}
}

func (e Throttle) BinaryValue() encoding.BinaryMarshaler {
	v := ThrottleInfo{
		Bps:      e.BytesPerSecond,
		TimeLast: 0, // Used on the BPF-side
		Tokens:   e.Tokens,
	}
	return bpf.StructBinaryMarshaler{Target: &v}
}

func (e Throttle) TableHeader() []string {
	return []string{
		"EndpointID",
		"BitsPerSecond",
		"Tokens",
		"Status",
	}
}

func (e Throttle) TableRow() []string {
	// Show the limit as bits per second as that's how it is configured via
	// the annotation.
	quantity := resource.NewQuantity(int64(e.BytesPerSecond*8), resource.DecimalSI)
	return []string{
		strconv.FormatUint(uint64(e.EndpointID), 10),
		quantity.String(),
		strconv.FormatUint(e.Tokens, 10),
		e.Status.String(),
	}
}
