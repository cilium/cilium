// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package iptrace

import (
	"fmt"

	"github.com/cilium/ebpf"

	"github.com/cilium/cilium/pkg/bpf"
)

const (
	// MapName is the name of the map.
	MapName = "cilium_percpu_trace_id"

	// MaxEntries represents the maximum number of trace ID entries.
	MaxEntries = 1
)

// Key is the key for the IP trace map.
type Key uint32

// TraceId is the value for the IP trace map.
type TraceId uint64

// String returns the string representation of the key.
func (k *Key) String() string { return fmt.Sprintf("%d", uint32(*k)) }

// New creates a new key.
func (k *Key) New() bpf.MapKey { return new(Key) }

// String returns the string representation of the value.
func (v *TraceId) String() string { return fmt.Sprintf("%d", uint64(*v)) }

// New creates a new value.
func (v *TraceId) New() bpf.MapValue { return new(TraceId) }

// ipTraceMap is the trace map.
type ipTraceMap struct {
	*bpf.Map
}

// NewMap returns a new trace map.
func NewMap() *ipTraceMap {
	var ipopt Key
	var traceid TraceId

	return &ipTraceMap{
		Map: bpf.NewMap(
			MapName,
			ebpf.PerCPUArray,
			&ipopt,
			&traceid,
			MaxEntries,
			0,
		),
	}
}
