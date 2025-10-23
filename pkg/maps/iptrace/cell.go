// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package iptrace

import (
	"github.com/cilium/hive/cell"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/maps/registry"
)

// Cell provides the PerCPUTraceMap, which is an eBPF map used for IP tracing.
// This map is designed to store trace IDs on a per-CPU basis, allowing for
// efficient and concurrent tracing of IP packets. The map has a maximum of
// one entry, which is used to store the trace ID for the current CPU.
var Cell = cell.Module(
	"iptrace-map",
	"eBPF map for IP tracing",

	cell.Provide(NewMap),
)

func NewMap(lc cell.Lifecycle, mapSpecRegistry *registry.MapSpecRegistry) bpf.MapOut[*ipTraceMap] {
	m := &ipTraceMap{}
	lc.Append(cell.Hook{
		OnStart: func(startCtx cell.HookContext) error {
			spec, err := mapSpecRegistry.Get(MapName)
			if err != nil {
				return err
			}

			var ipopt Key
			var traceid TraceId
			m.Map = bpf.NewMap(spec, &ipopt, &traceid)

			return m.OpenOrCreate()
		},
		OnStop: func(stopCtx cell.HookContext) error {
			return m.Close()
		},
	})
	return bpf.NewMapOut(m)
}
