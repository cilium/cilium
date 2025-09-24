// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package iptrace

import (
	"github.com/cilium/hive/cell"

	"github.com/cilium/cilium/pkg/bpf"
)

// Cell provides the PerCPUTraceMap, which is an eBPF map used for IP tracing.
// This map is designed to store trace IDs on a per-CPU basis, allowing for
// efficient and concurrent tracing of IP packets. The map has a maximum of
// one entry, which is used to store the trace ID for the current CPU.
var Cell = cell.Module(
	"iptrace-map",
	"eBPF map for IP tracing",

	cell.Provide(
		func(lc cell.Lifecycle) bpf.MapOut[*ipTraceMap] {
			m := NewMap()
			lc.Append(cell.Hook{
				OnStart: func(startCtx cell.HookContext) error {
					return m.OpenOrCreate()
				},
				OnStop: func(stopCtx cell.HookContext) error {
					return m.Close()
				},
			})
			return bpf.NewMapOut(m)
		},
	),
)
