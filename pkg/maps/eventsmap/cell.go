// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package eventsmap

import (
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/cilium/hive/cell"

	"github.com/cilium/cilium/pkg/bpf"
)

// Cell provides eventsmap.Map, which is the hive representation of the cilium
// events perf event ring buffer.
var Cell = cell.Module(
	"events-map",
	"eBPF ring buffer of cilium events",

	cell.Provide(newEventsMap),
)

var (
	MaxEntries int
)

type Map any

func newEventsMap(lifecycle cell.Lifecycle) bpf.MapOut[Map] {
	eventsMap := &eventsMap{}

	lifecycle.Append(cell.Hook{
		OnStart: func(context cell.HookContext) error {
			cpus, err := ebpf.PossibleCPU()
			if err != nil {
				return fmt.Errorf("failed to get number of possible CPUs: %w", err)
			}
			err = eventsMap.init(cpus)
			if err != nil {
				return fmt.Errorf("initializing events map: %w", err)
			}
			return nil
		},
		OnStop: func(context cell.HookContext) error {
			// We don't currently care for cleaning up.
			return nil
		},
	})

	return bpf.NewMapOut(Map(eventsMap))
}
