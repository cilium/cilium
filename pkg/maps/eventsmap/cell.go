// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package eventsmap

import (
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/cilium/hive/cell"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/maps/registry"
	"github.com/cilium/cilium/pkg/option"
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

func newEventsMap(lifecycle cell.Lifecycle, mapSpecRegistry *registry.MapSpecRegistry) (bpf.MapOut[Map], error) {
	eventsMap := &eventsMap{}

	cpus, err := ebpf.PossibleCPU()
	if err != nil {
		return bpf.MapOut[Map]{}, fmt.Errorf("failed to get number of possible CPUs: %w", err)
	}

	err = mapSpecRegistry.ModifyMapSpec(MapName, func(ms *ebpf.MapSpec) error {
		ms.MaxEntries = uint32(cpus)
		return nil
	})
	if err != nil {
		return bpf.MapOut[Map]{}, fmt.Errorf("failed to modify events map spec: %w", err)
	}

	lifecycle.Append(cell.Hook{
		OnStart: func(context cell.HookContext) error {
			spec, err := mapSpecRegistry.Get(MapName)
			if err != nil {
				return fmt.Errorf("failed to get events map spec: %w", err)
			}

			eventsMap.m = bpf.NewMap(spec, &Key{}, &Value{}).
				WithEvents(option.Config.GetEventBufferConfig(MapName))
			return eventsMap.m.Create()
		},
		OnStop: func(context cell.HookContext) error {
			// We don't currently care for cleaning up.
			return nil
		},
	})

	return bpf.NewMapOut(Map(eventsMap)), nil
}
