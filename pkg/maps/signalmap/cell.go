// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package signalmap

import (
	"fmt"
	"log/slog"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/hive/cell"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/maps/registry"
)

// Cell initializes and manages the config map.
var Cell = cell.Module(
	"signal-map",
	"eBPF map signal passes wakeup events from Cilium datapath",

	cell.Provide(newMap),
)

// PerfReader is an interface for reading from perf records. Implementations need to be safe to call
// from multiple goroutines.
type PerfReader interface {
	Read() (perf.Record, error)
	Pause() error
	Resume() error
	Close() error
}

type Map interface {
	NewReader() (PerfReader, error)
	MapName() string
}

func newMap(lifecycle cell.Lifecycle, logger *slog.Logger, mapSpecRegistry *registry.MapSpecRegistry) (bpf.MapOut[Map], error) {
	possibleCPUs, err := ebpf.PossibleCPU()
	if err != nil {
		return bpf.MapOut[Map]{}, fmt.Errorf("failed to get number of possible CPUs: %w", err)
	}

	mapSpecRegistry.ModifyMapSpec(MapName, func(spec *ebpf.MapSpec) error {
		spec.MaxEntries = uint32(possibleCPUs)
		return nil
	})

	m := &signalMap{
		logger: logger,
	}

	lifecycle.Append(cell.Hook{
		OnStart: func(startCtx cell.HookContext) error {
			spec, err := mapSpecRegistry.Get(MapName)
			if err != nil {
				return err
			}

			m.bpfMap = bpf.NewMap(spec, &Key{}, &Value{})

			return m.bpfMap.OpenOrCreate()
		},
		OnStop: func(stopCtx cell.HookContext) error {
			return m.bpfMap.Close()
		},
	})

	return bpf.NewMapOut(Map(m)), nil
}
