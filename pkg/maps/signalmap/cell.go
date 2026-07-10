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

func newMap(lifecycle cell.Lifecycle, logger *slog.Logger) (bpf.MapOut[Map], error) {
	possibleCPUs, err := ebpf.PossibleCPU()
	if err != nil {
		return bpf.MapOut[Map]{}, fmt.Errorf("failed to get number of possible CPUs: %w", err)
	}
	signalmap := initMap(logger, possibleCPUs)

	lifecycle.Append(cell.Hook{
		OnStart: func(startCtx cell.HookContext) error {
			return signalmap.open()
		},
		OnStop: func(stopCtx cell.HookContext) error {
			return signalmap.close()
		},
	})

	return bpf.NewMapOut(Map(signalmap)), nil
}
