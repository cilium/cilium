// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package signalmap

import (
	"log/slog"

	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/hive/cell"

	"github.com/cilium/cilium/pkg/bpf"
)

// Cell initializes and manages the config map.
var Cell = cell.Module(
	"signal-map",
	"eBPF map signal passes wakeup events from Cilium datapath",

	cell.Provide(newMap),
)

// RingBufReader is an interface for reading from ring buffer records.
// Implementations need to be safe to call from multiple goroutines.
type RingBufReader interface {
	Read() (ringbuf.Record, error)
	Close() error
}

type Map interface {
	NewReader() (RingBufReader, error)
	MapName() string
}

func newMap(lifecycle cell.Lifecycle, logger *slog.Logger) (bpf.MapOut[Map], error) {
	signalmap := initMap(logger)

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
