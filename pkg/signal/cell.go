// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package signal

import (
	"log/slog"

	"github.com/cilium/hive/cell"

	"github.com/cilium/cilium/pkg/maps/signalmap"
)

// Cell initializes and manages the signal manager.
var Cell = cell.Module(
	"signal",
	"Receive signals from datapath and distribute them to registered channels",

	cell.Provide(provideSignalManager),
)

func provideSignalManager(lifecycle cell.Lifecycle, logger *slog.Logger, signalMap signalmap.Map) SignalManager {
	sm := newSignalManager(signalMap, logger)

	lifecycle.Append(cell.Hook{
		OnStart: func(startCtx cell.HookContext) error {
			return sm.start()
		},
		OnStop: func(stopCtx cell.HookContext) error {
			return sm.stop()
		},
	})

	return sm
}
