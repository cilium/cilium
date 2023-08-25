// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package signal

import (
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/cilium/cilium/pkg/maps/signalmap"
)

// Cell initializes and manages the signal manager.
var Cell = cell.Module(
	"signal",
	"Receive signals from datapath and distribute them to registered channels",

	cell.Provide(provideSignalManager),
)

func provideSignalManager(lifecycle hive.Lifecycle, signalMap signalmap.Map) SignalManager {
	sm := newSignalManager(signalMap)

	log.Debugf("newSignalManager: %v", sm)

	lifecycle.Append(hive.Hook{
		OnStart: func(startCtx hive.HookContext) error {
			return sm.start()
		},
		OnStop: func(stopCtx hive.HookContext) error {
			return sm.stop()
		},
	})

	return sm
}
