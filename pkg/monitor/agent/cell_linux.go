// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package agent

import (
	"context"
	"fmt"
	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/maps/eventsmap"
	"github.com/cilium/ebpf"
	"github.com/cilium/hive/cell"
	"log/slog"
)

// Cell provides the monitor agent, which monitors the cilium events perf event
// buffer and forwards events to consumers/listeners. It also handles
// multicasting of other agent events.
var Cell = cell.Module(
	"monitor-agent",
	"Consumes the cilium events map and distributes those and other agent events",

	cell.Provide(newMonitorAgent),
	cell.Config(defaultConfig),
)

type agentParams struct {
	cell.In

	Lifecycle cell.Lifecycle
	Log       *slog.Logger
	Config    AgentConfig
	EventsMap eventsmap.Map `optional:"true"`
}

func newMonitorAgent(params agentParams) Agent {
	ctx, cancel := context.WithCancel(context.Background())
	agent := newAgent(ctx, params.Log)

	params.Lifecycle.Append(cell.Hook{
		OnStart: func(cell.HookContext) error {
			if params.EventsMap == nil {
				// If there's no event map, function only for agent events.
				params.Log.Info("No eventsmap: monitor works only for agent events.")
				return nil
			}

			err := agent.AttachToEventsMap(defaults.MonitorBufferPages)
			if err != nil {
				params.Log.Error("encountered error when attaching the monitor agent to eventsmap", logfields.Error, err)
				return fmt.Errorf("encountered error when attaching the monitor agent: %w", err)
			}

			if params.Config.EnableMonitor {
				queueSize := params.Config.MonitorQueueSize
				if queueSize == 0 {
					possibleCPUs, err := ebpf.PossibleCPU()
					if err != nil {
						params.Log.Error("failed to get number of possible CPUs", logfields.Error, err)
						return fmt.Errorf("failed to get number of possible CPUs: %w", err)
					}
					queueSize = min(possibleCPUs*defaults.MonitorQueueSizePerCPU, defaults.MonitorQueueSizePerCPUMaximum)
				}

				err = ServeMonitorAPI(ctx, params.Log, agent, queueSize)
				if err != nil {
					params.Log.Error("encountered error serving monitor agent API", logfields.Error, err)
					return fmt.Errorf("encountered error serving monitor agent API: %w", err)
				}
			}
			return err
		},
		OnStop: func(cell.HookContext) error {
			cancel()
			return nil
		},
	})

	return agent
}
