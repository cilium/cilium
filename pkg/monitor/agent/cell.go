// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package agent

import (
	"context"
	"fmt"

	"github.com/sirupsen/logrus"
	"github.com/spf13/pflag"

	"github.com/cilium/cilium/pkg/common"
	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/cilium/cilium/pkg/maps/eventsmap"
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

type AgentConfig struct {
	// EnableMonitor enables the monitor unix domain socket server
	EnableMonitor bool

	// MonitorQueueSize is the size of the monitor event queue
	MonitorQueueSize int
}

var defaultConfig = AgentConfig{
	EnableMonitor: true,
}

func (def AgentConfig) Flags(flags *pflag.FlagSet) {
	flags.Bool("enable-monitor", def.EnableMonitor, "Enable the monitor unix domain socket server")
	flags.Int("monitor-queue-size", 0, "Size of the event queue when reading monitor events")
}

type agentParams struct {
	cell.In

	Lifecycle hive.Lifecycle
	Log       logrus.FieldLogger
	Config    AgentConfig
	EventsMap eventsmap.Map `optional:"true"`
}

func newMonitorAgent(params agentParams) Agent {
	ctx, cancel := context.WithCancel(context.Background())
	agent := newAgent(ctx)

	params.Lifecycle.Append(hive.Hook{
		OnStart: func(hive.HookContext) error {
			if params.EventsMap == nil {
				// If there's no event map, function only for agent events.
				log.Info("No eventsmap: monitor works only for agent events.")
				return nil
			}

			err := agent.AttachToEventsMap(defaults.MonitorBufferPages)
			if err != nil {
				log.WithError(err).Error("encountered error when attaching the monitor agent to eventsmap")
				return fmt.Errorf("encountered error when attaching the monitor agent: %w", err)
			}

			if params.Config.EnableMonitor {
				queueSize := params.Config.MonitorQueueSize
				if queueSize == 0 {
					queueSize = common.GetNumPossibleCPUs(log) * defaults.MonitorQueueSizePerCPU
					if queueSize > defaults.MonitorQueueSizePerCPUMaximum {
						queueSize = defaults.MonitorQueueSizePerCPUMaximum
					}
				}

				err = ServeMonitorAPI(ctx, agent, queueSize)
				if err != nil {
					log.WithError(err).Error("encountered error serving monitor agent API")
					return fmt.Errorf("encountered error serving monitor agent API: %w", err)
				}
			}
			return err
		},
		OnStop: func(hive.HookContext) error {
			cancel()
			return nil
		},
	})

	return agent
}
