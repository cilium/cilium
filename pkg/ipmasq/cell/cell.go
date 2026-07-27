// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cell

import (
	"fmt"
	"log/slog"

	"github.com/cilium/cilium/pkg/ipmasq"
	ipmasqmaps "github.com/cilium/cilium/pkg/maps/ipmasq"

	"github.com/cilium/hive/cell"
)

var Cell = cell.Module(
	"ip-masq-agent",
	"BPF ip-masq-agent implementation",

	cell.Provide(newIPMasqAgentCell),
	cell.Config(defaultConfig),
)

type ipMasqAgentParams struct {
	cell.In

	Logger    *slog.Logger
	Lifecycle cell.Lifecycle
	Config    Config
	IPMasqMap *ipmasqmaps.IPMasqBPFMap
}

func newIPMasqAgentCell(params ipMasqAgentParams) (*ipmasq.IPMasqAgent, error) {
	if !params.Config.EnableIPMasqAgent {
		return nil, nil
	}

	agent := ipmasq.NewIPMasqAgent(params.Logger, params.Config.IPMasqAgentConfigPath, params.IPMasqMap)

	params.Lifecycle.Append(cell.Hook{
		OnStart: func(cell.HookContext) error {
			params.Logger.Info("Starting ip-masq-agent")
			if err := agent.Start(); err != nil {
				return fmt.Errorf("failed to start ip-masq-agent: %w", err)
			}
			return nil
		},
		OnStop: func(cell.HookContext) error {
			params.Logger.Info("Stopping ip-masq-agent")
			agent.Stop()
			return nil
		},
	})

	return agent, nil
}
