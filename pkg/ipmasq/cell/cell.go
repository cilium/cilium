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

	// The agent has no in-process consumer: it is wired up for its side
	// effects on the BPF ipmasq map. Construct and register it from an invoke
	// so that it runs even though nothing depends on it.
	cell.Invoke(registerIPMasqAgent),
	cell.Config(defaultConfig),
)

type ipMasqAgentParams struct {
	cell.In

	Logger    *slog.Logger
	Lifecycle cell.Lifecycle
	Config    Config
	IPMasqMap *ipmasqmaps.IPMasqBPFMap
}

func registerIPMasqAgent(params ipMasqAgentParams) {
	if !params.Config.EnableIPMasqAgent {
		return
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
}
