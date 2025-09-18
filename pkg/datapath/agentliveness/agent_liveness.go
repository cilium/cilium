// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package agentliveness

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/spf13/pflag"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/maps/configmap"
	"github.com/cilium/cilium/pkg/time"
)

// Cell provides the agent liveness updater which periodically writes the current monotonic time to the config
// BPF map to inform the datapath that the agent is still alive.
var Cell = cell.Module(
	"agent-liveness-updater",
	"Agent Liveness Updater",
	cell.Invoke(newAgentLivenessUpdater),
	cell.Config(defaultAgentLivenessConfig),
)

var defaultAgentLivenessConfig = agentLivenessConfig{
	AgentLivenessUpdateInterval: 1 * time.Second,
}

type agentLivenessConfig struct {
	AgentLivenessUpdateInterval time.Duration
}

func (alc agentLivenessConfig) Flags(flags *pflag.FlagSet) {
	flags.Duration("agent-liveness-update-interval", alc.AgentLivenessUpdateInterval,
		"Interval at which the agent updates liveness time for the datapath")
}

func newAgentLivenessUpdater(
	lifecycle cell.Lifecycle,
	jobRegistry job.Registry,
	health cell.Health,
	configMap configmap.Map,
	agentLivenessConfig agentLivenessConfig,
) {
	// Discard even debug logs since this particular job is very noisy
	log := slog.New(slog.DiscardHandler)
	group := jobRegistry.NewGroup(health, lifecycle, job.WithLogger(log))
	group.Add(job.Timer("agent-liveness-updater", func(_ context.Context) error {
		mtime, err := bpf.GetMtime()
		if err != nil {
			return fmt.Errorf("get mtime: %w", err)
		}

		err = configMap.Update(configmap.AgentLiveness, mtime)
		if err != nil {
			return fmt.Errorf("update config map: %w", err)
		}

		return nil
	}, agentLivenessConfig.AgentLivenessUpdateInterval))

}
