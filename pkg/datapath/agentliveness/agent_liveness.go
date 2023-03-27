// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package agentliveness

import (
	"context"
	"fmt"
	"io"
	"time"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/cilium/cilium/pkg/hive/job"
	"github.com/cilium/cilium/pkg/maps/configmap"

	"github.com/sirupsen/logrus"
	"github.com/spf13/pflag"
)

var Cell = cell.Group(
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
	logger logrus.FieldLogger,
	lifecycle hive.Lifecycle,
	jobRegistry job.Registry,
	configMap configmap.Map,
	agentLivenessConfig agentLivenessConfig,
) {
	// Discard even debug logs since this particular job is very noisy
	log := logrus.New()
	log.Out = io.Discard
	group := jobRegistry.NewGroup(job.WithLogger(log))

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

	lifecycle.Append(group)
}
