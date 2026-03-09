// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package features

import (
	"context"
	"fmt"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/cilium/cilium/pkg/metrics/promdump"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/spf13/cobra"
)

func updateAgentConfigMetricOnStart(jg job.Group, params featuresParams, m featureMetrics) error {
	jg.Add(job.OneShot("update-config-metric", func(ctx context.Context, health cell.Health) error {
		// We depend on settings modified by the Daemon startup.
		// Once the Deamon is initialized this promise
		// is resolved and we are guaranteed to have the correct settings.
		health.OK("Waiting for agent config")
		agentConfig, err := params.ConfigPromise.Await(ctx)
		if err != nil {
			return fmt.Errorf("failed to get agent config: %w", err)
		}
		m.update(&params, agentConfig, params.LBConfig, params.KPRConfig, params.WgConfig, params.IPsecConfig)
		return nil
	}))

	return nil
}

func NewDumpCmd(parentCmd *cobra.Command) *cobra.Command {
	return &cobra.Command{
		Use:    "feature-metrics [output directory]",
		Short:  fmt.Sprintf("Generate feature metrics for %s to given output directory", parentCmd.Name()),
		Args:   cobra.ExactArgs(1),
		Hidden: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return promdump.DumpGatherer(parentCmd.Name(), args[0], "feature-metrics.prom", func() (prometheus.Gatherer, error) {
				return NewMetrics(true, true).toGatherer()
			})
		},
	}
}
