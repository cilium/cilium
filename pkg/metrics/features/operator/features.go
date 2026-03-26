// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package features

import (
	"context"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/spf13/cobra"

	"github.com/cilium/cilium/pkg/metrics/promdump"
)

func updateOperatorConfigMetricOnStart(jg job.Group, params featuresParams, m featureMetrics) error {
	jg.Add(job.OneShot("update-config-metric", func(ctx context.Context, health cell.Health) error {
		health.OK("Updating metrics based on OperatorConfig")
		m.update(&params, params.OperatorConfig)
		return nil
	}))

	return nil
}

func NewDumpCmd() *cobra.Command {
	dumpCmd := &cobra.Command{
		Use:    "dump",
		Short:  "Dump metrics to an output directory",
		Hidden: true,
	}

	dumpCmd.AddCommand(&cobra.Command{
		Use:    "features [output directory]",
		Short:  "Dump feature metrics to an output directory",
		Args:   cobra.ExactArgs(1),
		Hidden: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return promdump.DumpGatherer(cmd.Root().Name(), args[0], "feature-metrics.prom", func() (prometheus.Gatherer, error) {
				return NewMetrics(true, true).toGatherer()
			})
		},
	})

	return dumpCmd
}
