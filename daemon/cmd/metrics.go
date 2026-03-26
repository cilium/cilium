// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"github.com/spf13/cobra"

	agentFeatures "github.com/cilium/cilium/pkg/metrics/features"
)

func newMetricsCmd() *cobra.Command {
	metricsCmd := &cobra.Command{
		Use:    "metrics",
		Short:  "Access metric status of the agent",
		Hidden: true,
	}

	metricsCmd.AddCommand(agentFeatures.NewDumpCmd())

	return metricsCmd
}
