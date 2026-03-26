// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"github.com/spf13/cobra"

	operatorFeatures "github.com/cilium/cilium/pkg/metrics/features/operator"
)

// MetricsCmd represents the metrics command for the operator.
var MetricsCmd = &cobra.Command{
	Use:   "metrics",
	Short: "Access metric status of the operator",
}

func init() {
	MetricsCmd.AddCommand(MetricsListCmd)
	MetricsCmd.AddCommand(operatorFeatures.NewDumpCmd())
}
