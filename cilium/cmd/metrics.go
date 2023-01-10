// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"github.com/spf13/cobra"
)

// metricsCmd represents the metrics command.
var metricsCmd = &cobra.Command{
	Use:   "metrics",
	Short: "Access metric status",
}

func init() {
	rootCmd.AddCommand(metricsCmd)
}
