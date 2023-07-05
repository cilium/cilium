// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"github.com/spf13/cobra"
)

// MetricsCmd represents the metrics command.
var MetricsCmd = &cobra.Command{
	Use:   "metrics",
	Short: "Access metric status",
}

func init() {
	RootCmd.AddCommand(MetricsCmd)
}
