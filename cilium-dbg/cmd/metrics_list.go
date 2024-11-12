// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"os"

	"github.com/spf13/cobra"

	"github.com/cilium/cilium/pkg/command"
)

var matchPattern string

// MetricsListCmd dumps all metrics into stdout
var MetricsListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all metrics",
	Run: func(cmd *cobra.Command, args []string) {
		shellExchange(os.Stdout, "metrics %s", matchPattern)
	},
}

func init() {
	MetricsCmd.AddCommand(MetricsListCmd)
	MetricsListCmd.Flags().StringVarP(&matchPattern, "match-pattern", "p", "", "Show only metrics whose names match matchpattern")
	command.AddOutputOption(MetricsListCmd)
}
