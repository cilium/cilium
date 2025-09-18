// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/cilium/cilium/pkg/command"
	shell "github.com/cilium/cilium/pkg/shell/client"
)

var matchPattern string

// MetricsListCmd dumps all metrics into stdout
var MetricsListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all metrics",
	Run: func(cmd *cobra.Command, args []string) {
		format := "table"
		if command.OutputOption() {
			format = strings.ToLower(command.OutputOptionString())
		}
		shell.ShellExchange(os.Stdout, "metrics --format=%s '%s'", format, matchPattern)
	},
}

func init() {
	MetricsCmd.AddCommand(MetricsListCmd)
	MetricsListCmd.Flags().StringVarP(&matchPattern, "match-pattern", "p", "", "Show only metrics whose names match matchpattern")
	command.AddOutputOption(MetricsListCmd)
}
