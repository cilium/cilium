// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"os"
	"strings"

	"github.com/cilium/hive/shell"
	"github.com/spf13/cobra"

	"github.com/cilium/cilium/pkg/command"
	"github.com/cilium/cilium/pkg/hive"
)

var matchPattern string

// MetricsListCmd dumps all metrics into stdout
var MetricsListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all metrics",
	RunE: func(cmd *cobra.Command, args []string) error {
		format := "table"
		if command.OutputOption() {
			format = strings.ToLower(command.OutputOptionString())
		}
		cfg := hive.DefaultShellConfig
		if err := cfg.Parse(cmd.Flags()); err != nil {
			return err
		}
		return shell.ShellExchange(cfg, os.Stdout, "metrics --format=%s '%s'", format, matchPattern)
	},
}

func init() {
	MetricsCmd.AddCommand(MetricsListCmd)
	MetricsListCmd.Flags().StringVarP(&matchPattern, "match-pattern", "p", "", "Show only metrics whose names match matchpattern")
	command.AddOutputOption(MetricsListCmd)
	hive.DefaultShellConfig.Flags(MetricsListCmd.Flags())
}
