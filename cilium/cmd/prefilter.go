// SPDX-License-Identifier: Apache-2.0
// Copyright 2017 Authors of Cilium

package cmd

import (
	"github.com/spf13/cobra"
)

// preFilterCmd represents the prefilter command
var preFilterCmd = &cobra.Command{
	Use:   "prefilter",
	Short: "Manage XDP CIDR filters",
}

func init() {
	rootCmd.AddCommand(preFilterCmd)
}
