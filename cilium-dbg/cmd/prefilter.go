// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"github.com/spf13/cobra"
)

// PreFilterCmd represents the prefilter command
var PreFilterCmd = &cobra.Command{
	Use:   "prefilter",
	Short: "Manage XDP CIDR filters",
}

func init() {
	RootCmd.AddCommand(PreFilterCmd)
}
