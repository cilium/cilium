// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"github.com/spf13/cobra"
)

// nodeCmd represents the node command
var nodeCmd = &cobra.Command{
	Use:   "node",
	Short: "Manage cluster nodes",
}

func init() {
	rootCmd.AddCommand(nodeCmd)
}
