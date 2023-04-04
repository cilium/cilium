// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"github.com/spf13/cobra"
)

// nodeidCmd represents the nodeid command
var nodeIDCmd = &cobra.Command{
	Use:   "nodeid",
	Short: "List node IDs and associated information",
}

func init() {
	rootCmd.AddCommand(nodeIDCmd)
}
