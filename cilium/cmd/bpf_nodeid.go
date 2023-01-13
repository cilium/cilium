// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"github.com/spf13/cobra"
)

// bpfNodeIDCmd represents the bpf command
var bpfNodeIDCmd = &cobra.Command{
	Use:   "nodeid",
	Short: "Manage the node IDs",
}

func init() {
	bpfCmd.AddCommand(bpfNodeIDCmd)
}
