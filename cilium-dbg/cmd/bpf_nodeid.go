// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"github.com/spf13/cobra"
)

// BPFNodeIDCmd represents the bpf command
var BPFNodeIDCmd = &cobra.Command{
	Use:   "nodeid",
	Short: "Manage the node IDs",
}

func init() {
	BPFCmd.AddCommand(BPFNodeIDCmd)
}
