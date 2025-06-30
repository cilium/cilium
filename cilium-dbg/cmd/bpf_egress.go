// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"github.com/spf13/cobra"
)

// BPFEgressCmd represents the bpf command
var BPFEgressCmd = &cobra.Command{
	Use:   "egress",
	Short: "Manage the egress routing rules",
}

func init() {
	BPFCmd.AddCommand(BPFEgressCmd)
}
