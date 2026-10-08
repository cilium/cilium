// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import "github.com/spf13/cobra"

var BPFStatsCmd = &cobra.Command{
	Use:   "stats",
	Short: "BPF program runtime and execution count stats",
}

func init() {
	BPFCmd.AddCommand(BPFStatsCmd)
}
