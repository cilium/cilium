// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"github.com/spf13/cobra"
)

// BPFCtCmd represents the bpf_ct command
var BPFCtCmd = &cobra.Command{
	Use:   "ct",
	Short: "Connection tracking tables",
}

func init() {
	BPFCmd.AddCommand(BPFCtCmd)
}
