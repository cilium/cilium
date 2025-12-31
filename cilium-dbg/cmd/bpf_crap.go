// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"github.com/spf13/cobra"
)

// BPFCrapCmd represents the bpf command
var BPFCrapCmd = &cobra.Command{
	Use:   "crap",
	Short: "Manage the CRAP rules",
}

func init() {
	BPFCmd.AddCommand(BPFCrapCmd)
}
