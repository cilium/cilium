// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"github.com/spf13/cobra"
)

// BPFCmd represents the bpf command
var BPFCmd = &cobra.Command{
	Use:   "bpf",
	Short: "Direct access to local BPF maps",
}

func init() {
	RootCmd.AddCommand(BPFCmd)
}
