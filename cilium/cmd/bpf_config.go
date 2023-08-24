// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"github.com/spf13/cobra"
)

// BPFConfigCmd represents the bpf command
var BPFConfigCmd = &cobra.Command{
	Use:   "config",
	Short: "Manage runtime config",
}

func init() {
	BPFCmd.AddCommand(BPFConfigCmd)
}
