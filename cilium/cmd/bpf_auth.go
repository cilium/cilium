// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"github.com/spf13/cobra"
)

// BPFAuthCmd represents the bpf command
var BPFAuthCmd = &cobra.Command{
	Use:   "auth",
	Short: "Manage authenticated connections between identities",
}

func init() {
	BPFCmd.AddCommand(BPFAuthCmd)
}
