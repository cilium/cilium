// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"github.com/spf13/cobra"
)

// bpfAuthCmd represents the bpf command
var bpfAuthCmd = &cobra.Command{
	Use:   "auth",
	Short: "Manage authenticated connections between identities",
}

func init() {
	bpfCmd.AddCommand(bpfAuthCmd)
}
