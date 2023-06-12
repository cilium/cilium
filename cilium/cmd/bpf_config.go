// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"github.com/spf13/cobra"
)

// bpfConfigCmd represents the bpf command
var bpfConfigCmd = &cobra.Command{
	Use:   "config",
	Short: "Manage runtime config",
}

func init() {
	bpfCmd.AddCommand(bpfConfigCmd)
}
