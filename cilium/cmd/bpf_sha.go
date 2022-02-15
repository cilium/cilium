// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"github.com/spf13/cobra"
)

// bpfIPCacheCmd represents the bpf command
var bpfTemplateCmd = &cobra.Command{
	Use:     "sha",
	Aliases: []string{"template"},
	Short:   "Manage compiled BPF template objects",
}

func init() {
	bpfCmd.AddCommand(bpfTemplateCmd)
}
