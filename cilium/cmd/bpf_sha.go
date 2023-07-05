// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"github.com/spf13/cobra"
)

// BPFTemplateCmd represents the bpf-sha command
var BPFTemplateCmd = &cobra.Command{
	Use:     "sha",
	Aliases: []string{"template"},
	Short:   "Manage compiled BPF template objects",
}

func init() {
	BPFCmd.AddCommand(BPFTemplateCmd)
}
