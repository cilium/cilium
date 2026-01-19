// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"github.com/spf13/cobra"
)

// BPFVtepPolicyCmd represents the bpf command
var BPFVtepPolicyCmd = &cobra.Command{
	Use:   "vtep-policy",
	Short: "Manage the VTEP Policy mappings",
}

func init() {
	BPFCmd.AddCommand(BPFVtepPolicyCmd)
}
