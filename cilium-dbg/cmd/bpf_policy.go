// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"github.com/spf13/cobra"
)

// BPFPolicyCmd represents the bpf_policy command
var BPFPolicyCmd = &cobra.Command{
	Use:   "policy",
	Short: "Manage policy related BPF maps",
}

func init() {
	BPFCmd.AddCommand(BPFPolicyCmd)
}
