// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"github.com/spf13/cobra"
)

// bpfPolicyCmd represents the bpf_policy command
var bpfPolicyCmd = &cobra.Command{
	Use:   "policy",
	Short: "Manage policy related BPF maps",
}

func init() {
	bpfCmd.AddCommand(bpfPolicyCmd)
}
