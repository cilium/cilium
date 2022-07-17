// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"github.com/spf13/cobra"

	"github.com/cilium/cilium/pkg/command"
	"github.com/cilium/cilium/pkg/common"
)

// bpfPolicyListCmd represents the bpf_policy_list command
var bpfPolicyListCmd = &cobra.Command{
	Use:     "list",
	Aliases: []string{"ls"},
	Short:   "Dump all policy maps",
	Run: func(cmd *cobra.Command, args []string) {
		common.RequireRootPrivilege("cilium bpf policy list")
		listAllMaps()
	},
}

func init() {
	bpfPolicyCmd.AddCommand(bpfPolicyListCmd)
	command.AddOutputOption(bpfPolicyListCmd)
}
