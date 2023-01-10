// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"github.com/spf13/cobra"

	"github.com/cilium/cilium/pkg/common"
)

// bpfPolicyDeleteCmd represents the bpf_policy_delete command
var bpfPolicyDeleteCmd = &cobra.Command{
	Use:    "delete <endpoint id> <identity> [port/proto]",
	Short:  "Delete a policy entry",
	PreRun: requireEndpointID,
	Run: func(cmd *cobra.Command, args []string) {
		common.RequireRootPrivilege("cilium bpf policy delete")
		updatePolicyKey(parsePolicyUpdateArgs(cmd, args, isDeny), false)
	},
}

func init() {
	bpfPolicyDeleteCmd.Flags().BoolVar(&isDeny, "deny", false, "Sets deny mode")
	bpfPolicyCmd.AddCommand(bpfPolicyDeleteCmd)
}
