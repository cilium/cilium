// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"github.com/spf13/cobra"

	"github.com/cilium/cilium/pkg/common"
)

var isDeny bool

// bpfPolicyAddCmd represents the bpf_policy_add command
var bpfPolicyAddCmd = &cobra.Command{
	Use:    "add <endpoint id> <traffic-direction> <identity> [port/proto]",
	Short:  "Add/update policy entry",
	PreRun: requireEndpointID,
	Run: func(cmd *cobra.Command, args []string) {
		common.RequireRootPrivilege("cilium bpf policy add")
		updatePolicyKey(parsePolicyUpdateArgs(cmd, args, isDeny), true)
	},
}

func init() {
	bpfPolicyAddCmd.Flags().BoolVar(&isDeny, "deny", false, "Sets deny mode")
	bpfPolicyCmd.AddCommand(bpfPolicyAddCmd)
}
