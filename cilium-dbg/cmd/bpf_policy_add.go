// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"github.com/spf13/cobra"

	"github.com/cilium/cilium/pkg/common"
	"github.com/cilium/cilium/pkg/logging"
)

var isDeny bool

// bpfPolicyAddCmd represents the bpf_policy_add command
var bpfPolicyAddCmd = &cobra.Command{
	Use:    "add <endpoint id> <traffic-direction> <identity> [port/proto]",
	Short:  "Add/update policy entry",
	PreRun: requireEndpointID,
	Run: func(cmd *cobra.Command, args []string) {
		common.RequireRootPrivilege("cilium bpf policy add")
		updatePolicyKey(parsePolicyUpdateArgs(logging.DefaultSlogLogger, cmd, args, isDeny), true)
	},
}

func init() {
	bpfPolicyAddCmd.Flags().BoolVar(&isDeny, "deny", false, "Sets deny mode")
	BPFPolicyCmd.AddCommand(bpfPolicyAddCmd)
}
