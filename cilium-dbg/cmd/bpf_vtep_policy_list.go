// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/cilium/cilium/pkg/command"
	"github.com/cilium/cilium/pkg/common"
	"github.com/cilium/cilium/pkg/maps/vtep_policy"
)

const (
	vtepPolicyCidrTitle = "SourceIP DestinationCIDR"
	vtepPolicyTitle     = "VTEP IP/MAC"
)

var (
	vtepPolicyListUsage = "List VTEP CIDR and their corresponding VTEP MAC/IP.\n"
)

var bpfVtepPolicyListCmd = &cobra.Command{
	Use:     "list",
	Aliases: []string{"ls"},
	Short:   "List VTEP Policy entries",
	Long:    vtepPolicyListUsage,
	Run: func(cmd *cobra.Command, args []string) {
		common.RequireRootPrivilege("cilium bpf vtep-policy list")

		vtep, err := vtep_policy.OpenPinnedVtepPolicyMap(log)
		if err != nil {
			Fatalf("Unable to open map: %s", err)
		}

		bpfVtepList := make(map[string][]string)
		parse := func(key *vtep_policy.VtepPolicyKey, val *vtep_policy.VtepPolicyVal) {
			bpfVtepList[key.String()] = append(bpfVtepList[key.String()], val.VtepIp.String())
			bpfVtepList[key.String()] = append(bpfVtepList[key.String()], val.Mac.String())
		}

		if err := vtep.IterateWithCallback(parse); err != nil {
			Fatalf("Error dumping contents of egress policy map: %s\n", err)
		}

		if command.OutputOption() {
			if err := command.PrintOutput(bpfVtepList); err != nil {
				fmt.Fprintf(os.Stderr, "error getting output of map in %s: %s\n", command.OutputOptionString(), err)
				os.Exit(1)
			}
			return
		}

		if len(bpfVtepList) == 0 {
			fmt.Fprintf(os.Stderr, "No entries found.\n")
		} else {
			TablePrinter(vtepPolicyCidrTitle, vtepPolicyTitle, bpfVtepList)
		}
	},
}

func init() {
	BPFVtepPolicyCmd.AddCommand(bpfVtepPolicyListCmd)
	command.AddOutputOption(bpfVtepPolicyListCmd)
}
