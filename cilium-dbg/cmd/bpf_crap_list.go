// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/cilium/cilium/pkg/command"
	"github.com/cilium/cilium/pkg/common"
	"github.com/cilium/cilium/pkg/maps/crap"
)

const (
	crapRuleCidrTitle = "Public IP"
	crapRuleTitle     = "Pod IP"
)

var (
	crapRuleListUsage = "List CRAP public IPs and their corresponding pod IPs.\n"
)

var bpfCrapListCmd = &cobra.Command{
	Use:     "list",
	Aliases: []string{"ls"},
	Short:   "List crap entries",
	Long:    crapRuleListUsage,
	Run: func(cmd *cobra.Command, args []string) {
		common.RequireRootPrivilege("cilium bpf crap list")

		vtep, err := crap.OpenPinnedCrapMap(log)
		if err != nil {
			Fatalf("Unable to open map: %s", err)
		}

		rules := make(map[string][]string)
		parse := func(key *crap.CrapKey, val *crap.CrapVal) {
			rules[key.String()] = append(rules[key.String()], val.PodIp.String())
		}

		if err := vtep.IterateWithCallback(parse); err != nil {
			Fatalf("Error dumping contents of egress policy map: %s\n", err)
		}

		if command.OutputOption() {
			if err := command.PrintOutput(rules); err != nil {
				fmt.Fprintf(os.Stderr, "error getting output of map in %s: %s\n", command.OutputOptionString(), err)
				os.Exit(1)
			}
			return
		}

		if len(rules) == 0 {
			fmt.Fprintf(os.Stderr, "No entries found.\n")
		} else {
			TablePrinter(crapRuleCidrTitle, crapRuleTitle, rules)
		}
	},
}

func init() {
	BPFCrapCmd.AddCommand(bpfCrapListCmd)
	command.AddOutputOption(bpfCrapListCmd)
}
