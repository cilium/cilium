// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/cilium/cilium/pkg/command"
	"github.com/cilium/cilium/pkg/common"
	"github.com/cilium/cilium/pkg/maps/subnet"
)

const (
	subnetPrefixTitle   = "SUBNET PREFIX"
	subnetIdentityTitle = "IDENTITY"
)

var bpfSubnetListCmd = &cobra.Command{
	Use:     "list",
	Aliases: []string{"ls"},
	Short:   "List subnet CIDR to identity mappings",
	Long:    "List the contents of the subnet BPF map used for hybrid routing.\n",
	Run: func(cmd *cobra.Command, args []string) {
		common.RequireRootPrivilege("cilium bpf subnet list")

		bpfSubnetList := make(map[string][]string)
		if err := subnet.SubnetMap().DumpIfExists(bpfSubnetList); err != nil {
			fmt.Fprintf(os.Stderr, "error dumping contents of map: %s\n", err)
			os.Exit(1)
		}

		if command.OutputOption() {
			if err := command.PrintOutput(bpfSubnetList); err != nil {
				fmt.Fprintf(os.Stderr, "error getting output of map in %s: %s\n", command.OutputOptionString(), err)
				os.Exit(1)
			}
			return
		}

		if len(bpfSubnetList) == 0 {
			fmt.Fprintf(os.Stderr, "No entries found.\n")
		} else {
			TablePrinter(subnetPrefixTitle, subnetIdentityTitle, bpfSubnetList)
		}
	},
}

func init() {
	BPFSubnetCmd.AddCommand(bpfSubnetListCmd)
	command.AddOutputOption(bpfSubnetListCmd)
}
