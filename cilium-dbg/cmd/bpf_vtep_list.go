// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/cilium/cilium/pkg/command"
	"github.com/cilium/cilium/pkg/common"
	"github.com/cilium/cilium/pkg/maps/vtep"
)

const (
	vtepCidrTitle = "IP PREFIX/ADDRESS"
	vtepTitle     = "VTEP"
)

var vtepListUsage = "List VTEP CIDR and their corresponding VTEP MAC/IP.\n"

var bpfVtepListCmd = &cobra.Command{
	Use:     "list",
	Aliases: []string{"ls"},
	Short:   "List VTEP CIDR and their corresponding VTEP MAC/IP",
	Long:    vtepListUsage,
	Run: func(cmd *cobra.Command, args []string) {
		common.RequireRootPrivilege("cilium bpf vtep list")

		vtepMap, err := vtep.OpenMap(log)
		if err != nil {
			Fatalf("error opening VTEP map: %s", err)
		}

		bpfVtepList := make(map[string][]string)
		if err := vtepMap.Dump(bpfVtepList); err != nil {
			Fatalf("error dumping contents of map: %s", err)
		}

		if command.OutputOption() {
			if err := command.PrintOutput(bpfVtepList); err != nil {
				Fatalf("error getting output of map in %s: %s", command.OutputOptionString(), err)
			}
			return
		}

		if len(bpfVtepList) == 0 {
			fmt.Fprintf(os.Stderr, "No entries found.\n")
		} else {
			TablePrinter(vtepCidrTitle, vtepTitle, bpfVtepList)
		}
	},
}

func init() {
	BPFVtepCmd.AddCommand(bpfVtepListCmd)
	command.AddOutputOption(bpfVtepListCmd)
}
