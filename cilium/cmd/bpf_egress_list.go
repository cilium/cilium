// SPDX-License-Identifier: Apache-2.0
// Copyright 2021 Authors of Cilium

package cmd

import (
	"fmt"
	"os"

	"github.com/cilium/cilium/pkg/command"
	"github.com/cilium/cilium/pkg/common"
	"github.com/cilium/cilium/pkg/maps/egressmap"

	"github.com/spf13/cobra"
)

const (
	egressListUsage = "List egress entries.\n" + lpmWarningMessage
)

var bpfEgressListCmd = &cobra.Command{
	Use:     "list",
	Aliases: []string{"ls"},
	Short:   "List egress entries",
	Long:    egressListUsage,
	Run: func(cmd *cobra.Command, args []string) {
		common.RequireRootPrivilege("cilium bpf egress list")

		bpfEgressList := make(map[string][]string)
		if err := egressmap.EgressMap.Dump(bpfEgressList); err != nil {
			Fatalf("error dumping contents of map: %s\n", err)
		}

		if command.OutputJSON() {
			if err := command.PrintOutput(bpfEgressList); err != nil {
				Fatalf("error getting output of map in JSON: %s\n", err)
			}
			return
		}

		if len(bpfEgressList) == 0 {
			fmt.Fprintf(os.Stderr, "No entries found.\n%v\n", lpmWarningMessage)
		} else {
			TablePrinter("SRC IP & DST CIDR", "EGRESS INFO", bpfEgressList)
		}
	},
}

func init() {

	bpfEgressCmd.AddCommand(bpfEgressListCmd)
	command.AddJSONOutput(bpfEgressListCmd)
}
