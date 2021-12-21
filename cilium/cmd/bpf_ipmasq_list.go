// SPDX-License-Identifier: Apache-2.0
// Copyright 2020 Authors of Cilium

package cmd

import (
	"fmt"
	"os"

	"github.com/cilium/cilium/pkg/command"
	"github.com/cilium/cilium/pkg/common"
	"github.com/cilium/cilium/pkg/maps/ipmasq"

	"github.com/spf13/cobra"
)

const (
	cidrTitle = "IP PREFIX/ADDRESS"
)

var bpfIPMasqListCmd = &cobra.Command{
	Use:     "list",
	Aliases: []string{"ls"},
	Short:   "List ip-masq-agent CIDRs",
	Long:    "List ip-masq-agent CIDRs. Packets sent from pods to IPs from these CIDRs avoid masquerading.",
	Run: func(cmd *cobra.Command, args []string) {
		common.RequireRootPrivilege("cilium bpf ipmasq list")

		cidrs, err := (&ipmasq.IPMasqBPFMap{}).Dump()
		if err != nil {
			fmt.Fprintf(os.Stderr, "error dumping contents of map: %s\n", err)
			os.Exit(1)
		}

		if command.OutputJSON() {
			if err := command.PrintOutput(cidrs); err != nil {
				fmt.Fprintf(os.Stderr, "error getting output of map in JSON: %s\n", err)
				os.Exit(1)
			}
			return
		}

		tmp := map[string][]string{}
		for _, cidr := range cidrs {
			tmp[cidr.String()] = []string{""}
		}

		if len(cidrs) == 0 {
			fmt.Fprintf(os.Stderr, "No entries found.\n")
		} else {
			TablePrinter(cidrTitle, "", tmp)
		}
	},
}

func init() {
	bpfIPMasqCmd.AddCommand(bpfIPMasqListCmd)
	command.AddJSONOutput(bpfIPMasqListCmd)
}
