// SPDX-License-Identifier: Apache-2.0
// Copyright 2021 Authors of Cilium

package cmd

import (
	"fmt"
	"os"

	"github.com/cilium/cilium/pkg/command"
	"github.com/cilium/cilium/pkg/common"
	"github.com/cilium/cilium/pkg/maps/srv6map"

	"github.com/spf13/cobra"
)

const (
	srv6ListUsage = "List SRv6 policy entries.\n" + lpmWarningMessage
)

var bpfSRv6ListCmd = &cobra.Command{
	Use:     "list",
	Aliases: []string{"ls"},
	Short:   "List SRv6 policy entries",
	Long:    srv6ListUsage,
	Run: func(cmd *cobra.Command, args []string) {
		common.RequireRootPrivilege("cilium bpf srv6 list")

		bpfSRv6List := make(map[string][]string)
		if err := srv6map.SRv6Map4.Dump(bpfSRv6List); err != nil {
			Fatalf("error dumping contents of IPv4 map: %s\n", err)
		}
		if err := srv6map.SRv6Map6.Dump(bpfSRv6List); err != nil {
			Fatalf("error dumping contents of IPv6 map: %s\n", err)
		}

		if command.OutputJSON() {
			if err := command.PrintOutput(bpfSRv6List); err != nil {
				Fatalf("error getting output of maps in JSON: %s\n", err)
			}
			return
		}

		if len(bpfSRv6List) == 0 {
			fmt.Fprintf(os.Stderr, "No entries found.\n%v\n", lpmWarningMessage)
		} else {
			TablePrinter("SRC IP & DST CIDR", "SID", bpfSRv6List)
		}
	},
}

func init() {
	bpfSRv6Cmd.AddCommand(bpfSRv6ListCmd)
	command.AddJSONOutput(bpfSRv6ListCmd)
}
