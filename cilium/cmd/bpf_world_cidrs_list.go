// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"text/tabwriter"

	"github.com/cilium/cilium/pkg/command"
	"github.com/cilium/cilium/pkg/common"
	"github.com/cilium/cilium/pkg/maps/worldcidrsmap"

	"github.com/spf13/cobra"
)

const (
	worldCIDRsListUsage = "List world CIDRs."
)

var bpfWorldCIDRsListCmd = &cobra.Command{
	Use:     "list",
	Aliases: []string{"ls"},
	Short:   "List world CIDRs",
	Long:    worldCIDRsListUsage,
	Run: func(cmd *cobra.Command, args []string) {
		common.RequireRootPrivilege("cilium bpf world list")

		if err := worldcidrsmap.OpenWorldCIDRsMap(); err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				fmt.Fprintln(os.Stderr, "Cannot find world CIDR map")
				return
			}

			Fatalf("Cannot open world CIDR map: %s", err)
		}

		bpfCIDRList := []string{}
		parse := func(key *worldcidrsmap.WorldCIDRKey4, val *worldcidrsmap.WorldCIDRVal) {
			bpfCIDRList = append(bpfCIDRList, key.GetCIDR().String())
		}

		if err := worldcidrsmap.WorldCIDRsMap.IterateWithCallback(parse); err != nil {
			Fatalf("Error dumping contents of the IPv4 world CIDR map: %s\n", err)
		}

		if command.OutputOption() {
			if err := command.PrintOutput(bpfCIDRList); err != nil {
				Fatalf("error getting output of map in JSON: %s\n", err)
			}
			return
		}

		if len(bpfCIDRList) == 0 {
			fmt.Fprintf(os.Stderr, "No entries found.\n")
		} else {
			printWorldCIDRList(bpfCIDRList)
		}
	},
}

func printWorldCIDRList(cidrList []string) {
	w := tabwriter.NewWriter(os.Stdout, 5, 0, 3, ' ', 0)

	fmt.Fprintln(w, "World CIDR")
	for _, cidr := range cidrList {
		fmt.Fprintf(w, "%s\n", cidr)
	}

	w.Flush()
}

func init() {
	bpfWorldCIDRCmd.AddCommand(bpfWorldCIDRsListCmd)
	command.AddOutputOption(bpfWorldCIDRsListCmd)
}
