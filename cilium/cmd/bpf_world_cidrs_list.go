// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"errors"
	"fmt"
	"io/fs"
	"net/netip"
	"os"

	"github.com/cilium/cilium/pkg/command"
	"github.com/cilium/cilium/pkg/common"
	"github.com/cilium/cilium/pkg/maps/worldcidrsmap"

	"github.com/spf13/cobra"
)

const (
	worldCIDRsListUsage = "List world CIDRs."

	prefixTitle  = "PREFIX"
	encapEnabled = "ENCAPSULATE"
)

var BPFWorldCIDRsListCmd = &cobra.Command{
	Use:     "list",
	Aliases: []string{"ls"},
	Short:   "List world CIDRs",
	Long:    worldCIDRsListUsage,
	Run: func(cmd *cobra.Command, args []string) {
		common.RequireRootPrivilege("cilium bpf world list")

		wcm, err := worldcidrsmap.LoadWorldCIDRsMap()

		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				fmt.Fprintln(os.Stderr, "Cannot find world CIDR map")
				return
			}

			Fatalf("Cannot open world CIDR map: %s", err)
		}

		bpfCIDRList := map[string][]string{}
		parse := func(key netip.Prefix, encap bool) {
			v := "no"
			if encap {
				v = "yes"
			}
			bpfCIDRList[key.String()] = []string{v}
		}

		if err := wcm.IterateWithCallback(parse); err != nil {
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
			TablePrinter(prefixTitle, encapEnabled, bpfCIDRList)
		}
	},
}

func init() {
	BPFWorldCIDRCmd.AddCommand(BPFWorldCIDRsListCmd)
	command.AddOutputOption(BPFWorldCIDRsListCmd)
}
