// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/cilium/cilium/pkg/command"
	"github.com/cilium/cilium/pkg/common"
	"github.com/cilium/cilium/pkg/maps/ipmasq"
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

		// Depending on whether BPF masquerading is enabled for IPv4
		// and IPv6, we may have zero, one, or two maps to dump, and we
		// need to tell which ones to DumpForProtocols().
		// Here we try to open the maps as a hack to avoid going
		// through a full API request to check the config options from
		// the agent.
		ipv4Needed := ipmasq.IPMasq4Map().Open() == nil
		ipv6Needed := ipmasq.IPMasq6Map().Open() == nil
		cidrs, err := (&ipmasq.IPMasqBPFMap{}).DumpForProtocols(ipv4Needed, ipv6Needed)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error dumping contents of map: %s\n", err)
			os.Exit(1)
		}

		if command.OutputOption() {
			if err := command.PrintOutput(cidrs); err != nil {
				fmt.Fprintf(os.Stderr, "error getting output of map in %s: %s\n", command.OutputOptionString(), err)
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
	BPFIPMasqCmd.AddCommand(bpfIPMasqListCmd)
	command.AddOutputOption(bpfIPMasqListCmd)
}
