// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"os"

	"github.com/spf13/cobra"

	"github.com/cilium/cilium/pkg/command"
	"github.com/cilium/cilium/pkg/common"
	"github.com/cilium/cilium/pkg/maps/tunnel"
)

const (
	tunnelTitle      = "TUNNEL"
	destinationTitle = "VALUE"
)

var bpfTunnelListCmd = &cobra.Command{
	Use:     "list",
	Aliases: []string{"ls"},
	Short:   "List tunnel endpoint entries",
	Run: func(cmd *cobra.Command, args []string) {
		common.RequireRootPrivilege("cilium bpf tunnel list")

		tunnelList := make(map[string][]string)
		if err := tunnel.TunnelMap().Dump(tunnelList); err != nil {
			os.Exit(1)
		}

		if command.OutputOption() {
			if err := command.PrintOutput(tunnelList); err != nil {
				os.Exit(1)
			}
			return
		}

		TablePrinter(tunnelTitle, destinationTitle, tunnelList)
	},
}

func init() {
	bpfTunnelCmd.AddCommand(bpfTunnelListCmd)
	command.AddOutputOption(bpfTunnelListCmd)
}
