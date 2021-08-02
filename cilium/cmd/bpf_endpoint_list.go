// SPDX-License-Identifier: Apache-2.0
// Copyright 2017 Authors of Cilium

package cmd

import (
	"os"

	"github.com/cilium/cilium/pkg/command"
	"github.com/cilium/cilium/pkg/common"
	"github.com/cilium/cilium/pkg/maps/lxcmap"

	"github.com/spf13/cobra"
)

const (
	ipAddressTitle         = "IP ADDRESS"
	localEndpointInfoTitle = "LOCAL ENDPOINT INFO"
)

var bpfEndpointListCmd = &cobra.Command{
	Use:     "list",
	Aliases: []string{"ls"},
	Short:   "List local endpoint entries",
	Run: func(cmd *cobra.Command, args []string) {
		common.RequireRootPrivilege("cilium bpf endpoint list")

		bpfEndpointList := make(map[string][]string)
		if err := lxcmap.LXCMap.Dump(bpfEndpointList); err != nil {
			os.Exit(1)
		}

		if command.OutputJSON() {
			if err := command.PrintOutput(bpfEndpointList); err != nil {
				os.Exit(1)
			}
			return
		}

		TablePrinter(ipAddressTitle, localEndpointInfoTitle, bpfEndpointList)
	},
}

func init() {
	bpfEndpointCmd.AddCommand(bpfEndpointListCmd)
	command.AddJSONOutput(bpfEndpointListCmd)
}
