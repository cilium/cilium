// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"net/netip"

	"github.com/spf13/cobra"

	"github.com/cilium/cilium/pkg/common"
	"github.com/cilium/cilium/pkg/maps/lxcmap"
)

var bpfEndpointDeleteCmd = &cobra.Command{
	Use:   "delete",
	Short: "Delete local endpoint entries",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		common.RequireRootPrivilege("cilium bpf endpoint delete")

		if args[0] == "" {
			Fatalf("Please specify the endpoint to delete")
		}

		addr, err := netip.ParseAddr(args[0])
		if err != nil {
			Fatalf("Unable to parse IP '%s': %v", args[0], err)
		}

		m, err := lxcmap.OpenMap(log)
		if err != nil {
			Fatalf("Unable to open map: %s", err)
		}

		if err := m.DeleteEntry(addr); err != nil {
			Fatalf("Unable to delete endpoint entry: %s", err)
		}
	},
}

func init() {
	BPFEndpointCmd.AddCommand(bpfEndpointDeleteCmd)
}
