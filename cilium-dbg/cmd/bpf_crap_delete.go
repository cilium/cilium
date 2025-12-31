// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"net/netip"

	"github.com/spf13/cobra"

	"github.com/cilium/cilium/pkg/common"
	"github.com/cilium/cilium/pkg/maps/crap"
)

const (
	crapRuleDelUsage = "Delete the CRAP rule.\n"
)

var bpfCrapDeleteCmd = &cobra.Command{
	Args:  cobra.ExactArgs(1),
	Use:   "delete",
	Short: "Delete crap entries",
	Long:  crapRuleDelUsage,
	Run: func(cmd *cobra.Command, args []string) {
		common.RequireRootPrivilege("cilium bpf crap delete <public_ip>")

		vtep, err := crap.OpenPinnedCrapMap(log)
		if err != nil {
			Fatalf("Unable to open map: %s", err)
		}

		dst_ip, err := netip.ParseAddr(args[0])
		if err != nil {
			Fatalf("Unable to parse IP '%s'", args[0])
		}

		if err := vtep.RemoveCrapMapping(dst_ip); err != nil {
			Fatalf("error deleting contents of map: %s\n", err)
		}
	},
}

func init() {
	BPFCrapCmd.AddCommand(bpfCrapDeleteCmd)
}
