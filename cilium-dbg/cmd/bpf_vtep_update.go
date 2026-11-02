// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"net/netip"

	"github.com/spf13/cobra"

	"github.com/cilium/cilium/pkg/common"
	"github.com/cilium/cilium/pkg/mac"
	"github.com/cilium/cilium/pkg/maps/vtep"
)

const (
	vtepUpdateUsage = "Create/Update vtep entry.\n"
)

var bpfVtepUpdateCmd = &cobra.Command{
	Args:    cobra.ExactArgs(3),
	Use:     "update",
	Short:   "Update vtep entries",
	Aliases: []string{"add"},
	Long:    vtepUpdateUsage,
	Run: func(cmd *cobra.Command, args []string) {
		common.RequireRootPrivilege("cilium bpf vtep update <vtep_cidr> <vtep_ip> <vtep_mac>")

		vcidr, err := netip.ParsePrefix(args[0])
		if err != nil {
			Fatalf("error parsing cidr %s: %s", args[0], err)
		}

		vip, err := netip.ParseAddr(args[1])
		if err != nil || !vip.Is4() {
			Fatalf("Unable to parse IP '%s'", args[1])
		}

		vmac, err := mac.ParseMAC(args[2])
		if err != nil {
			Fatalf("Unable to parse vtep mac '%s'", args[2])
		}

		vtepMap, err := vtep.OpenMap(log)
		if err != nil {
			Fatalf("error opening VTEP map: %s", err)
		}

		if err := vtepMap.Update(vcidr, vip, vmac); err != nil {
			Fatalf("error updating contents of map: %s", err)
		}
	},
}

func init() {
	BPFVtepCmd.AddCommand(bpfVtepUpdateCmd)
}
