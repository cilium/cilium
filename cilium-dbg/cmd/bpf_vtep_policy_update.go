// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"fmt"
	"net/netip"
	"os"

	"github.com/spf13/cobra"

	"github.com/cilium/cilium/pkg/common"
	"github.com/cilium/cilium/pkg/mac"
	"github.com/cilium/cilium/pkg/maps/vtep_policy"
)

const (
	vtepPolUpdateUsage = "Create/Update vtep entry.\n"
)

var bpfVtepPolicyUpdateCmd = &cobra.Command{
	Args:    cobra.ExactArgs(4),
	Use:     "update",
	Short:   "Update VTEP Policy entries",
	Aliases: []string{"add"},
	Long:    vtepPolUpdateUsage,
	Run: func(cmd *cobra.Command, args []string) {
		common.RequireRootPrivilege("cilium bpf vtep-policy update <src_ip> <dst_cidr> <vtep_ip> <vtep_rmac>")

		vtep, err := vtep_policy.OpenPinnedVtepPolicyMap(log)
		if err != nil {
			Fatalf("Unable to open map: %s", err)
		}

		src_ip, err := netip.ParseAddr(args[0])
		if err != nil {
			Fatalf("Unable to parse IP '%s'", args[0])
		}

		dst_cidr, err := netip.ParsePrefix(args[1])
		if err != nil {
			Fatalf("error parsing cidr %s: %s", args[1], err)
		}

		vtep_ip, err := netip.ParseAddr(args[2])
		if err != nil {
			Fatalf("Unable to parse IP '%s'", args[2])
		}

		rmac, err := mac.ParseMAC(args[3])
		if err != nil {
			Fatalf("Unable to parse vtep mac '%s'", args[3])
		}

		if err := vtep.UpdateVtepPolicyMapping(src_ip, dst_cidr, vtep_ip, rmac); err != nil {
			fmt.Fprintf(os.Stderr, "error updating contents of map: %s\n", err)
			os.Exit(1)
		}
	},
}

func init() {
	BPFVtepPolicyCmd.AddCommand(bpfVtepPolicyUpdateCmd)
}
