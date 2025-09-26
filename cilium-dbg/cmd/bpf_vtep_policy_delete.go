// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"net/netip"

	"github.com/spf13/cobra"

	"github.com/cilium/cilium/pkg/common"
	"github.com/cilium/cilium/pkg/maps/vtep_policy"
)

const (
	vtepPolicyDelUsage = "Delete vtep entries using vtep CIDR.\n"
)

var bpfVtepPolicyDeleteCmd = &cobra.Command{
	Args:  cobra.ExactArgs(2),
	Use:   "delete",
	Short: "Delete VTEP Policy entries",
	Long:  vtepPolicyDelUsage,
	Run: func(cmd *cobra.Command, args []string) {
		common.RequireRootPrivilege("cilium bpf vtep-policy delete <vtep_cidr>")

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

		if err := vtep.RemoveVtepPolicyMapping(src_ip, dst_cidr); err != nil {
			Fatalf("error deleting contents of map: %s\n", err)
		}
	},
}

func init() {
	BPFVtepPolicyCmd.AddCommand(bpfVtepPolicyDeleteCmd)
}
