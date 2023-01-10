// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"github.com/spf13/cobra"

	"github.com/cilium/cilium/pkg/cidr"
	"github.com/cilium/cilium/pkg/common"
	"github.com/cilium/cilium/pkg/maps/vtep"
)

const (
	vtepDeleteUsage = "Delete vtep entries using vtep CIDR.\n"
)

var bpfVtepDeleteCmd = &cobra.Command{
	Args:  cobra.ExactArgs(1),
	Use:   "delete",
	Short: "Delete vtep entries",
	Long:  vtepDeleteUsage,
	Run: func(cmd *cobra.Command, args []string) {
		common.RequireRootPrivilege("cilium bpf vtep delete <vtep_cidr>")

		vcidr, err := cidr.ParseCIDR(args[0])
		if err != nil {
			Fatalf("error parsing cidr %s: %s", args[0], err)
		}

		key := vtep.NewKey(vcidr.IP)

		if err := vtep.VtepMap().Delete(&key); err != nil {
			Fatalf("error deleting contents of map: %s\n", err)
		}
	},
}

func init() {
	bpfVtepCmd.AddCommand(bpfVtepDeleteCmd)
}
