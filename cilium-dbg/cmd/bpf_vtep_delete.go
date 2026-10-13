// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"net/netip"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/cilium/cilium/pkg/common"
	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/maps/vtep"
)

const (
	vtepDeleteUsage = "Delete vtep entries using vtep CIDR.\n" +
		"The VTEP mask is read from the local agent runtime configuration.\n"
)

var bpfVtepDeleteCmd = &cobra.Command{
	Args:  cobra.ExactArgs(1),
	Use:   "delete",
	Short: "Delete vtep entries",
	Long:  vtepDeleteUsage,
	Run: func(cmd *cobra.Command, args []string) {
		common.RequireRootPrivilege("cilium bpf vtep delete <vtep_cidr>")

		vcidr, err := netip.ParsePrefix(args[0])
		if err != nil {
			Fatalf("error parsing cidr %s: %s", args[0], err)
		}

		if err := loadVTEPMask(filepath.Join(defaults.RuntimePath, defaults.StateDir, "agent-runtime-config.json")); err != nil {
			Fatalf("Unable to load VTEP mask: %s", err)
		}

		if err := vtep.LoadVTEPMap(log).Delete(vcidr.Addr()); err != nil {
			Fatalf("error deleting contents of map: %s\n", err)
		}
	},
}

func init() {
	BPFVtepCmd.AddCommand(bpfVtepDeleteCmd)
}
