// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"fmt"
	"net/netip"
	"os"

	"github.com/spf13/cobra"

	"github.com/cilium/cilium/pkg/common"
	"github.com/cilium/cilium/pkg/maps/crap"
)

const (
	crapUpdateUsage = "Create/Update CRAP entry.\n"
)

var bpfCrapUpdateCmd = &cobra.Command{
	Args:    cobra.ExactArgs(2),
	Use:     "update",
	Short:   "Update CRAP entries",
	Aliases: []string{"add"},
	Long:    crapUpdateUsage,
	Run: func(cmd *cobra.Command, args []string) {
		common.RequireRootPrivilege("cilium bpf crap update <public_ip> <pod_ip>")

		crap, err := crap.OpenPinnedCrapMap(log)
		if err != nil {
			Fatalf("Unable to open map: %s", err)
		}

		dst_ip, err := netip.ParseAddr(args[0])
		if err != nil {
			Fatalf("Unable to parse public IP '%s'", args[0])
		}

		pod_ip, err := netip.ParseAddr(args[1])
		if err != nil {
			Fatalf("Unable to parse pod IP '%s'", args[1])
		}

		if err := crap.UpdateCrapMapping(dst_ip, pod_ip); err != nil {
			fmt.Fprintf(os.Stderr, "error updating contents of map: %s\n", err)
			os.Exit(1)
		}
	},
}

func init() {
	BPFCrapCmd.AddCommand(bpfCrapUpdateCmd)
}
