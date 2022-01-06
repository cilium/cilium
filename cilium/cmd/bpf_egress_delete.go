// SPDX-License-Identifier: Apache-2.0
// Copyright 2021 Authors of Cilium

package cmd

import (
	"net"

	"github.com/spf13/cobra"

	"github.com/cilium/cilium/pkg/common"
	"github.com/cilium/cilium/pkg/maps/egressmap"
)

const (
	egressDeleteUsage = "Delete egress entries using source IP and destination CIDR.\n"
)

var bpfEgressDeleteCmd = &cobra.Command{
	Args:  cobra.ExactArgs(2),
	Use:   "delete",
	Short: "Delete egress entries",
	Long:  egressDeleteUsage,
	Run: func(cmd *cobra.Command, args []string) {
		common.RequireRootPrivilege("cilium bpf egress delete <src_ip> <dest_cidr>")

		sip := net.ParseIP(args[0]).To4()
		if sip == nil {
			Fatalf("Unable to parse IP '%s'", args[0])
		}

		_, cidr, err := net.ParseCIDR(args[1])
		if err != nil {
			Fatalf("error parsing cidr %s: %s", args[1], err)
		}

		if err := egressmap.EgressPolicyMap.Delete(sip, *cidr); err != nil {
			Fatalf("error deleting contents of map: %s\n", err)
		}
	},
}

func init() {
	bpfEgressCmd.AddCommand(bpfEgressDeleteCmd)
}
