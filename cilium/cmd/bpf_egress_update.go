// SPDX-License-Identifier: Apache-2.0
// Copyright 2021 Authors of Cilium

package cmd

import (
	"fmt"
	"net"
	"os"

	"github.com/spf13/cobra"

	"github.com/cilium/cilium/pkg/common"
	"github.com/cilium/cilium/pkg/maps/egressmap"
)

const (
	egressUpdateUsage = "Create/Update egress entry.\n"
)

var bpfEgressUpdateCmd = &cobra.Command{
	Args:    cobra.ExactArgs(4),
	Use:     "update",
	Short:   "Update egress entries",
	Aliases: []string{"add"},
	Long:    egressUpdateUsage,
	Run: func(cmd *cobra.Command, args []string) {
		common.RequireRootPrivilege("cilium bpf egress update <src_ip> <dest_cidr> <gw_ip> <egress_ip>")

		sip := net.ParseIP(args[0]).To4()
		if sip == nil {
			Fatalf("Unable to parse IP '%s'", args[0])
		}

		_, cidr, err := net.ParseCIDR(args[1])
		if err != nil {
			Fatalf("error parsing cidr %s: %s", args[1], err)
		}

		gwip := net.ParseIP(args[2]).To4()
		if gwip == nil {
			Fatalf("Unable to parse IP '%s'", args[2])
		}

		eip := net.ParseIP(args[3]).To4()
		if eip == nil {
			Fatalf("Unable to parse IP '%s'", args[3])
		}

		if err := egressmap.EgressPolicyMap.Update(sip, *cidr, gwip, eip); err != nil {
			fmt.Fprintf(os.Stderr, "error updating contents of map: %s\n", err)
			os.Exit(1)
		}
	},
}

func init() {
	bpfEgressCmd.AddCommand(bpfEgressUpdateCmd)
}
