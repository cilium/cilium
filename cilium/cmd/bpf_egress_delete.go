// SPDX-License-Identifier: Apache-2.0
// Copyright 2021 Authors of Cilium

package cmd

import (
	"net"

	"github.com/cilium/cilium/pkg/common"
	"github.com/cilium/cilium/pkg/maps/egressmap"

	"github.com/spf13/cobra"
)

const (
	egressDeleteUsage = "Delete egress policy/gateway entries using source IP and destination CIDR.\n"
)

var bpfEgressDeleteCmd = &cobra.Command{
	Args:  cobra.MinimumNArgs(2),
	Use:   "delete",
	Short: "Delete egress policy/gateway entries",
	Long:  egressDeleteUsage,
	Run: func(cmd *cobra.Command, args []string) {
		common.RequireRootPrivilege("cilium bpf egress delete <Source IP> <Destination CIDR> [<Gateway>..]")
		egressmap.OpenEgressMaps()

		sourceIP := net.ParseIP(args[0]).To4()
		if sourceIP == nil {
			Fatalf("Unable to parse source IP '%s'", args[0])
		}

		_, destCIDR, err := net.ParseCIDR(args[1])
		if err != nil {
			Fatalf("Unable to parse destination CIDR '%s': %s", args[1], err)
		}

		if len(args)-2 == 0 {
			// No gateway IP(s) specified, delete the entire policy
			if err := egressmap.RemoveEgressPolicy(sourceIP, *destCIDR); err != nil {
				Fatalf("Error removing egress policy: %s\n", err)
			}
		} else {
			for i := 2; i < len(args); i++ {
				gatewayIP := net.ParseIP(args[i]).To4()
				if gatewayIP == nil {
					Fatalf("Unable to parse gateway IP '%s'", args[i])
				}

				if err := egressmap.RemoveEgressGateway(sourceIP, *destCIDR, gatewayIP); err != nil {
					Fatalf("Error removing gateway from egress policy: %s\n", err)
				}
			}
		}
	},
}

func init() {
	bpfEgressCmd.AddCommand(bpfEgressDeleteCmd)
}
