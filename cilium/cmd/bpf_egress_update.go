// SPDX-License-Identifier: Apache-2.0
// Copyright 2021 Authors of Cilium

package cmd

import (
	"fmt"
	"net"
	"os"

	"github.com/cilium/cilium/pkg/common"
	"github.com/cilium/cilium/pkg/maps/egressmap"

	"github.com/spf13/cobra"
)

const (
	egressUpdateUsage = "Create/Update egress entry.\n"
)

var bpfEgressUpdateCmd = &cobra.Command{
	Args:    cobra.MinimumNArgs(4),
	Use:     "update",
	Short:   "Update egress entries",
	Aliases: []string{"add"},
	Long:    egressUpdateUsage,
	Run: func(cmd *cobra.Command, args []string) {
		common.RequireRootPrivilege("cilium bpf egress update <source IP> <destination CIDR> <egress IP> <gateway IPs>...")

		egressmap.OpenEgressMaps()

		sourceIP := net.ParseIP(args[0]).To4()
		if sourceIP == nil {
			Fatalf("Unable to parse source IP '%s'", args[0])
		}

		_, destCIDR, err := net.ParseCIDR(args[1])
		if err != nil {
			Fatalf("Unable to parse destination CIDR '%s': %s", args[1], err)
		}

		egressIP := net.ParseIP(args[2]).To4()
		if egressIP == nil {
			Fatalf("Unable to parse egress IP '%s'", args[2])
		}

		gatewayIPs := []net.IP{}
		for i := 3; i < len(args); i++ {
			gatewayIP := net.ParseIP(args[i]).To4()
			if gatewayIP == nil {
				Fatalf("Unable to parse gateway IP '%s'", args[i])
			}
			gatewayIPs = append(gatewayIPs, gatewayIP)
		}

		for _, gatewayIP := range gatewayIPs {
			if err := egressmap.InsertEgressGateway(sourceIP, *destCIDR, egressIP, gatewayIP); err != nil {
				fmt.Fprintf(os.Stderr, "Cannot update egress policy map: %s\n", err)
				os.Exit(1)
			}
		}
	},
}

func init() {
	bpfEgressCmd.AddCommand(bpfEgressUpdateCmd)
}
