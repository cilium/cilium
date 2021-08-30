// SPDX-License-Identifier: Apache-2.0
// Copyright 2021 Authors of Cilium

package cmd

import (
	"fmt"
	"net"

	"github.com/cilium/cilium/pkg/common"
	"github.com/cilium/cilium/pkg/maps/egressmap"

	"github.com/spf13/cobra"
)

const (
	egressGetUsage = "Get egress policy entries using source and destination IPs.\n"
)

var bpfEgressGetCmd = &cobra.Command{
	Args:    cobra.ExactArgs(2),
	Use:     "get",
	Short:   "Get egress policy entry",
	Aliases: []string{"lookup"},
	Long:    egressGetUsage,
	Run: func(cmd *cobra.Command, args []string) {
		common.RequireRootPrivilege("cilium bpf egress get <source IP> <destination IP>")

		egressmap.OpenEgressMaps()

		sourceIP := net.ParseIP(args[0]).To4()
		if sourceIP == nil {
			Fatalf("Unable to parse source IP '%s'", args[0])
		}

		destIP := net.ParseIP(args[1]).To4()
		if destIP == nil {
			Fatalf("Unable to parse destination IP '%s'", args[1])
		}

		val, err := egressmap.EgressPolicyMap.Lookup(sourceIP, net.IPNet{
			IP:   destIP,
			Mask: net.IPv4Mask(255, 255, 255, 255),
		})
		if err != nil {
			Fatalf("Error looking up egress policy map: %s\n", err)
		}

		fmt.Printf("Egress IP: %s\n", val.EgressIP)

		fmt.Printf("Gateway IPs:\n")
		for i := uint32(0); i < val.Size; i++ {
			fmt.Printf("\t%s\n", val.GatewayIPs[i].String())
		}
	},
}

func init() {
	bpfEgressCmd.AddCommand(bpfEgressGetCmd)
}
