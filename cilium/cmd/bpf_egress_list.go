// SPDX-License-Identifier: Apache-2.0
// Copyright 2021 Authors of Cilium

package cmd

import (
	"fmt"
	"net"
	"os"
	"text/tabwriter"

	"github.com/cilium/cilium/pkg/command"
	"github.com/cilium/cilium/pkg/common"
	"github.com/cilium/cilium/pkg/maps/egressmap"

	"github.com/spf13/cobra"
)

const (
	egressListUsage = "List egress policy entries.\n" + lpmWarningMessage
)

type EgressPolicy struct {
	SourceIP string
	DestCIDR string
	EgressIP string
	Gateways []string
}

var bpfEgressListCmd = &cobra.Command{
	Use:     "list",
	Aliases: []string{"ls"},
	Short:   "List egress policy entries",
	Long:    egressListUsage,
	Run: func(cmd *cobra.Command, args []string) {
		common.RequireRootPrivilege("cilium bpf egress list")

		egressmap.OpenEgressMaps()

		bpfEgressList := []EgressPolicy{}
		parse := func(key *egressmap.EgressPolicyKey4, val *egressmap.EgressPolicyVal4) {
			gatewayIPs := []string{}
			for i := uint32(0); i < val.Size; i++ {
				gatewayIPs = append(gatewayIPs, val.GatewayIPs[i].String())
			}

			destCIDR := &net.IPNet{
				IP:   key.DestCIDR.IP(),
				Mask: net.CIDRMask(int(key.PrefixLen-egressmap.PolicyStaticPrefixBits), 32),
			}

			bpfEgressList = append(bpfEgressList, EgressPolicy{
				SourceIP: key.SourceIP.String(),
				DestCIDR: destCIDR.String(),
				EgressIP: val.EgressIP.String(),
				Gateways: gatewayIPs,
			})
		}

		if err := egressmap.EgressPolicyMap.IterateWithCallback(parse); err != nil {
			Fatalf("Error dumping contents of egress policy map: %s\n", err)
		}

		if command.OutputJSON() {
			if err := command.PrintOutput(bpfEgressList); err != nil {
				Fatalf("error getting output of map in JSON: %s\n", err)
			}
			return
		}

		if len(bpfEgressList) == 0 {
			fmt.Fprintf(os.Stderr, "No entries found.\n%v\n", lpmWarningMessage)
		} else {
			printEgressList(bpfEgressList)
		}
	},
}

func printEgressList(egressList []EgressPolicy) {
	w := tabwriter.NewWriter(os.Stdout, 5, 0, 3, ' ', 0)

	fmt.Fprintln(w, "Source IP\tDestination CIDR\tEgress IP\tGateway\t")
	for _, ep := range egressList {
		fmt.Fprintf(w, "%s\t%s\t%s\t0 => %s\n", ep.SourceIP, ep.DestCIDR, ep.EgressIP, ep.Gateways[0])
		for i := 1; i < len(ep.Gateways); i++ {
			fmt.Fprintf(w, "\t\t\t%d => %s\n", i, ep.Gateways[i])
		}
	}

	w.Flush()
}

func init() {
	bpfEgressCmd.AddCommand(bpfEgressListCmd)
	command.AddJSONOutput(bpfEgressListCmd)
}
