// SPDX-License-Identifier: Apache-2.0
// Copyright 2021 Authors of Cilium

package cmd

import (
	"fmt"
	"net"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/common"
	"github.com/cilium/cilium/pkg/maps/egressmap"

	"github.com/spf13/cobra"
)

const (
	egressGetUsage = "Get egress entries using source and destination IPs.\n"
)

var bpfEgressGetCmd = &cobra.Command{
	Args:    cobra.ExactArgs(2),
	Use:     "get",
	Short:   "Get egress entries",
	Aliases: []string{"lookup"},
	Long:    egressGetUsage,
	Run: func(cmd *cobra.Command, args []string) {
		common.RequireRootPrivilege("cilium bpf egress get <src_ip> <dest_ip>")

		var (
			ipv4Mask = net.IPv4Mask(255, 255, 255, 255)
			err      error
			value    bpf.MapValue
		)

		sip := net.ParseIP(args[0]).To4()
		if sip == nil {
			Fatalf("Unable to parse IP '%s'", args[0])
		}

		dip := net.ParseIP(args[1]).To4()
		if dip == nil {
			Fatalf("Unable to parse IP '%s'", args[1])
		}

		key := egressmap.NewKey(sip, dip, ipv4Mask)

		if value, err = egressmap.EgressMap.Lookup(&key); err != nil {
			Fatalf("error lookup contents of map: %s\n", err)
		}

		fmt.Println(value.String())
	},
}

func init() {
	bpfEgressCmd.AddCommand(bpfEgressGetCmd)
}
