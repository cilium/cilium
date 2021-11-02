// SPDX-License-Identifier: Apache-2.0
// Copyright 2021 Authors of Cilium

package cmd

import (
	"fmt"
	"net"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/common"
	"github.com/cilium/cilium/pkg/maps/srv6map"

	"github.com/spf13/cobra"
)

const (
	srv6GetUsage = "Get SRv6 policy entries using source and destination IPs.\n"
)

var bpfSRv6GetCmd = &cobra.Command{
	Args:    cobra.ExactArgs(2),
	Use:     "get",
	Short:   "Get SRv6 policy entries",
	Aliases: []string{"lookup"},
	Long:    srv6GetUsage,
	Run: func(cmd *cobra.Command, args []string) {
		common.RequireRootPrivilege("cilium bpf srv6 get <src_ip> <dest_ip>")

		var (
			ipv4Mask = net.IPv4Mask(255, 255, 255, 255)
			err      error
			value    bpf.MapValue
		)

		sip := net.ParseIP(args[0])
		if sip4 := sip.To4(); sip4 != nil {
			dip := net.ParseIP(args[1]).To4()
			if dip == nil {
				Fatalf("Unable to parse IP '%s'", args[1])
			}

			key := srv6map.NewKey4(sip, dip, ipv4Mask)

			if value, err = srv6map.SRv6Map4.Lookup(&key); err != nil {
				Fatalf("error lookup contents of map: %s\n", err)
			}
		} else if sip6 := sip.To16(); sip6 != nil {
			dip := net.ParseIP(args[1]).To16()
			if dip == nil {
				Fatalf("Unable to parse IP '%s'", args[1])
			}

			key := srv6map.NewKey6(sip, dip, ipv4Mask)

			if value, err = srv6map.SRv6Map6.Lookup(&key); err != nil {
				Fatalf("error lookup contents of map: %s\n", err)
			}
		} else {
			Fatalf("Unable to parse IP '%s'", args[0])
		}

		fmt.Println(value.String())
	},
}

func init() {
	bpfSRv6Cmd.AddCommand(bpfSRv6GetCmd)
}
