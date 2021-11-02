// SPDX-License-Identifier: Apache-2.0
// Copyright 2021 Authors of Cilium

package cmd

import (
	"net"

	"github.com/cilium/cilium/pkg/common"
	"github.com/cilium/cilium/pkg/maps/srv6map"

	"github.com/spf13/cobra"
)

const (
	srv6DeleteUsage = "Delete SRv6 policy entries using source IP and destination CIDR.\n"
)

var bpfSRv6DeleteCmd = &cobra.Command{
	Args:  cobra.ExactArgs(2),
	Use:   "delete",
	Short: "Delete SRv6 policy entries",
	Long:  srv6DeleteUsage,
	Run: func(cmd *cobra.Command, args []string) {
		common.RequireRootPrivilege("cilium bpf srv6 delete <src_ip> <dest_cidr>")

		_, cidr, err := net.ParseCIDR(args[1])
		if err != nil {
			Fatalf("error parsing cidr %s: %s", args[1], err)
		}

		sip := net.ParseIP(args[0])
		if sip4 := sip.To4(); sip != nil {
			key := srv6map.NewKey4(sip4, cidr.IP, cidr.Mask)
			if err := srv6map.SRv6Map4.Delete(&key); err != nil {
				Fatalf("error deleting contents of map: %s\n", err)
			}
		} else if sip6 := sip.To16(); sip6 != nil {
			key := srv6map.NewKey6(sip6, cidr.IP, cidr.Mask)
			if err := srv6map.SRv6Map6.Delete(&key); err != nil {
				Fatalf("error deleting contents of map: %s\n", err)
			}
		} else {
			Fatalf("Unable to parse IP '%s'", args[0])
		}
	},
}

func init() {
	bpfSRv6Cmd.AddCommand(bpfSRv6DeleteCmd)
}
