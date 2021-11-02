// SPDX-License-Identifier: Apache-2.0
// Copyright 2021 Authors of Cilium

package cmd

import (
	"fmt"
	"net"
	"os"

	"github.com/cilium/cilium/pkg/common"
	"github.com/cilium/cilium/pkg/maps/srv6map"

	"github.com/spf13/cobra"
)

const (
	srv6UpdateUsage = "Create/Update SRv6 policy entry.\n"
)

var bpfSRv6UpdateCmd = &cobra.Command{
	Args:    cobra.ExactArgs(4),
	Use:     "update",
	Short:   "Update SRv6 policy entries",
	Aliases: []string{"add"},
	Long:    srv6UpdateUsage,
	Run: func(cmd *cobra.Command, args []string) {
		common.RequireRootPrivilege("cilium bpf srv6 update <src_ip> <dest_cidr> <sid>")

		_, cidr, err := net.ParseCIDR(args[1])
		if err != nil {
			Fatalf("error parsing cidr %s: %s", args[1], err)
		}

		sid := net.ParseIP(args[2]).To16()
		if sid == nil {
			Fatalf("Unable to parse SID '%s'", args[3])
		}
		value := &srv6map.Value{}
		copy(value.SID[:], sid)

		sip := net.ParseIP(args[0])
		if sip4 := sip.To4(); sip4 != nil {
			key := srv6map.NewKey4(sip4, cidr.IP, cidr.Mask)
			if err := srv6map.SRv6Map4.Update(&key, value); err != nil {
				fmt.Fprintf(os.Stderr, "error updating contents of map: %s\n", err)
				os.Exit(1)
			}
		} else if sip6 := sip.To16(); sip6 != nil {
			key := srv6map.NewKey6(sip6, cidr.IP, cidr.Mask)
			if err := srv6map.SRv6Map6.Update(&key, value); err != nil {
				fmt.Fprintf(os.Stderr, "error updating contents of map: %s\n", err)
				os.Exit(1)
			}
		} else {
			Fatalf("Unable to parse IP '%s'", args[0])
		}
	},
}

func init() {
	bpfSRv6Cmd.AddCommand(bpfSRv6UpdateCmd)
}
