// Copyright 2021 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package cmd

import (
	"fmt"
	"net"

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
			value    *egressmap.EgressPolicyVal4
		)

		sip := net.ParseIP(args[0]).To4()
		if sip == nil {
			Fatalf("Unable to parse IP '%s'", args[0])
		}

		dip := net.ParseIP(args[1]).To4()
		if dip == nil {
			Fatalf("Unable to parse IP '%s'", args[1])
		}

		if value, err = egressmap.EgressPolicyMap.Lookup(sip, net.IPNet{IP: dip, Mask: ipv4Mask}); err != nil {
			Fatalf("error lookup contents of map: %s\n", err)
		}

		fmt.Println(value.String())
	},
}

func init() {
	bpfEgressCmd.AddCommand(bpfEgressGetCmd)
}
