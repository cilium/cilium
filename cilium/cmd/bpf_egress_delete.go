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
	"net"

	"github.com/cilium/cilium/pkg/common"
	"github.com/cilium/cilium/pkg/maps/egressmap"

	"github.com/spf13/cobra"
)

const (
	egressDeleteUsage = "Delete egress entries using source IP and destination CIDR.\n"
)

var bpfEgressDeleteCmd = &cobra.Command{
	Args:  cobra.ExactArgs(2),
	Use:   "delete",
	Short: "Delete egress entries",
	Long:  egressDeleteUsage,
	Run: func(cmd *cobra.Command, args []string) {
		common.RequireRootPrivilege("cilium bpf egress delete <src_ip> <dest_cidr>")

		sip := net.ParseIP(args[0]).To4()
		if sip == nil {
			Fatalf("Unable to parse IP '%s'", args[0])
		}

		_, cidr, err := net.ParseCIDR(args[1])
		if err != nil {
			Fatalf("error parsing cidr %s: %s", args[1], err)
		}

		if err := egressmap.EgressPolicyMap.Delete(sip, *cidr); err != nil {
			Fatalf("error deleting contents of map: %s\n", err)
		}
	},
}

func init() {
	bpfEgressCmd.AddCommand(bpfEgressDeleteCmd)
}
