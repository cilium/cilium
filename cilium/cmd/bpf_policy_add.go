// Copyright 2017 Authors of Cilium
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
	"strconv"

	"github.com/cilium/cilium/common"
	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/maps/policymap"
	"github.com/cilium/cilium/pkg/u8proto"

	"github.com/spf13/cobra"
)

// bpfPolicyAddCmd represents the bpf_policy_add command
var bpfPolicyAddCmd = &cobra.Command{
	Use:    "add <endpoint id> <traffic-direction> <identity> [port/proto]",
	Short:  "Add/update policy entry",
	PreRun: requireEndpointID,
	Run: func(cmd *cobra.Command, args []string) {
		common.RequireRootPrivilege("cilium bpf policy add")
		updatePolicyKey(cmd, args, true)
	},
}

func init() {
	bpfPolicyCmd.AddCommand(bpfPolicyAddCmd)
}

func updatePolicyKey(cmd *cobra.Command, args []string, add bool) {
	if len(args) < 3 {
		Usagef(cmd, "<endpoint id>, <traffic-direction>, and <identity> required")
	}

	trafficDirection := args[1]
	parsedTd, err := parseTrafficString(trafficDirection)
	if err != nil {
		Fatalf("Failed to convert %s to a valid traffic direction: %s", args[1], err)
	}

	endpointID := args[0]
	if numericIdentity := identity.GetReservedID(endpointID); numericIdentity != identity.IdentityUnknown {
		endpointID = "reserved_" + strconv.FormatUint(uint64(numericIdentity), 10)
	}

	policyMapPath := bpf.MapPath(policymap.MapName + endpointID)
	policyMap, _, err := policymap.OpenMap(policyMapPath)
	if err != nil {
		Fatalf("Cannot open policymap '%s' : %s", policyMapPath, err)
	}

	peerLbl, err := strconv.ParseUint(args[2], 10, 32)
	if err != nil {
		Fatalf("Failed to convert %s", args[2])
	}

	port := uint16(0)
	protos := []uint8{}
	if len(args) > 3 {
		pp, err := parseL4PortsSlice([]string{args[3]})
		if err != nil {
			Fatalf("Failed to parse L4: %s", err)
		}
		port = pp[0].Port
		if port != 0 {
			proto, _ := u8proto.ParseProtocol(pp[0].Protocol)
			if proto == 0 {
				for _, proto := range u8proto.ProtoIDs {
					protos = append(protos, uint8(proto))
				}
			} else {
				protos = append(protos, uint8(proto))
			}
		}
	}
	if len(protos) == 0 {
		protos = append(protos, 0)
	}

	label := uint32(peerLbl)
	for _, proto := range protos {
		u8p := u8proto.U8proto(proto)
		entry := fmt.Sprintf("%d %d/%s", label, port, u8p.String())
		if add == true {
			if err := policyMap.AllowL4(label, port, proto, parsedTd); err != nil {
				Fatalf("Cannot add policy key '%s': %s\n", entry, err)
			}
		} else {
			if err := policyMap.DeleteL4(label, port, proto, parsedTd); err != nil {
				Fatalf("Cannot delete policy key '%s': %s\n", entry, err)
			}
		}
	}
}
