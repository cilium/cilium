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
	"strconv"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/maps/policymap"
	"github.com/cilium/cilium/pkg/policy"

	"github.com/spf13/cobra"
)

// bpfPolicyAddCmd represents the bpf_policy_add command
var bpfPolicyAddCmd = &cobra.Command{
	Use:    "add <endpoint id> <identity>",
	Short:  "Add/update policy entry",
	PreRun: requireEndpointID,
	Run: func(cmd *cobra.Command, args []string) {
		updatePolicyKey(cmd, args, true)
	},
}

func init() {
	bpfPolicyCmd.AddCommand(bpfPolicyAddCmd)
}

func updatePolicyKey(cmd *cobra.Command, args []string, add bool) {
	if len(args) < 2 {
		Usagef(cmd, "<endpoint id> and <identity> required")
	}

	lbl := args[0]
	if id := policy.GetReservedID(lbl); id != policy.ID_UNKNOWN {
		lbl = "reserved_" + strconv.FormatUint(uint64(id), 10)
	}

	file := bpf.MapPath(policymap.MapName + lbl)
	policyMap, _, err := policymap.OpenMap(file)
	if err != nil {
		Fatalf("Cannot open policymap '%s' : %s", file, err)
	}

	peerLbl, err := strconv.ParseUint(args[1], 10, 32)
	if err != nil {
		Fatalf("Failed to convert %s", args[1])
	}

	if add == true {
		if err := policyMap.AllowConsumer(uint32(peerLbl)); err != nil {
			Fatalf("Cannot add policy key: %s", err)
		}
	} else {
		if err := policyMap.DeleteConsumer(uint32(peerLbl)); err != nil {
			Fatalf("Cannot delete policy key: %s", err)
		}
	}
}
