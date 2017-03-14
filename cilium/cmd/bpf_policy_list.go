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
	"os"
	"strconv"
	"text/tabwriter"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/maps/policymap"
	"github.com/cilium/cilium/pkg/policy"

	"github.com/spf13/cobra"
)

var printIDs bool

// bpfPolicyListCmd represents the bpf_policy_list command
var bpfPolicyListCmd = &cobra.Command{
	Use:    "list",
	Short:  "List contents of a policy BPF map",
	PreRun: requireEndpointID,
	Run: func(cmd *cobra.Command, args []string) {
		listMap(cmd, args)
	},
}

func init() {
	bpfPolicyCmd.AddCommand(bpfPolicyListCmd)
	bpfPolicyListCmd.Flags().BoolVarP(&printIDs, "numeric", "n", false, "Do not resolve IDs")
}

func listMap(cmd *cobra.Command, args []string) {
	lbl := args[0]

	if lbl != "" {
		if id := policy.GetReservedID(lbl); id != policy.ID_UNKNOWN {
			lbl = "reserved_" + strconv.FormatUint(uint64(id), 10)
		}
	} else {
		Fatalf("Need ID or label\n")
	}

	file := bpf.MapPath(policymap.MapName + lbl)
	fd, err := bpf.ObjGet(file)
	if err != nil {
		Fatalf("%s\n", err)
	}

	m := policymap.PolicyMap{Fd: fd}
	statsMap, err := m.DumpToSlice()
	if err != nil {
		Fatalf("Error while opening bpf Map: %s\n", err)
	}
	labelsID := map[policy.NumericIdentity]*policy.Identity{}

	w := tabwriter.NewWriter(os.Stdout, 5, 0, 3, ' ', 0)

	const (
		labelsIDTitle  = "IDENTITY"
		labelsDesTitle = "LABELS (source:key[=value])"
		actionTitle    = "ACTION"
		bytesTitle     = "BYTES"
		packetsTitle   = "PACKETS"
	)

	for _, stat := range statsMap {
		if !printIDs {
			id := policy.NumericIdentity(stat.ID)
			if lbls, err := client.IdentityGet(id.StringID()); err != nil {
				fmt.Fprintf(os.Stderr, "Was impossible to retrieve label ID %d: %s\n",
					id, err)
			} else {
				labelsID[id] = policy.NewIdentityFromModel(lbls)
			}
		}

	}

	if printIDs {
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t\n", labelsIDTitle, actionTitle, bytesTitle, packetsTitle)
	} else {
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t\n", labelsDesTitle, actionTitle, bytesTitle, packetsTitle)
	}
	for _, stat := range statsMap {
		id := policy.NumericIdentity(stat.ID)
		act := policy.ConsumableDecision(stat.Action)
		if printIDs {
			fmt.Fprintf(w, "%d\t%s\t%d\t%d\t\n", id, act.String(), stat.Bytes, stat.Packets)
		} else if lbls := labelsID[id]; lbls != nil {
			first := true
			for _, lbl := range lbls.Labels {
				if first {
					fmt.Fprintf(w, "%s\t%s\t%d\t%d\t\n", lbl, act.String(), stat.Bytes, stat.Packets)
					first = false
				} else {
					fmt.Fprintf(w, "%s\t\t\t\t\t\n", lbl)
				}
			}
		} else {
			fmt.Fprintf(w, "%d\t%s\t%d\t%d\t\n", id, act.String(), stat.Bytes, stat.Packets)
		}
	}
	w.Flush()
	if len(statsMap) == 0 {
		fmt.Printf("Policy stats empty. Perhaps the policy enforcement is disabled?\n")
	}
}
