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
	"errors"
	"fmt"
	"io/fs"
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

type egressPolicy struct {
	SourceIP  string
	DestCIDR  string
	EgressIP  string
	GatewayIP string
}

var bpfEgressListCmd = &cobra.Command{
	Use:     "list",
	Aliases: []string{"ls"},
	Short:   "List egress policy entries",
	Long:    egressListUsage,
	Run: func(cmd *cobra.Command, args []string) {
		common.RequireRootPrivilege("cilium bpf egress list")

		if err := egressmap.OpenEgressMaps(); err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				fmt.Fprintln(os.Stderr, "Cannot find egress gateway bpf maps")
				return
			}

			Fatalf("Cannot open egress gateway bpf maps: %s", err)
		}

		bpfEgressList := []egressPolicy{}
		parse := func(key *egressmap.EgressPolicyKey4, val *egressmap.EgressPolicyVal4) {
			bpfEgressList = append(bpfEgressList, egressPolicy{
				SourceIP:  key.GetSourceIP().String(),
				DestCIDR:  key.GetDestCIDR().String(),
				EgressIP:  val.GetEgressIP().String(),
				GatewayIP: val.GetGatewayIP().String(),
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

func printEgressList(egressList []egressPolicy) {
	w := tabwriter.NewWriter(os.Stdout, 5, 0, 3, ' ', 0)

	fmt.Fprintln(w, "Source IP\tDestination CIDR\tEgress IP\tGateway IP")
	for _, ep := range egressList {
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", ep.SourceIP, ep.DestCIDR, ep.EgressIP, ep.GatewayIP)
	}

	w.Flush()
}

func init() {
	bpfEgressCmd.AddCommand(bpfEgressListCmd)
	command.AddJSONOutput(bpfEgressListCmd)
}
