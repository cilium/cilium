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

	"github.com/cilium/cilium/common"
	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/maps/lbmap"

	"github.com/spf13/cobra"
)

var listRevNAT bool
var serviceList = map[string][]string{}

// bpfCtListCmd represents the bpf_ct_list command
var bpfLBListCmd = &cobra.Command{
	Use:   "list",
	Short: "List load-balancing configuration",
	Run: func(cmd *cobra.Command, args []string) {
		common.RequireRootPrivilege("cilium bpf lb list")
		if listRevNAT {
			fmt.Printf("%-6s %-s\n", "ID", "Service Address")
			fmt.Println("-----------------------------------------------------------")
			lbmap.RevNat4Map.Dump(lbmap.RevNat4DumpParser, dumpRevNAT)
			lbmap.RevNat6Map.Dump(lbmap.RevNat6DumpParser, dumpRevNAT)
		} else {
			fmt.Printf("%-20s %-s\n", "Service Address", "Backend Address")
			fmt.Println("-----------------------------------------------------------")
			lbmap.Service4Map.Dump(lbmap.Service4DumpParser, dumpService)
			lbmap.Service6Map.Dump(lbmap.Service6DumpParser, dumpService)
			for key, backends := range serviceList {
				for k, v := range backends {
					if k == 0 {
						fmt.Printf("%-20s %-s\n", key, v)
					} else {
						fmt.Printf("%-20s %-s\n", "", v)
					}
				}
			}
		}
	},
}

func init() {
	bpfLBCmd.AddCommand(bpfLBListCmd)
	bpfLBListCmd.Flags().BoolVarP(&listRevNAT, "revnat", "", false, "List reverse NAT entries")
}

func dumpService(key bpf.MapKey, value bpf.MapValue) {
	svcKey := key.(lbmap.ServiceKey)
	svcValue := value.(lbmap.ServiceValue)
	if svcKey.GetBackend() != 0 {
		serviceList[svcKey.String()] = append(serviceList[svcKey.String()], svcValue.String())
	}
}

func dumpRevNAT(key bpf.MapKey, value bpf.MapValue) {
	revNatK := key.(lbmap.RevNatKey)
	revNatV := value.(lbmap.RevNatValue)
	fmt.Printf("%-6s %s\n", revNatK.String(), revNatV.String())
}
