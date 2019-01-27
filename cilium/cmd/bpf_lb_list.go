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
	"github.com/cilium/cilium/common"
	"github.com/cilium/cilium/pkg/command"
	"github.com/cilium/cilium/pkg/maps/lbmap"

	"github.com/spf13/cobra"
)

const (
	idTitle             = "ID"
	serviceAddressTitle = "SERVICE ADDRESS"
	backendAddressTitle = "BACKEND ADDRESS"
)

var listRevNAT bool

// bpfCtListCmd represents the bpf_ct_list command
var bpfLBListCmd = &cobra.Command{
	Use:     "list",
	Aliases: []string{"ls"},
	Short:   "List load-balancing configuration",
	Run: func(cmd *cobra.Command, args []string) {
		common.RequireRootPrivilege("cilium bpf lb list")

		var firstTitle string
		serviceList := make(map[string][]string)
		if listRevNAT {
			firstTitle = idTitle
			if err := lbmap.RevNat4Map.DumpIfExists(serviceList); err != nil {
				Fatalf("Unable to dump IPv4 reverse NAT table: %s", err)
			}
			if err := lbmap.RevNat6Map.DumpIfExists(serviceList); err != nil {
				Fatalf("Unable to dump IPv6 reverse NAT table: %s", err)
			}
		} else {
			firstTitle = serviceAddressTitle
			if err := lbmap.Service4Map.DumpIfExists(serviceList); err != nil {
				Fatalf("Unable to dump IPv4 services table: %s", err)
			}
			if err := lbmap.Service6Map.DumpIfExists(serviceList); err != nil {
				Fatalf("Unable to dump IPv6 services table: %s", err)
			}
		}

		if command.OutputJSON() {
			if err := command.PrintOutput(serviceList); err != nil {
				Fatalf("Unable to generate JSON output: %s", err)
			}
			return
		}

		TablePrinter(firstTitle, backendAddressTitle, serviceList)
	},
}

func init() {
	bpfLBCmd.AddCommand(bpfLBListCmd)
	bpfLBListCmd.Flags().BoolVarP(&listRevNAT, "revnat", "", false, "List reverse NAT entries")
	command.AddJSONOutput(bpfLBListCmd)
}
