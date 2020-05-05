// Copyright 2020 Authors of Cilium
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

	"github.com/cilium/cilium/pkg/command"
	"github.com/cilium/cilium/pkg/common"
	"github.com/cilium/cilium/pkg/maps/ipmasq"

	"github.com/spf13/cobra"
)

const (
	cidrTitle = "IP PREFIX/ADDRESS"
)

var bpfIPMasqListCmd = &cobra.Command{
	Use:     "list",
	Aliases: []string{"ls"},
	Short:   "List ip-masq-agent CIDRs",
	Long:    "List ip-masq-agent CIDRs. Packets sent from pods to IPs from these CIDRs avoid masquerading.",
	Run: func(cmd *cobra.Command, args []string) {
		common.RequireRootPrivilege("cilium bpf ipmasq list")

		cidrs, err := (&ipmasq.IPMasqBPFMap{}).Dump()
		if err != nil {
			fmt.Fprintf(os.Stderr, "error dumping contents of map: %s\n", err)
			os.Exit(1)
		}

		if command.OutputJSON() {
			if err := command.PrintOutput(cidrs); err != nil {
				fmt.Fprintf(os.Stderr, "error getting output of map in JSON: %s\n", err)
				os.Exit(1)
			}
			return
		}

		tmp := map[string][]string{}
		for _, cidr := range cidrs {
			tmp[cidr.String()] = []string{""}
		}

		if len(cidrs) == 0 {
			fmt.Fprintf(os.Stderr, "No entries found.\n")
		} else {
			TablePrinter(cidrTitle, "", tmp)
		}
	},
}

func init() {
	bpfIPMasqCmd.AddCommand(bpfIPMasqListCmd)
	command.AddJSONOutput(bpfIPMasqListCmd)
}
