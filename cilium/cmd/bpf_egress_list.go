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
	"os"

	"github.com/cilium/cilium/pkg/command"
	"github.com/cilium/cilium/pkg/common"
	"github.com/cilium/cilium/pkg/maps/egressmap"

	"github.com/spf13/cobra"
)

const (
	egressListUsage = "List egress entries.\n" + lpmWarningMessage
)

var bpfEgressListCmd = &cobra.Command{
	Use:     "list",
	Aliases: []string{"ls"},
	Short:   "List egress entries",
	Long:    egressListUsage,
	Run: func(cmd *cobra.Command, args []string) {
		common.RequireRootPrivilege("cilium bpf egress list")

		bpfEgressList := make(map[string][]string)
		if err := egressmap.EgressMap.Dump(bpfEgressList); err != nil {
			Fatalf("error dumping contents of map: %s\n", err)
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
			TablePrinter("SRC IP & DST CIDR", "EGRESS INFO", bpfEgressList)
		}
	},
}

func init() {

	bpfEgressCmd.AddCommand(bpfEgressListCmd)
	command.AddJSONOutput(bpfEgressListCmd)
}
