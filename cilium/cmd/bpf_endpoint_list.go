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
	"os"

	"github.com/cilium/cilium/pkg/command"
	"github.com/cilium/cilium/pkg/common"
	"github.com/cilium/cilium/pkg/maps/lxcmap"

	"github.com/spf13/cobra"
)

const (
	ipAddressTitle         = "IP ADDRESS"
	localEndpointInfoTitle = "LOCAL ENDPOINT INFO"
)

var bpfEndpointListCmd = &cobra.Command{
	Use:     "list",
	Aliases: []string{"ls"},
	Short:   "List local endpoint entries",
	Run: func(cmd *cobra.Command, args []string) {
		common.RequireRootPrivilege("cilium bpf endpoint list")

		bpfEndpointList := make(map[string][]string)
		if err := lxcmap.LXCMap.Dump(bpfEndpointList); err != nil {
			os.Exit(1)
		}

		if command.OutputJSON() {
			if err := command.PrintOutput(bpfEndpointList); err != nil {
				os.Exit(1)
			}
			return
		}

		TablePrinter(ipAddressTitle, localEndpointInfoTitle, bpfEndpointList)
	},
}

func init() {
	bpfEndpointCmd.AddCommand(bpfEndpointListCmd)
	command.AddJSONOutput(bpfEndpointListCmd)
}
