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
	"github.com/cilium/cilium/pkg/maps/tunnel"

	"github.com/spf13/cobra"
)

const (
	tunnelTitle      = "TUNNEL"
	destinationTitle = "VALUE"
)

var bpfTunnelListCmd = &cobra.Command{
	Use:     "list",
	Aliases: []string{"ls"},
	Short:   "List tunnel endpoint entries",
	Run: func(cmd *cobra.Command, args []string) {
		common.RequireRootPrivilege("cilium bpf tunnel list")

		tunnelList := make(map[string][]string)
		if err := tunnel.TunnelMap.Dump(tunnelList); err != nil {
			os.Exit(1)
		}

		if command.OutputJSON() {
			if err := command.PrintOutput(tunnelList); err != nil {
				os.Exit(1)
			}
			return
		}

		TablePrinter(tunnelTitle, destinationTitle, tunnelList)
	},
}

func init() {
	bpfTunnelCmd.AddCommand(bpfTunnelListCmd)
	command.AddJSONOutput(bpfTunnelListCmd)
}
