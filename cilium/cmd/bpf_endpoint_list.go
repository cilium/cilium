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

	"github.com/cilium/cilium/common"
	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/maps/lxcmap"

	"github.com/spf13/cobra"
)

var bpfEndpointList = make(map[string]string)

var bpfEndpointListCmd = &cobra.Command{
	Use:   "list",
	Short: "List local endpoint entries",
	Run: func(cmd *cobra.Command, args []string) {
		common.RequireRootPrivilege("cilium bpf endpoint list")
		fmt.Printf("%-32s %s\n", "IP address", "Local endpoint info")
		if len(dumpOutput) > 0 {
			lxcmap.DumpMap(dumpEndpointToJSON)
			if err := OutputPrinter(bpfEndpointList); err != nil {
				os.Exit(1)
			}
			return
		}
		lxcmap.DumpMap(nil)
	},
}

func dumpEndpointToJSON(key bpf.MapKey, value bpf.MapValue) {
	bpfEndpointList[fmt.Sprintf("%s", key)] = fmt.Sprintf("%s", value)
}

func init() {
	bpfEndpointCmd.AddCommand(bpfEndpointListCmd)
	AddMultipleOutput(bpfEndpointListCmd)
}
