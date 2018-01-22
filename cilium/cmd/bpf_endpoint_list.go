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
	"text/tabwriter"

	"github.com/cilium/cilium/common"
	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/maps/lxcmap"

	"github.com/spf13/cobra"
)

const (
	ipAddressTitle         = "IP ADDRESS"
	localEndpointInfoTitle = "LOCAL ENDPOINT INFO"
)

var bpfEndpointList = make(map[string]string)

var bpfEndpointListCmd = &cobra.Command{
	Use:   "list",
	Short: "List local endpoint entries",
	Run: func(cmd *cobra.Command, args []string) {
		common.RequireRootPrivilege("cilium bpf endpoint list")

		lxcmap.DumpMap(dumpEndpoint)

		if len(dumpOutput) > 0 {
			if err := OutputPrinter(bpfEndpointList); err != nil {
				os.Exit(1)
			}
			return
		}

		w := tabwriter.NewWriter(os.Stdout, 5, 0, 3, ' ', 0)

		fmt.Fprintf(w, "%s\t%s\t\n", ipAddressTitle, localEndpointInfoTitle)

		for k, v := range bpfEndpointList {
			fmt.Fprintf(w, "%s\t%s\t\n", k, v)
		}

		w.Flush()
	},
}

func dumpEndpoint(key bpf.MapKey, value bpf.MapValue) {
	endpointKey, endpointValue := key.(lxcmap.EndpointKey), value.(lxcmap.EndpointInfo)
	bpfEndpointList[endpointKey.String()] = endpointValue.String()
}

func init() {
	bpfEndpointCmd.AddCommand(bpfEndpointListCmd)
	AddMultipleOutput(bpfEndpointListCmd)
}
