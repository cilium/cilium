// Copyright 2018 Authors of Cilium
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
	"github.com/cilium/cilium/pkg/command"
	"github.com/cilium/cilium/pkg/maps/metricsmap"

	"github.com/spf13/cobra"
)

const (
	// DropForward is the bpf map key
	DropForward = "KEY"
	count       = "COUNT"
)

var bpfMetricsListCmd = &cobra.Command{
	Use:   "metrics list",
	Short: "List L3/L4 metrics",
	Run: func(cmd *cobra.Command, args []string) {
		common.RequireRootPrivilege("cilium bpf metrics list")

		bpfMetricsList := make(map[string][]string)
		if err := metricsmap.Metrics.Dump(bpfMetricsList); err != nil {
			fmt.Fprintf(os.Stderr, "error dumping contents of map: %s\n", err)
			os.Exit(1)
		}

		if command.OutputJSON() {
			if err := command.PrintOutput(bpfMetricsList); err != nil {
				fmt.Fprintf(os.Stderr, "error getting output of map in JSON: %s\n", err)
				os.Exit(1)
			}
			return
		}

		TablePrinter(DropForward, count, bpfMetricsList)
	},
}

func init() {
	bpfMetricsCmd.AddCommand(bpfMetricsListCmd)
	command.AddJSONOutput(bpfMetricsListCmd)
}
