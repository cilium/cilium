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
	"sort"
	"strconv"
	"strings"
	"text/tabwriter"

	"github.com/cilium/cilium/common"
	"github.com/cilium/cilium/pkg/command"
	"github.com/cilium/cilium/pkg/maps/metricsmap"
	monitorAPI "github.com/cilium/cilium/pkg/monitor/api"

	"github.com/spf13/cobra"
)

const (
	reasonTitle    = "REASON"
	directionTitle = "DIRECTION"
	packetsTitle   = "PACKETS"
	bytesTitle     = "BYTES"
)

var bpfMetricsListCmd = &cobra.Command{
	Use:   "list",
	Short: "List BPF datapath traffic metrics",
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

		listMetrics(bpfMetricsList)
	},
}

func listMetrics(bpfMetricsList map[string][]string) {
	if len(bpfMetricsList) == 0 {
		fmt.Fprintf(os.Stderr, "No entries found.\n")
		return
	}

	w := tabwriter.NewWriter(os.Stdout, 5, 0, 3, ' ', 0)
	fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", reasonTitle, directionTitle, packetsTitle, bytesTitle)

	const numColumns = 4
	rows := [][numColumns]string{}

	for key, value := range bpfMetricsList {
		var reason, trafficDirection, packets, bytes string
		var keyIsValid, valueIsValid bool
		var reasonCode, trafficDirectionCode uint8

		reason, trafficDirection, keyIsValid = extractTwoValues(key)

		if keyIsValid {
			v, err := strconv.Atoi(reason)
			reasonCode = uint8(v)
			keyIsValid = err == nil
		}

		if keyIsValid {
			v, err := strconv.Atoi(trafficDirection)
			trafficDirectionCode = uint8(v)
			keyIsValid = err == nil
		}

		if keyIsValid && len(value) == 1 {
			packets, bytes, valueIsValid = extractTwoValues(value[0])
		}

		if keyIsValid && valueIsValid {
			rows = append(rows, [numColumns]string{monitorAPI.DropReason(reasonCode), metricsmap.MetricDirection(trafficDirectionCode), packets, bytes})
		} else {
			// Fall back to best effort printing.
			for i, v := range value {
				if i == 0 {
					rows = append(rows, [numColumns]string{key, v, "", ""})
				} else {
					rows = append(rows, [numColumns]string{"", v, "", ""})
				}
			}
		}
	}

	sort.Slice(rows, func(i, j int) bool {
		for k := 0; k < numColumns; k++ {
			c := strings.Compare(rows[i][k], rows[j][k])

			if c != 0 {
				return c < 0
			}
		}

		return false
	})

	for _, r := range rows {
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", r[0], r[1], r[2], r[3])
	}

	w.Flush()
}

func extractTwoValues(str string) (string, string, bool) {
	tmp := strings.Split(str, " ")
	if len(tmp) != 2 {
		return "", "", false
	}

	a := strings.Split(tmp[0], ":")
	if len(a) != 2 {
		return "", "", false
	}

	b := strings.Split(tmp[1], ":")
	if len(b) != 2 {
		return "", "", false
	}

	return a[1], b[1], true
}

func init() {
	bpfMetricsCmd.AddCommand(bpfMetricsListCmd)
	command.AddJSONOutput(bpfMetricsListCmd)
}
