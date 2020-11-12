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

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/command"
	"github.com/cilium/cilium/pkg/common"
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

type metricsRow struct {
	reasonCode int
	reasonDesc string
	direction  string
	packets    int
	bytes      int
}

type jsonMetricValues struct {
	Packets uint64 `json:"packets"`
	Bytes   uint64 `json:"bytes"`
}

type jsonMetric struct {
	Reason      uint64                      `json:"reason"`
	Description string                      `json:"description"`
	Values      map[string]jsonMetricValues `json:"values"`
}

type jsonMetrics []jsonMetric

var bpfMetricsListCmd = &cobra.Command{
	Use:   "list",
	Short: "List BPF datapath traffic metrics",
	Run: func(cmd *cobra.Command, args []string) {
		common.RequireRootPrivilege("cilium bpf metrics list")
		listMetrics(metricsmap.Metrics)
	},
}

func listMetrics(m metricsmap.MetricsMap) {
	bpfMetricsList := make(map[string]string)
	callback := func(key bpf.MapKey, value bpf.MapValue) {
		bpfMetricsList[key.String()] = value.String()
	}
	if err := m.DumpWithCallback(callback); err != nil {
		fmt.Fprintf(os.Stderr, "error dumping contents of map: %s\n", err)
		os.Exit(1)
	}

	if command.OutputJSON() {
		listJSONMetrics(bpfMetricsList)
		return
	}

	listHumanReadableMetrics(bpfMetricsList)
}

func listJSONMetrics(bpfMetricsList map[string]string) {
	metricsByReason := map[int]jsonMetric{}

	for key, value := range bpfMetricsList {
		row, err := extractRow(key, value)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s\n", err)
			continue
		}

		if _, ok := metricsByReason[row.reasonCode]; !ok {
			metricsByReason[row.reasonCode] = jsonMetric{
				Reason:      uint64(row.reasonCode),
				Description: monitorAPI.DropReason(uint8(row.reasonCode)),
				Values:      map[string]jsonMetricValues{},
			}
		}

		direction := strings.ToLower(row.direction)

		metricsByReason[row.reasonCode].Values[direction] = jsonMetricValues{
			Packets: uint64(row.packets),
			Bytes:   uint64(row.bytes),
		}
	}

	metrics := jsonMetrics{}
	for _, v := range metricsByReason {
		metrics = append(metrics, v)
	}

	if err := command.PrintOutput(metrics); err != nil {
		fmt.Fprintf(os.Stderr, "error getting output of map in JSON: %s\n", err)
		os.Exit(1)
	}
}

func listHumanReadableMetrics(bpfMetricsList map[string]string) {
	if len(bpfMetricsList) == 0 {
		fmt.Fprintf(os.Stderr, "No entries found.\n")
		return
	}

	w := tabwriter.NewWriter(os.Stdout, 5, 0, 3, ' ', 0)
	fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", reasonTitle, directionTitle, packetsTitle, bytesTitle)

	const numColumns = 4
	rows := [][numColumns]string{}

	for key, value := range bpfMetricsList {
		row, err := extractRow(key, value)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s\n", err)
			continue

		}

		rows = append(rows, [numColumns]string{row.reasonDesc, row.direction, fmt.Sprintf("%d", row.packets), fmt.Sprintf("%d", row.bytes)})
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

func extractRow(key, value string) (*metricsRow, error) {
	reasonCodeStr, directionCodeStr, ok := extractTwoValues(key)
	if !ok {
		return nil, fmt.Errorf("cannot extract reason and traffic direction from map's key \"%s\"", key)
	}

	reasonCode, err := strconv.Atoi(reasonCodeStr)
	if err != nil {
		return nil, fmt.Errorf("cannot parse reason: %s", err)
	}

	directionCode, err := strconv.Atoi(directionCodeStr)
	if err != nil {
		return nil, fmt.Errorf("cannot parse direction: %s", err)
	}

	packetsStr, bytesStr, ok := extractTwoValues(value)
	if !ok {
		return nil, fmt.Errorf("cannot extract packets and bytes counters from map's value \"%s\"", value)
	}

	packets, err := strconv.Atoi(packetsStr)
	if err != nil {
		return nil, fmt.Errorf("cannot parse packets counter: %s", err)
	}

	bytes, err := strconv.Atoi(bytesStr)
	if err != nil {
		return nil, fmt.Errorf("cannot parse bytes counter: %s", err)
	}

	reasonDesc := monitorAPI.DropReason(uint8(reasonCode))
	direction := metricsmap.MetricDirection(uint8(directionCode))

	return &metricsRow{reasonCode, reasonDesc, direction, packets, bytes}, nil
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
